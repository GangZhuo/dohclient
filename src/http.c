#include "http.h"
#include "dllist.h"
#include "../rbtree/rbtree.h"
#include "netutils.h"
#include "log.h"
#include "stream.h"
#include "../http-parser/http_parser.h"

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define HTTP_CONN_ST_NONE		0
#define HTTP_CONN_ST_FLY		1
#define HTTP_CONN_ST_IDLE		2
#define HTTP_CONN_ST_BUSY		3

struct http_ctx_t {
	struct rbtree_t pool;
	const proxy_t* proxies;
	int proxy_num;
	int timeout;
};

typedef struct http_pool_item_t {
	sockaddr_t addr; /* server's address */
	dllist_t idle_conns;
	dllist_t busy_conns;
	dllist_t fly_conns;
	int idle_count;
	int busy_count;
	int fly_count;
	struct rbnode_t rbn;
} http_pool_item_t;

typedef enum http_field_status {
	fs_none = 0,
	fs_name,
	fs_value,
} http_field_status;

typedef struct http_conn_t {
	http_ctx_t* http_ctx;
	struct conn_t conn;
	SSL* ssl;
	int ssl_status;
	int status;				/* HTTP_CONN_ST_[NONE|FLY|IDLE|BUSY] */
	http_pool_item_t* pool;
	dlitem_t entry;
	http_request_t* request;
	http_response_t* response;
	http_parser parser;
	struct {
		stream_t name;
		stream_t value;
		http_field_status status;
	} field;
	int keep_alive;
	stream_t proxy_stream;
} http_conn_t;

struct http_request_t {
	const char* method; /* GET|POST */
	const char* path;   /* request path */
	const char* host;
	dllist_t    headers;
	char*       data;
	int         data_len;
	http_conn_t* conn;
	http_callback_fun_t callback;
	void* cb_state;
};

struct http_response_t {
	unsigned short http_major;
	unsigned short http_minor;
	int      status_code;
	char*    status_text;
	dllist_t headers;
	stream_t data;
	http_conn_t* conn;
};

typedef struct http_header_t {
	char* name;
	char* value;
	dlitem_t entry;
} http_header_t;

typedef struct http_fdset_state {
	http_ctx_t* ctx;
	fd_set* readset;
	fd_set* writeset;
	fd_set* errorset;
	sock_t  maxfd;
} http_fdset_state;

typedef struct http_step_state {
	http_ctx_t* ctx;
	fd_set* readset;
	fd_set* writeset;
	fd_set* errorset;
} http_step_state;

static void http_call_callback(http_request_t* req, int err, http_response_t* res);
static int on_message_begin(http_parser* parser);
static int on_status(http_parser* parser, const char* at, size_t length);
static int on_header_field(http_parser* parser, const char* at, size_t length);
static int on_header_value(http_parser* parser, const char* at, size_t length);
static int on_headers_complete(http_parser* parser);
static int on_body(http_parser* parser, const char* at, size_t length);
static int on_message_complete(http_parser* parser);
static int on_chunk_header(http_parser* parser);
static int on_chunk_complete(http_parser* parser);


static SSL_CTX* sslctx = NULL;

static http_parser_settings parser_settings = {
	.on_message_begin = on_message_begin,
	.on_url = NULL,
	.on_status = on_status,
	.on_header_field = on_header_field,
	.on_header_value = on_header_value,
	.on_headers_complete = on_headers_complete,
	.on_body = on_body,
	.on_message_complete = on_message_complete,
	.on_chunk_header = on_chunk_header,
	.on_chunk_complete = on_chunk_complete,
};

static inline void http_update_expire(http_conn_t* conn)
{
	http_ctx_t* ctx = conn->http_ctx;
	conn->conn.expire = time(NULL) + ctx->timeout;
}

static inline int http_is_expired(http_conn_t* conn, time_t now)
{
	return conn->conn.expire <= now;
}

static void http_conn_free(http_conn_t *conn)
{
	if (conn->request) {
		http_call_callback(conn->request, HTTP_ABORT, conn->response);
	}
	if (conn->response) {
		conn->response->conn = NULL;
		conn->response = NULL;
	}
	if (conn->ssl) {
		SSL_free(conn->ssl);
	}
	conn_free(&conn->conn);
	stream_free(&conn->field.name);
	stream_free(&conn->field.value);
	stream_free(&conn->proxy_stream);
	free(conn);

	logv("http_conn_free()\n");
}

static void http_pool_item_free_conns(dllist_t *conns)
{
	dlitem_t* cur, * nxt;
	http_conn_t* conn;
	dllist_foreach(conns, cur, nxt,
		http_conn_t, conn, entry) {
		dllist_remove(&conn->entry);
		http_conn_free(conn);
	}
}

static void http_pool_item_free(http_pool_item_t* item)
{
	http_pool_item_free_conns(&item->fly_conns);
	http_pool_item_free_conns(&item->idle_conns);
	http_pool_item_free_conns(&item->busy_conns);
	free(item);

	logv("http_pool_item_free()\n");
}

static int rbcmp(const void* a, const void* b)
{
	sockaddr_t* x = (sockaddr_t*)a;
	sockaddr_t* y = (sockaddr_t*)b;
	if (x->addr.ss_family != y->addr.ss_family)
		return ((int)x->addr.ss_family) - ((int)y->addr.ss_family);
	if (x->addr.ss_family != AF_INET) {
		return memcmp(
			&((struct sockaddr_in*)(&x->addr))->sin_addr,
			&((struct sockaddr_in*)&y->addr)->sin_addr,
			4);
	}
	else {
		return memcmp(
			&((struct sockaddr_in6*)(&x->addr))->sin6_addr,
			&((struct sockaddr_in6*)&y->addr)->sin6_addr,
			16);
	}
}

static void rbnfree(rbnode_t* node, void* state)
{
	http_pool_item_t* item = rbtree_container_of(node, http_pool_item_t, rbn);
	http_pool_item_free(item);
}

static char* http_strdup(const char* s, int len)
{
	char* r = (char*)malloc(len + 1);
	if (!r) {
		loge("http_strdup() error: alloc\n");
		return NULL;
	}
	memcpy(r, s, len);
	r[len] = '\0';
	return r;
}


http_request_t* http_request_create(
	const char *method, const char *path,
	const char *host)
{
	http_request_t* req = (http_request_t*)malloc(sizeof(http_request_t));
	if (!req) {
		loge("http_create_request() error: alloc\n");
		return NULL;
	}

	memset(req, 0, sizeof(http_request_t));

	dllist_init(&req->headers);

	req->method = method;
	req->path = path;
	req->host = host;

	return req;
}

void http_request_destroy(http_request_t *request)
{
	if (request) {
		dlitem_t* cur, * nxt;
		http_header_t* header;
		if (request->conn) {
			request->conn->request = NULL;
		}
		dllist_foreach(&request->headers, cur, nxt,
			http_header_t, header, entry) {
			dllist_remove(&header->entry);
			free(header);
		}
		free(request);
	}
}

http_header_t* http_request_find_header(http_request_t* request,
	const char* name)
{
	dlitem_t* cur, * nxt;
	http_header_t* header;
	dllist_foreach(&request->headers, cur, nxt,
		http_header_t, header, entry) {
		if (strcmp(header->name, name) == 0) {
			return header;
		}
	}
	return NULL;
}

const char* http_request_get_header(http_request_t* request,
	const char* name)
{
	http_header_t* header = 
		http_request_find_header(request, name);
	if (header) {
		return header->value;
	}
	return NULL;
}

int http_request_set_header(http_request_t* request,
	const char *name, const char *value)
{
	http_header_t* header =
		http_request_find_header(request, name);
	if (header) {
		header->value = (char*)value;
	}
	else {
		header = (http_header_t*)malloc(sizeof(http_header_t));
		if (!header) {
			loge("http_request_set_header() error: alloc\n");
			return -1;
		}

		memset(header, 0, sizeof(http_header_t));

		header->name = (char*)name;
		header->value = (char*)value;

		dllist_add(&request->headers, &header->entry);
	}

	if (strcmp(name, "Host") == 0) {
		request->host = value;
	}

	return 0;
}

const char* http_request_get_method(http_request_t* request)
{
	return request->method;
}

void http_request_set_method(http_request_t* request,
	const char* value)
{
	request->method = value;
}

const char* http_request_get_path(http_request_t* request)
{
	return request->path;
}

void http_request_set_path(http_request_t* request,
	const char* value)
{
	request->path = value;
}

const char* http_request_get_host(http_request_t* request)
{
	return request->host;
}

void http_request_set_host(http_request_t* request,
	const char* value)
{
	request->host = value;
	http_header_t* header =
		http_request_find_header(request, "Host");
	if (header) {
		header->value = (char*)value;
	}
}

char* http_request_get_data(http_request_t* request, int* data_len)
{
	if (data_len) *data_len = request->data_len;
	return request->data;
}

void http_request_set_data(http_request_t* request,
	char* data, int data_len)
{
	request->data = data;
	request->data_len = data_len;
}

int http_request_header_next(http_request_t* request, struct dliterator_t* iterator,
	const char** name, const char** value)
{
	int r = dliterator_next(&request->headers, iterator);
	if (r && (name || value)) {
		http_header_t* header =
			dllist_container_of(iterator->cur, http_header_t, entry);
		if (name) *name = header->name;
		if (value) *value = header->value;
	}
	return r;
}

int http_request_headers_serialize(/*write stream*/stream_t* s, http_request_t* req)
{
	struct dliterator_t it;
	const char* name;
	const char* value;
	int have_connection = FALSE;
	int have_host = FALSE;

	if (stream_appendf(s,
		"%s %s HTTP/1.1\r\n",
		req->method,
		req->path) == -1) {
		loge("http_request_serialize() error: stream_appendf()\n");
		return -1;
	}

	dliterator_reset(&it);

	while (http_request_header_next(req, &it, &name, &value)) {
		if (stream_appendf(s, "%s: %s\r\n", name, value) == -1) {
			loge("http_request_serialize() error: stream_appendf()\n");
			return -1;
		}
		if (strcmp(name, "Connection") == 0)
			have_connection = TRUE;
		else if (strcmp(name, "Host") == 0)
			have_host = TRUE;
	}

	if (!have_host) {
		if (stream_appendf(s, "Host: %s\r\n", req->host) == -1) {
			loge("http_request_serialize() error: stream_appendf()\n");
			return -1;
		}
	}

	if (!have_connection) {
		if (stream_appendf(s, "Connection: %s\r\n", "keep-alive") == -1) {
			loge("http_request_serialize() error: stream_appendf()\n");
			return -1;
		}
	}

	if (strcmp(req->method, "POST") == 0) {
		if (stream_appendf(s, "Content-Length: %d\r\n\r\n", req->data_len) == -1) {
			loge("http_request_serialize() error: stream_appendf()\n");
			return -1;
		}
	}
	else {
		if (stream_appends(s, "\r\n", 2) == -1) {
			loge("http_request_serialize() error: stream_appendf()\n");
			return -1;
		}
	}

	return s->size - s->pos;
}

int http_request_serialize(/*write stream*/stream_t* s, http_request_t* req)
{
	if (http_request_headers_serialize(s, req) == -1) {
		loge("http_request_serialize() error: http_request_headers_serialize()\n");
		return -1;
	}

	if (strcmp(req->method, "POST") == 0) {
		if (req->data_len > 0) {
			if (stream_appends(s, req->data, req->data_len) == -1) {
				loge("http_request_serialize() error: stream_appendf()\n");
				return -1;
			}
		}
	}

	return s->size - s->pos;
}



http_response_t* http_response_create()
{
	http_response_t* res = (http_response_t*)malloc(sizeof(http_response_t));
	if (!res) {
		loge("http_response_create() error: alloc\n");
		return NULL;
	}

	memset(res, 0, sizeof(http_response_t));

	dllist_init(&res->headers);

	stream_init(&res->data);

	return res;
}

void http_response_destroy(http_response_t* response)
{
	if (response) {
		dlitem_t* cur, * nxt;
		http_header_t* header;
		if (response->conn) {
			response->conn->response = NULL;
		}
		dllist_foreach(&response->headers, cur, nxt,
			http_header_t, header, entry) {
			dllist_remove(&header->entry);
			free(header->name);
			free(header->value);
			free(header);
		}
		free(response->status_text);
		stream_free(&response->data);
		free(response);
	}
}

http_header_t* http_response_find_header(http_response_t* response,
	const char* name)
{
	dlitem_t* cur, * nxt;
	http_header_t* header;
	dllist_foreach(&response->headers, cur, nxt,
		http_header_t, header, entry) {
		if (strcmp(header->name, name) == 0) {
			return header;
		}
	}
	return NULL;
}

const char* http_response_get_header(http_response_t* response,
	const char* name)
{
	http_header_t* header =
		http_response_find_header(response, name);
	if (header) {
		return header->value;
	}
	return NULL;
}

int http_response_add_header(http_response_t* response,
	const char* name, const char* value)
{
	http_header_t* header;

	header = (http_header_t*)malloc(sizeof(http_header_t));
	if (!header) {
		loge("http_response_add_header() error: alloc\n");
		return -1;
	}

	memset(header, 0, sizeof(http_header_t));

	header->name = strdup(name);
	header->value = strdup(value);

	dllist_add(&response->headers, &header->entry);

	return 0;
}

int http_response_set_header(http_response_t* response,
	const char* name, const char* value)
{
	http_header_t* header =
		http_response_find_header(response, name);
	if (header) {
		free(header->value);
		header->value = strdup(value);
		return 0;
	}
	else {
		return http_response_add_header(response, name, value);
	}
}

int http_response_get_status_code(http_response_t* response, const char** status_text)
{
	if (status_text) *status_text = response->status_text;
	return response->status_code;
}

int http_response_header_next(http_response_t* response, struct dliterator_t* iterator,
	const char** name, const char** value)
{
	int r = dliterator_next(&response->headers, iterator);
	if (r && (name || value)) {
		http_header_t* header =
			dllist_container_of(iterator->cur, http_header_t, entry);
		if (name) *name = header->name;
		if (value) *value = header->value;
	}
	return r;
}

char* http_response_get_data(http_response_t* response, int* data_len)
{
	if (data_len) *data_len = response->data.size;
	return response->data.array;
}

int http_response_append_data(http_response_t* response,
	const char* data, int data_len)
{
	if (stream_appends(&response->data, data, data_len) == -1) {
		loge("http_response_append_data() error: stream_appends()\n");
		return -1;
	}
	return 0;
}

int http_response_headers_serialize(/*write stream*/stream_t* s, http_response_t* response)
{
	struct dliterator_t it;
	const char* name;
	const char* value;
	int have_connection = FALSE;
	int have_host = FALSE;

	if (stream_appendf(s,
		"HTTP/%d.%d %d %s\r\n",
		response->http_major,
		response->http_minor,
		response->status_code,
		response->status_text) == -1) {
		loge("http_response_headers_serialize() error: stream_appendf()\n");
		return -1;
	}

	dliterator_reset(&it);

	while (http_response_header_next(response, &it, &name, &value)) {
		if (stream_appendf(s, "%s: %s\r\n", name, value) == -1) {
			loge("http_response_headers_serialize() error: stream_appendf()\n");
			return -1;
		}
	}

	if (stream_appends(s, "\r\n", 2) == -1) {
		loge("http_response_headers_serialize() error: stream_appendf()\n");
		return -1;
	}

	return s->size - s->pos;
}

int http_response_serialize(/*write stream*/stream_t* s, http_response_t* response)
{
	if (http_response_headers_serialize(s, response) == -1) {
		loge("http_response_serialize() error: http_response_headers_serialize()\n");
		return -1;
	}

	if (response->data.size > 0) {
		if (stream_appends(s, response->data.array, response->data.size) == -1) {
			loge("http_response_serialize() error: stream_appendf()\n");
			return -1;
		}
	}

	return s->size - s->pos;
}



int http_init(const config_t* conf)
{
	const SSL_METHOD* method;
	SSL* ssl;
	STACK_OF(SSL_CIPHER)* active_ciphers;
	char ciphers[300];

	/* Whitelist of candidate ciphers. */
	static const char* const candidates[] = {
	  "AES128-GCM-SHA256", "AES128-SHA256", "AES256-SHA256", /* strong ciphers */
	  "AES128-SHA", "AES256-SHA", /* strong ciphers, also in older versions */
	  "RC4-SHA", "RC4-MD5", /* backwards compatibility, supposed to be weak */
	  "DES-CBC3-SHA", "DES-CBC3-MD5", /* more backwards compatibility */
	  NULL
	};

	if (SSL_library_init() < 0) {
		loge("http_init() error: Could not initialize the OpenSSL library !\n");
		return -1;
	}

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	method = SSLv23_client_method();

	if ((sslctx = SSL_CTX_new(method)) == NULL) {
		loge("http_init() error: Unable to create a new SSL context structure.\n");
		return -1;
	}

	SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

	if (SSL_CTX_set_cipher_list(sslctx, "HIGH:MEDIUM") != 1) {
		loge("http_init() error: SSL_CTX_set_cipher_list() error.\n");
		return -1;
	}

	/* Create a dummy SSL session to obtain the cipher list. */
	ssl = SSL_new(sslctx);
	if (ssl == NULL) {
		loge("http_init() error: SSL_new() error.\n");
		return -1;
	}

	active_ciphers = SSL_get_ciphers(ssl);
	if (active_ciphers == NULL) {
		loge("http_init() error: active_ciphers() error.\n");
		SSL_free(ssl);
		return -1;
	}

	/* Actually selected ciphers. */
	ciphers[0] = '\0';
	for (const char* const* c = candidates; *c; ++c) {
		for (int i = 0; i < sk_SSL_CIPHER_num(active_ciphers); ++i) {
			if (strcmp(SSL_CIPHER_get_name(sk_SSL_CIPHER_value(active_ciphers, i)),
				*c) == 0) {
				if (*ciphers) {
					strcat(ciphers, ":");
				}
				strcat(ciphers, *c);
				break;
			}
		}
	}

	SSL_free(ssl);

	logv("cipher list: %s\n", ciphers);

	/* Apply final cipher list. */
	if (SSL_CTX_set_cipher_list(sslctx, ciphers) != 1) {
		loge("http_init() error: SSL_CTX_set_cipher_list() error.\n");
		return -1;
	}

	return 0;
}

void http_uninit()
{
	if (sslctx) {
		SSL_CTX_free(sslctx);
		sslctx = NULL;
	}
}



static void http_remove_conn(http_conn_t* conn)
{
	dllist_remove(&conn->entry);
	if (conn->status == HTTP_CONN_ST_FLY)
		conn->pool->fly_count--;
	else if (conn->status == HTTP_CONN_ST_IDLE)
		conn->pool->idle_count--;
	else if (conn->status == HTTP_CONN_ST_BUSY)
		conn->pool->busy_count--;
	conn->status = HTTP_CONN_ST_NONE;
}

static void http_add_to_busy(http_conn_t* conn)
{
	dllist_add(&conn->pool->busy_conns, &conn->entry);
	conn->pool->busy_count++;
	conn->status = HTTP_CONN_ST_BUSY;
}

static void http_add_to_idle(http_conn_t* conn)
{
	dllist_add(&conn->pool->idle_conns, &conn->entry);
	conn->pool->idle_count++;
	conn->status = HTTP_CONN_ST_IDLE;
}

static void http_add_to_fly(http_conn_t* conn)
{
	dllist_add(&conn->pool->fly_conns, &conn->entry);
	conn->pool->fly_count++;
	conn->status = HTTP_CONN_ST_FLY;
}

static void http_move_to_busy(http_conn_t* conn)
{
	logv("http_move_to_busy()\n");
	http_remove_conn(conn);
	http_add_to_busy(conn);
}

static void http_move_to_idle(http_conn_t* conn)
{
	logv("http_move_to_idle()\n");
	http_remove_conn(conn);
	http_add_to_idle(conn);
}

static void http_move_to_fly(http_conn_t* conn)
{
	logv("http_move_to_fly()\n");
	http_remove_conn(conn);
	http_add_to_fly(conn);
}

static void http_conn_close(http_ctx_t* ctx, http_conn_t* conn)
{
	conn->conn.status = cs_closing;
	http_move_to_fly(conn);
	if (conn->conn.sock) {
		shutdown(conn->conn.sock, SHUT_RDWR);
	}
}

static int http_ssl_handshake(http_ctx_t* ctx, http_conn_t* conn)
{
	int r;
	int err;
	conn->conn.status = cs_ssl_handshaking;
	r = SSL_connect(conn->ssl);
	if (r == 1) {
		/* connected */
		conn->conn.status = cs_ssl_handshaked;
		http_move_to_busy(conn);
		logv("http_ssl_handshake(): ssl handshaked\n");
		return 0;
	}

	if (r == -1) {
		err = SSL_get_error(conn->ssl, r);
		if (err == SSL_ERROR_WANT_READ) {
			conn->conn.status = cs_ssl_handshaking_want_read;
			return 0;
		}
		else if (err == SSL_ERROR_WANT_WRITE) {
			conn->conn.status = cs_ssl_handshaking_want_write;
			return 0;
		}
		else {
			loge("http_ssl_handshake() error: errno=%d, %s\n",
				err, ERR_error_string(err, NULL));
		}
	}

	if (r != 0) {
		SSL_shutdown(conn->ssl);
	}

	return -1;
}

static int http_socks5_handshake(http_ctx_t* ctx, http_conn_t* conn)
{
	int r;
	conn_status cs = conn->conn.status;
	stream_t* s = &conn->proxy_stream;
	int rsize = stream_rsize(s);

	if (s->cap < 1024) {
		if (stream_set_cap(s, 1024)) {
			return -1;
		}
	}

	switch (cs) {
	case cs_connected:
		if (rsize == 0) {
			s->array[0] = 0x05;
			s->array[1] = 0x01;
			s->array[2] = 0x00;
			s->pos = 0;
			s->size = 3;
		}
		r = tcp_send(conn->conn.sock, s);
		if (r < 0) {
			loge("http_socks5_handshake() error: tcp_send() error\n");
			return -1;
		}
		if (stream_rsize(s) > 0) {
			conn->conn.status = cs_socks5_sending_method;
		}
		else {
			conn->conn.status = cs_socks5_waiting_method;
		}
		break;
	case cs_socks5_waiting_method:
		r = tcp_recv(conn->conn.sock, s->array, s->cap);
		if (r != 2) {
			loge("http_socks5_handshake() error: tcp_recv() error\n");
			return -1;
		}
		if (s->array[0] == 0x05 && s->array[1] == 0x00) {
			s->array[0] = 0x05;
			s->array[1] = 0x01;
			s->array[2] = 0x00;
			if (conn->pool->addr.addr.ss_family == AF_INET) {
				struct sockaddr_in* addr = (struct sockaddr_in*)&conn->pool->addr.addr;
				int port = htons(addr->sin_port);
				s->array[3] = 0x01;
				memcpy(s->array + 4, &addr->sin_addr, 4);
				s->array[8] = (char)((port >> 8) & 0xff);
				s->array[9] = (char)((port >> 0) & 0xff);
				s->size = 10;
			}
			else {
				s->array[3] = 0x04;
				struct sockaddr_in6* addr = (struct sockaddr_in6*)&conn->pool->addr.addr;
				int port = htons(addr->sin6_port);
				s->array[3] = 0x01;
				memcpy(s->array + 4, &addr->sin6_addr, 16);
				s->array[20] = (char)((port >> 8) & 0xff);
				s->array[21] = (char)((port >> 0) & 0xff);
				s->size = 22;
			}
			s->pos = 0;
			conn->conn.status = cs_socks5_sending_connect;
			r = tcp_send(conn->conn.sock, s);
			if (r < 0) {
				loge("http_socks5_handshake() error: tcp_send() error\n");
				return -1;
			}
			if (stream_rsize(s) > 0) {
				conn->conn.status = cs_socks5_sending_connect;
			}
			else {
				conn->conn.status = cs_socks5_waiting_connect;
			}
		}
		else {
			loge("http_socks5_handshake() error: no support method\n");
			return -1;
		}
		break;
	case cs_socks5_sending_connect:
		r = tcp_send(conn->conn.sock, s);
		if (r < 0) {
			loge("http_socks5_handshake() error: tcp_send() error\n");
			return -1;
		}
		if (stream_rsize(s) > 0) {
			conn->conn.status = cs_socks5_sending_connect;
		}
		else {
			conn->conn.status = cs_socks5_waiting_connect;
		}
		break;
	case cs_socks5_waiting_connect:
		r = tcp_recv(conn->conn.sock, s->array, s->cap);
		if (r <= 0) {
			loge("http_socks5_handshake() error: tcp_recv() error\n");
			return -1;
		}
		if (s->array[0] == 0x05 && s->array[1] == 0x00) {
			conn->conn.status = cs_socks5_handshaked;
			stream_free(s);
			logv("http_socks5_handshake(): socks5 handshaked\n");
			return http_ssl_handshake(ctx, conn);
		}
		else {
			loge("http_socks5_handshake() error: connect error\n");
			return -1;
		}
		break;
	default:
		loge("http_socks5_handshake() error: unknown status\n");
		return -1;
	}

	return 0;
}

static http_conn_t* http_conn_create(http_ctx_t* ctx, const char* host, sockaddr_t* addr)
{
	http_conn_t* conn = NULL;
	sock_t sock = 0;
	conn_status cs;
	SSL* ssl;

	ssl = SSL_new(sslctx);
	if (!ssl) {
		loge("http_conn_create() error: SSL_new() error\n");
		return NULL;
	}

	conn = (http_conn_t*)malloc(sizeof(http_conn_t));
	if (!conn) {
		loge("http_conn_create() error: alloc\n");
		SSL_free(ssl);
		return NULL;
	}

	memset(conn, 0, sizeof(http_conn_t));

	if (ctx->proxy_num > 0) {
		cs = tcp_connect(&ctx->proxies->addr, &sock);
	}
	else {
		cs = tcp_connect(addr, &sock);
	}
	if (cs != cs_connected && cs != cs_connecting) {
		loge("http_conn_create() error: tcp_connect() error\n");
		free(conn);
		SSL_free(ssl);
		return NULL;
	}

	if (conn_init(&conn->conn, sock)) {
		loge("http_conn_create() error: conn_init() error\n");
		close(sock);
		free(conn);
		SSL_free(ssl);
		return NULL;
	}

	conn->conn.status = cs;

	conn->ssl = ssl;
	conn->http_ctx = ctx;

	/* set expire */
	http_update_expire(conn);

	SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
	SSL_set_fd(ssl, sock);

	/* Enable the ServerNameIndication extension */
	if (!SSL_set_tlsext_host_name(ssl, host)) {
		loge("http_conn_create() error: SSL_set_tlsext_host_name() error\n");
		close(sock);
		free(conn);
		SSL_free(ssl);
		return NULL;
	}

	logv("http_conn_create()\n");

	return conn;
}

static http_pool_item_t* http_pool_item_create(http_ctx_t* ctx, sockaddr_t* addr)
{
	http_pool_item_t* pi = NULL;
	pi = (http_pool_item_t*)malloc(sizeof(http_pool_item_t));
	if (!pi) {
		loge("http_pool_item_create() error: alloc\n");
		return NULL;
	}

	memset(pi, 0, sizeof(http_pool_item_t));
	dllist_init(&pi->busy_conns);
	dllist_init(&pi->fly_conns);
	dllist_init(&pi->idle_conns);
	memcpy(&pi->addr, addr, sizeof(sockaddr_t));
	pi->rbn.key = &pi->addr;
	rbtree_insert(&ctx->pool, &pi->rbn);

	logv("http_pool_item_create()\n");

	return pi;
}

static http_conn_t* http_get_conn(http_ctx_t* ctx, const char *host, sockaddr_t* addr)
{
	http_conn_t* conn = NULL;
	http_pool_item_t* pi = NULL;
	struct rbnode_t* rbn = rbtree_lookup(&ctx->pool, addr);
	if (rbn) {
		pi = rbtree_container_of(rbn, http_pool_item_t, rbn);
		if (!dllist_is_empty(&pi->idle_conns)) {
			dlitem_t* first = dllist_start(&pi->idle_conns);
			conn = dllist_container_of(first, http_conn_t, entry);
			http_move_to_busy(conn);
		}
	}

	if (!conn) {

		conn = http_conn_create(ctx, host, addr);
		if (!conn) {
			loge("http_get_conn() error: http_conn_create() error\n");
			return NULL;
		}

		if (!pi) {
			pi = http_pool_item_create(ctx, addr);
			if (!pi) {
				loge("http_get_conn() error: http_pool_item_create() error\n");
				conn_free(&conn->conn);
				free(conn);
				return NULL;
			}
		}

		conn->pool = pi;

		http_add_to_fly(conn);
	}

	return conn;
}

static int http_conn_send(http_conn_t* conn)
{
	stream_t* s = &conn->conn.ws;
	int rsize = stream_rsize(s);
	int nsend;

	if (rsize == 0)
		return 0;

	nsend = SSL_write(conn->ssl, s->array + s->pos, rsize);
	if (nsend <= 0) {
		int err = SSL_get_error(conn->ssl, nsend);
		if (err == SSL_ERROR_WANT_READ) {
			conn->ssl_status = SSL_ERROR_WANT_READ;
			return 0;
		}
		else if (err == SSL_ERROR_WANT_WRITE) {
			conn->ssl_status = SSL_ERROR_WANT_WRITE;
			return 0;
		}
		else {
			loge("http_conn_send() error: errno=%d, %s\n",
				err, ERR_error_string(err, NULL));
			return -1;
		}
	}
	else {
		conn->ssl_status = 0;
		s->pos += nsend;
		logv("http_conn_send(): send %d bytes\n", nsend);
		if (stream_quake(s)) {
			loge("http_conn_send() error: stream_quake()\n");
			return -1;
		}
		return nsend;
	}
}

static int http_conn_recv(http_conn_t* conn)
{
	stream_t* s = &conn->conn.rs;
	char* buffer;
	int buflen, nread;
	size_t nparsed;

	if (s->cap < 8*1024) {
		if (stream_set_cap(s, 8 * 1024)) {
			return -1;
		}
	}

	buffer = s->array;
	buflen = s->cap;

	nread = SSL_read(conn->ssl, buffer, buflen);

	if (nread <= 0) {
		int err = SSL_get_error(conn->ssl, nread);
		if (err == SSL_ERROR_WANT_READ) {
			conn->ssl_status = SSL_ERROR_WANT_READ;
			return 0;
		}
		else if (err == SSL_ERROR_WANT_WRITE) {
			conn->ssl_status = SSL_ERROR_WANT_WRITE;
			return 0;
		}
		else {
			loge("http_conn_recv() error: errno=%d, %s\n",
				err, ERR_error_string(err, NULL));
			return -1;
		}
	}
	else {
		conn->ssl_status = 0;

		logv("http_conn_recv(): recv %d bytes\n", nread);

		http_update_expire(conn);

		nparsed = http_parser_execute(&conn->parser, &parser_settings, s->array, nread);

		if (nparsed <= 0) {
			loge("http_conn_recv() error: %s\n", http_errno_name(conn->parser.http_errno));
			return -1;
		}

		return nread;
	}
}

static int on_message_begin(http_parser* parser)
{
	http_conn_t* conn = (http_conn_t*)parser->data;
	return 0;
}

static int on_status(http_parser* parser, const char* at, size_t length)
{
	http_conn_t* conn = (http_conn_t*)parser->data;
	http_response_t* response = conn->response;
	response->status_code = parser->status_code;
	response->status_text = http_strdup(at, length);
	response->http_major = parser->http_major;
	response->http_minor = parser->http_minor;
	return 0;
}

static int on_header_field_complete(http_parser* parser)
{
	http_conn_t* conn = (http_conn_t*)parser->data;
	http_response_t* response = conn->response;

	http_response_add_header(response,
		conn->field.name.array,
		conn->field.value.array);

	stream_reset(&conn->field.name);
	stream_reset(&conn->field.value);
	conn->field.status = fs_none;

	return 0;
}

static int on_header_field(http_parser* parser, const char* at, size_t length)
{
	http_conn_t* conn = (http_conn_t*)parser->data;

	if (conn->field.status == fs_value) {
		if (on_header_field_complete(parser))
			return -1;
	}

	conn->field.status = fs_name;

	if (stream_writes(&conn->field.name, at, (int)length) == -1) {
		loge("on_header_field() error: stream_writes()\n");
		return -1;
	}

	return 0;
}

static int on_header_value(http_parser* parser, const char* at, size_t length)
{
	http_conn_t* conn = (http_conn_t*)parser->data;

	conn->field.status = fs_value;

	if (stream_writes(&conn->field.value, at, (int)length) == -1) {
		loge("on_header_value() error: stream_writes()\n");
		return -1;
	}

	return 0;
}

static int on_headers_complete(http_parser* parser)
{
	http_conn_t* conn = (http_conn_t*)parser->data;
	http_response_t* response = conn->response;

	if (conn->field.status != fs_none) {
		if (on_header_field_complete(parser))
			return -1;
	}

	conn->keep_alive = http_should_keep_alive(parser);

	if (loglevel > LOG_DEBUG) {
		stream_t s = STREAM_INIT();
		http_response_headers_serialize(&s, response);
		logv("Response Headers:\r\n%s\r\n", s.array);
		stream_free(&s);
	}

	return 0;
}

static int on_body(http_parser* parser, const char* at, size_t length)
{
	http_conn_t* conn = (http_conn_t*)parser->data;
	http_response_t* response = conn->response;

	if (http_response_append_data(response, at, (int)length) == -1) {
		loge("on_body() error: http_response_append_data()\n");
		return -1;
	}
	return 0;
}

static int on_message_complete(http_parser* parser)
{
	http_conn_t* conn = (http_conn_t*)parser->data;
	http_request_t* request = conn->request;
	http_response_t* response = conn->response;

	http_call_callback(request, HTTP_OK, response);

	if (conn->keep_alive) {
		http_move_to_idle(conn);
	}
	else {
		http_remove_conn(conn);
		http_conn_free(conn);
	}
	return 0;
}

static int on_chunk_header(http_parser* parser)
{
	http_conn_t* conn = (http_conn_t*)parser->data;
	return 0;
}

static int on_chunk_complete(http_parser* parser)
{
	http_conn_t* conn = (http_conn_t*)parser->data;
	return 0;
}


static void http_call_callback(http_request_t* req, int err, http_response_t *res)
{
	if (!req) return;
	if (req->conn) {
		req->conn->request = NULL;
		req->conn = NULL;
	}
	if (req->callback) {
		req->callback(err, req, res, req->cb_state);
		req->callback = NULL;
		req->cb_state = NULL;
	}
}

static void dl_fdset_func(dllist_t* conns, http_fdset_state* st)
{
	dlitem_t* cur, * nxt;
	http_conn_t* conn;
	conn_status cs;
	int is_sending;
	dllist_foreach(conns, cur, nxt,
		http_conn_t, conn, entry) {
		cs = conn->conn.status;
		if (cs == cs_ssl_handshaked) {
			st->maxfd = MAX(st->maxfd, conn->conn.sock);
			if (conn->ssl_status == SSL_ERROR_WANT_READ) {
				FD_SET(conn->conn.sock, st->readset);
			}
			else if (conn->ssl_status == SSL_ERROR_WANT_WRITE) {
				FD_SET(conn->conn.sock, st->writeset);
			}
			else {
				is_sending = stream_rsize(&conn->conn.ws) > 0;
				if (is_sending)
					FD_SET(conn->conn.sock, st->writeset);
				else
					FD_SET(conn->conn.sock, st->readset);
			}
			FD_SET(conn->conn.sock, st->errorset);
		}
		else if (cs == cs_ssl_handshaking_want_read ||
			cs == cs_socks5_waiting_method ||
			cs == cs_socks5_waiting_connect) {
			st->maxfd = MAX(st->maxfd, conn->conn.sock);
			FD_SET(conn->conn.sock, st->readset);
			FD_SET(conn->conn.sock, st->errorset);
		}
		else if (cs == cs_ssl_handshaking_want_write ||
			cs == cs_socks5_sending_method ||
			cs == cs_socks5_sending_connect) {
			st->maxfd = MAX(st->maxfd, conn->conn.sock);
			FD_SET(conn->conn.sock, st->writeset);
			FD_SET(conn->conn.sock, st->errorset);
		}
		else if (cs == cs_connecting) {
			st->maxfd = MAX(st->maxfd, conn->conn.sock);
			FD_SET(conn->conn.sock, st->writeset);
			FD_SET(conn->conn.sock, st->errorset);
		}
	}
}

static void dl_step_func(dllist_t* conns, http_step_state* st)
{
	dlitem_t* cur, * nxt;
	http_conn_t* conn;
	conn_status cs;
	http_request_t* req;
	http_response_t* res;
	time_t now;
	int r = 0;
	int is_sending;
	now = time(NULL);
	dllist_foreach(conns, cur, nxt,
		http_conn_t, conn, entry) {
		cs = conn->conn.status;
		r = 0;
		if (cs == cs_closing || cs == cs_rsp_closing) {
			r = -1;
		}
		else if (FD_ISSET(conn->conn.sock, st->errorset)) {
			int err = getsockerr(conn->conn.sock);
			loge("dl_step_func(): peer.conn.sock error: errno=%d, %s \n",
				err, strerror(err));
			r = -1;
		}
		else {
			if (cs == cs_ssl_handshaked) {
				if (conn->ssl_status == SSL_ERROR_WANT_READ) {
					if (FD_ISSET(conn->conn.sock, st->readset)) {
						is_sending = stream_rsize(&conn->conn.ws) > 0;
						if (is_sending) {
							r = http_conn_send(conn);
							if (r >= 0)
								r = 0;
						}
						else {
							r = http_conn_recv(conn);
							if (r >= 0)
								r = 0;
						}
					}
				}
				else if (conn->ssl_status == SSL_ERROR_WANT_WRITE) {
					if (FD_ISSET(conn->conn.sock, st->writeset)) {
						is_sending = stream_rsize(&conn->conn.ws) > 0;
						if (is_sending) {
							r = http_conn_send(conn);
							if (r >= 0)
								r = 0;
						}
						else {
							r = http_conn_recv(conn);
							if (r >= 0)
								r = 0;
						}
					}
				}
				else {
					is_sending = stream_rsize(&conn->conn.ws) > 0;
					if (is_sending) {
						if (FD_ISSET(conn->conn.sock, st->writeset)) {
							r = http_conn_send(conn);
							if (r >= 0)
								r = 0;
						}
					}
					else if (FD_ISSET(conn->conn.sock, st->readset)) {
						r = http_conn_recv(conn);
						if (r >= 0)
							r = 0;
					}
				}
			}
			else if (cs == cs_ssl_handshaking_want_read) {
				if (FD_ISSET(conn->conn.sock, st->readset)) {
					r = http_ssl_handshake(st->ctx, conn);
				}
			}
			else if (cs == cs_ssl_handshaking_want_write) {
				if (FD_ISSET(conn->conn.sock, st->writeset)) {
					r = http_ssl_handshake(st->ctx, conn);
				}
			}
			else if (cs == cs_socks5_waiting_method || cs == cs_socks5_waiting_connect) {
				if (FD_ISSET(conn->conn.sock, st->readset)) {
					r = http_socks5_handshake(st->ctx, conn);
				}
			}
			else if (cs == cs_socks5_sending_method || cs == cs_socks5_sending_connect) {
				if (FD_ISSET(conn->conn.sock, st->writeset)) {
					r = http_socks5_handshake(st->ctx, conn);
				}
			}
			else if (cs == cs_connecting) {
				if (FD_ISSET(conn->conn.sock, st->writeset)) {
					conn->conn.status = cs_connected;
					if (st->ctx->proxy_num > 0) {
						r = http_socks5_handshake(st->ctx, conn);
					}
					else {
						r = http_ssl_handshake(st->ctx, conn);
					}
				}
			}
		}

		if (!r && http_is_expired(conn, now)) {
			loge("http timeout - %s\n", get_sockname(conn->conn.sock));
			r = -1;
			req = conn->request;
			res = conn->response;
			if (req) {
				http_call_callback(req, HTTP_TIMEOUT, res);
			}
			http_remove_conn(conn);
			http_conn_free(conn);
		}
		else if (r) {
			req = conn->request;
			res = conn->response;
			if (req) {
				http_call_callback(req, HTTP_ERROR, res);
			}
			http_remove_conn(conn);
			http_conn_free(conn);
		}
	}
}

static int rb_fdset_func(rbtree_t* tree, rbnode_t* n, void* state)
{
	http_fdset_state* st = (http_fdset_state*)state;
	http_pool_item_t* pi = rbtree_container_of(n, http_pool_item_t, rbn);
	/* "fly" should be first, then "idle", then "busy". */
	/* otherwise, some connection maybe processed twice. */
	dl_fdset_func(&pi->fly_conns, st);
	dl_fdset_func(&pi->idle_conns, st);
	dl_fdset_func(&pi->busy_conns, st);
	return 0;
}

static int rb_step_func(rbtree_t* tree, rbnode_t* n, void* state)
{
	http_step_state* st = (http_step_state*)state;
	http_pool_item_t* pi = rbtree_container_of(n, http_pool_item_t, rbn);
	dl_step_func(&pi->idle_conns, st);
	dl_step_func(&pi->busy_conns, st);
	dl_step_func(&pi->fly_conns, st);
	return 0;
}

http_ctx_t* http_create(
	const proxy_t* proxies,
	const int proxy_num,
	int timeout)
{
	http_ctx_t* ctx = (http_ctx_t*)malloc(sizeof(http_ctx_t));
	if (!ctx) {
		loge("http_create() error: alloc\n");
		return NULL;
	}

	memset(ctx, 0, sizeof(http_ctx_t));

	rbtree_init(&ctx->pool, rbcmp);

	ctx->proxies = proxies;
	ctx->proxy_num = proxy_num;
	ctx->timeout = timeout;

	return ctx;
}

void http_destroy(http_ctx_t* ctx)
{
	if (ctx) {
		rbtree_clear(&ctx->pool, rbnfree, NULL);
	}
}

sock_t http_fdset(http_ctx_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	http_fdset_state state = {
		.ctx = ctx,
		.readset = readset,
		.writeset = writeset,
		.errorset = errorset,
		.maxfd = 0
	};

	rbtree_foreach_preorder(&ctx->pool, rb_fdset_func, &state);

	return state.maxfd;
}

int http_step(http_ctx_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	http_step_state state = {
		.ctx = ctx,
		.readset = readset,
		.writeset = writeset,
		.errorset = errorset,
	};

	rbtree_foreach_preorder(&ctx->pool, rb_step_func, &state);

	return 0;
}

int http_send(http_ctx_t* ctx, sockaddr_t* addr, http_request_t* request,
	http_callback_fun_t callback, void* state)
{
	http_conn_t* conn;
	http_response_t* response;
	int r;

	response = http_response_create();
	if (!response) {
		loge("http_send() error: http_response_create() error\n");
		return -1;
	}

	conn = http_get_conn(ctx, request->host, addr);
	if (!conn) {
		loge("http_send() error: http_get_conn() error\n");
		http_response_destroy(response);
		return -1;
	}

	if (conn->conn.status == cs_connected) {
		if (ctx->proxy_num > 0) {
			r = http_socks5_handshake(ctx, conn);
		}
		else {
			r = http_ssl_handshake(ctx, conn);
		}
		if (r) {
			loge("http_send() error: %s() error\n",
				ctx->proxy_num > 0 ? "http_socks5_handshake" : "http_ssl_handshake");
			http_conn_close(ctx, conn);
			http_response_destroy(response);
			return -1;
		}
	}

	stream_reset(&conn->conn.ws);

	r = http_request_serialize(&conn->conn.ws, request);
	if (r <= 0) {
		loge("http_send() error: http_request_serialize() error\n");
		http_conn_close(ctx, conn);
		http_response_destroy(response);
		return -1;
	}

	logv("Request Headers:\r\n%s\r\n", conn->conn.ws.array);

	http_parser_init(&conn->parser, HTTP_RESPONSE);
	stream_reset(&conn->field.name);
	stream_reset(&conn->field.value);

	conn->parser.data = conn;

	if (conn->conn.status == cs_ssl_handshaked) {
		r = http_conn_send(conn);
		if (r < 0) {
			loge("http_send() error: http_conn_send() error\n");
			http_conn_close(ctx, conn);
			http_response_destroy(response);
			return -1;
		}
	}

	request->conn = conn;
	request->callback = callback;
	request->cb_state = state;

	response->conn = conn;

	conn->request = request;
	conn->response = response;

	return 0;
}
