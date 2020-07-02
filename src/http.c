#include "http.h"
#include "dllist.h"
#include "../rbtree/rbtree.h"
#include "netutils.h"
#include "log.h"
#include "stream.h"

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

typedef struct http_conn_t {
	struct conn_t conn;
	SSL* ssl;
	int ssl_status;
	int status;				/* HTTP_CONN_ST_[NONE|FLY|IDLE|BUSY] */
	http_pool_item_t* pool;
	dlitem_t entry;
	http_request_t* request;
	http_response_t* response;
} http_conn_t;

struct http_request_t {
	const char* method; /* GET|POST */
	const char* path;   /* request path */
	const char* host;
	dllist_t    headers;
	const char* data;
	int         data_len;
	http_conn_t* conn;
	http_callback_fun_t callback;
	void* cb_state;
};

struct http_response_t {
	int      status_code;
	char*    status_text;
	dllist_t headers;
	char*    content;
	int      content_len;
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


static SSL_CTX* sslctx = NULL;


static void http_conn_free(http_conn_t *conn)
{
	if (conn->request && conn->request->callback) {
		conn->request->conn = NULL;
		conn->request->callback(
			HTTP_ABORT,
			conn->request,
			NULL,
			conn->request->cb_state);
	}
	if (conn->ssl) {
		SSL_free(conn->ssl);
	}
	conn_free(&conn->conn);
	free(conn);

	logd("http_conn_free()\n");
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

	logd("http_pool_item_free()\n");
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

const char* http_request_get_data(http_request_t* request, int* data_len)
{
	if (data_len) *data_len = request->data_len;
	return request->data;
}

void http_request_set_data(http_request_t* request,
	const char* data, int data_len)
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



http_response_t* http_response_create()
{
	http_response_t* res = (http_response_t*)malloc(sizeof(http_response_t));
	if (!res) {
		loge("http_response_create() error: alloc\n");
		return NULL;
	}

	memset(res, 0, sizeof(http_response_t));

	dllist_init(&res->headers);

	return res;
}

void http_response_destroy(http_response_t* response)
{
	if (response) {
		dlitem_t* cur, * nxt;
		http_header_t* header;
		dllist_foreach(&response->headers, cur, nxt,
			http_header_t, header, entry) {
			dllist_remove(&header->entry);
			free(header->name);
			free(header->value);
			free(header);
		}
		free(response->status_text);
		free(response->content);
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


int http_init(const config_t* conf)
{
	const SSL_METHOD* method;

	/* ---------------------------------------------------------- *
     * These function calls initialize openssl for correct work.  *
     * ---------------------------------------------------------- */
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();

	/* ---------------------------------------------------------- *
	 * initialize SSL library and register algorithms             *
	 * ---------------------------------------------------------- */
	if (SSL_library_init() < 0) {
		loge("http_init() error: Could not initialize the OpenSSL library !\n");
		return -1;
	}

	/* ---------------------------------------------------------- *
	 * Set SSLv2 client hello, also announce SSLv3 and TLSv1      *
	 * ---------------------------------------------------------- */
	method = SSLv23_client_method();

	/* ---------------------------------------------------------- *
	 * Try to create a new SSL context                            *
	 * ---------------------------------------------------------- */
	if ((sslctx = SSL_CTX_new(method)) == NULL) {
		loge("http_init() error: Unable to create a new SSL context structure.\n");
		return -1;
	}

	/* ---------------------------------------------------------- *
	 * Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
	 * ---------------------------------------------------------- */
	SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv2);

	return 0;
}

void http_uninit()
{
	if (sslctx) {
		SSL_CTX_free(sslctx);
		sslctx = NULL;
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
	}

	if (r != 0) {
		SSL_shutdown(conn->ssl);
	}

	return -1;
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
	http_remove_conn(conn);
	http_add_to_busy(conn);
}

static void http_move_to_idle(http_conn_t* conn)
{
	http_remove_conn(conn);
	http_add_to_idle(conn);
}

static void http_move_to_fly(http_conn_t* conn)
{
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

static http_conn_t* http_conn_create(http_ctx_t* ctx, sockaddr_t* addr)
{
	http_conn_t* conn = NULL;
	sock_t sock;
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

	cs = tcp_connect(addr, &sock);
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

	/* set expire */
	conn->conn.expire = time(NULL) + ctx->timeout;

	SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
	SSL_set_fd(ssl, sock);

	logd("http_conn_create()\n");

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

	logd("http_pool_item_create()\n");

	return pi;
}

static http_conn_t* http_get_conn(http_ctx_t* ctx, sockaddr_t* addr)
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

		conn = http_conn_create(ctx, addr);
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

static int http_request_serialize(/*write stream*/stream_t *s, http_request_t* req)
{
	struct dliterator_t it;
	const char* name;
	const char* value;
	int have_connection = FALSE;
	int have_host = FALSE;

	stream_reset(s);
	if (stream_appendf(s,
		"%s %s HTTP/1.1\r\n",
		req->method,
		req->path) == -1) {
		loge("http_request_serialize() error: stream_appendf()");
		return -1;
	}

	dliterator_reset(&it);

	while (http_request_header_next(req, &it, &name, &value)) {
		if (stream_appendf(s, "%s: %s\r\n", name, value) == -1) {
			loge("http_request_serialize() error: stream_appendf()");
			return -1;
		}
		if (strcmp(name, "Connection") == 0)
			have_connection = TRUE;
		else if (strcmp(name, "Host") == 0)
			have_host = TRUE;
	}

	if (!have_host) {
		if (stream_appendf(s, "Host: %s\r\n", req->host) == -1) {
			loge("http_request_serialize() error: stream_appendf()");
			return -1;
		}
	}

	if (!have_connection) {
		if (stream_appendf(s, "Connection: %s\r\n", "keep-alive") == -1) {
			loge("http_request_serialize() error: stream_appendf()");
			return -1;
		}
	}

	if (strcmp(req->method, "POST") == 0) {
		if (stream_appendf(s, "Content-Length: %d\r\n\r\n", req->data_len) == -1) {
			loge("http_request_serialize() error: stream_appendf()");
			return -1;
		}

		if (req->data_len > 0) {
			if (stream_writes(s, req->data, req->data_len) == -1) {
				loge("http_request_serialize() error: stream_appendf()");
				return -1;
			}
		}
	}
	else {
		if (stream_writes(s, "\r\n", 2) == -1) {
			loge("http_request_serialize() error: stream_appendf()");
			return -1;
		}
	}

	s->pos = 0;

	logv("Request Headers:\r\n%s\r\n", s->array);

	return s->size;
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
			loge("http_conn_send() error: errno=%d \n", err);
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

	if (stream_set_cap(s, 8 * 1024)) {
		return -1;
	}

	buffer = s->array + s->size;
	buflen = s->cap - s->size;

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
			loge("http_conn_recv() error: errno=%d \n", err);
			return -1;
		}
	}
	else {
		conn->ssl_status = 0;
		s->size += nread;
		logv("http_conn_recv(): recv %d bytes\n", nread);
		if (stream_quake(s)) {
			loge("http_conn_recv() error: stream_quake()\n");
			return -1;
		}
		return nread;
	}
}

static inline int http_is_expired(conn_t* conn, time_t now)
{
	return conn->expire <= now;
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
		else if (cs == cs_ssl_handshaking_want_read) {
			st->maxfd = MAX(st->maxfd, conn->conn.sock);
			FD_SET(conn->conn.sock, st->readset);
			FD_SET(conn->conn.sock, st->errorset);
		}
		else if (cs == cs_ssl_handshaking_want_write) {
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
			else if (cs == cs_connecting) {
				if (FD_ISSET(conn->conn.sock, st->writeset)) {
					r = http_ssl_handshake(st->ctx, conn);
				}
			}
		}

		if (!r && http_is_expired(&conn->conn, now)) {
			logd("http timeout - %s\n", get_sockname(conn->conn.sock));
			r = -1;
			req = conn->request;
			res = conn->response;
			http_remove_conn(conn);
			http_conn_free(conn);
			if (req) {
				http_call_callback(req, HTTP_TIMEOUT, res);
			}
		}
		else if (r) {
			req = conn->request;
			res = conn->response;
			http_remove_conn(conn);
			http_conn_free(conn);
			if (req) {
				http_call_callback(req, HTTP_ERROR, res);
			}
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
	int r;

	conn = http_get_conn(ctx, addr);
	if (!conn) {
		loge("http_send() error: http_get_conn() error\n");
		return -1;
	}

	if (conn->conn.status == cs_connected) {
		if (http_ssl_handshake(ctx, conn)) {
			loge("http_send() error: http_ssl_handshake() error\n");
			http_conn_close(ctx, conn);
			return -1;
		}
	}

	r = http_request_serialize(&conn->conn.ws, request);
	if (r <= 0) {
		loge("http_send() error: http_request_serialize() error\n");
		return -1;
	}

	if (conn->conn.status == cs_ssl_handshaked) {
		r = http_conn_send(conn);
		if (r < 0) {
			loge("http_send() error: http_conn_send() error\n");
			http_conn_close(ctx, conn);
			return -1;
		}
	}

	request->callback = callback;
	request->cb_state = state;
	conn->request = request;

	return 0;
}
