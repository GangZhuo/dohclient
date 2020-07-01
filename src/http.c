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

struct http_ctx_t {
	struct rbtree_t pool;
	int timeout;
};

typedef struct http_pool_item_t {
	sockaddr_t addr; /* server's address */
	dllist_t idle_conns;  /* connections */
	dllist_t busy_conns;  /* connections */
	dllist_t fly_conns;  /* connections */
	struct rbnode_t rbn;
} http_pool_item_t;

typedef struct http_conn_t {
	struct conn_t conn;
	SSL* ssl;
	http_pool_item_t* pool;
	dlitem_t entry;
	http_request_t* request;
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
	void* state;
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
	if (conn->ssl) {
		SSL_free(conn->ssl);
	}
	conn_free(&conn->conn);
	free(conn);
}

static void http_pool_item_free_conns(dllist_t *conns)
{
	dlitem_t* cur, * nxt;
	http_conn_t* conn;
	dllist_foreach(conns, cur, nxt,
		http_conn_t, conn, entry) {
		dllist_remove(&conn->entry);
		if (conn->request && conn->request->callback) {
			conn->request->conn = NULL;
			conn->request->callback(HTTP_ABORT, conn->request, NULL, conn->request->state);
		}
		http_conn_free(conn);
	}
}

static void http_pool_item_free(http_pool_item_t* item)
{
	http_pool_item_free_conns(&item->idle_conns);
	http_pool_item_free_conns(&item->busy_conns);
	http_pool_item_free_conns(&item->fly_conns);
	free(item);
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

static void http_move_to_busy(http_conn_t* conn)
{
	dllist_remove(&conn->entry);
	dllist_add(&conn->pool->busy_conns, &conn->entry);
}

static void http_move_to_idle(http_conn_t* conn)
{
	dllist_remove(&conn->entry);
	dllist_add(&conn->pool->idle_conns, &conn->entry);
}

static void http_move_to_fly(http_conn_t* conn)
{
	dllist_remove(&conn->entry);
	dllist_add(&conn->pool->fly_conns, &conn->entry);
}

static void http_conn_close(http_ctx_t* ctx, http_conn_t* conn)
{
	conn->conn.status = cs_closing;
	http_move_to_fly(conn);
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

	SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
	SSL_set_fd(ssl, sock);

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

		dllist_add(&pi->fly_conns, &conn->entry);
	}

	return conn;
}

static int http_request_serialize(/*write stream*/stream_t *ws, http_request_t* request)
{
	return 0;
}

static int conn_send(http_conn_t* conn)
{
	return 0;
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
			is_sending = stream_rsize(&conn->conn.ws) > 0;
			if (is_sending)
				FD_SET(conn->conn.sock, st->writeset);
			else
				FD_SET(conn->conn.sock, st->readset);
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
	dllist_foreach(conns, cur, nxt,
		http_conn_t, conn, entry) {
		cs = conn->conn.status;
		if (cs == cs_ssl_handshaked) {

		}
		else if (cs == cs_ssl_handshaking_want_read) {

		}
		else if (cs == cs_ssl_handshaking_want_write) {

		}
		else if (cs == cs_connecting) {

		}
	}
}

static int rb_fdset_func(rbtree_t* tree, rbnode_t* n, void* state)
{
	http_fdset_state* st = (http_fdset_state*)state;
	http_pool_item_t* pi = rbtree_container_of(n, http_pool_item_t, rbn);
	dl_fdset_func(&pi->idle_conns, st);
	dl_fdset_func(&pi->busy_conns, st);
	dl_fdset_func(&pi->fly_conns, st);
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

http_ctx_t* http_create(int timeout)
{
	http_ctx_t* ctx = (http_ctx_t*)malloc(sizeof(http_ctx_t));
	if (!ctx) {
		loge("http_create() error: alloc\n");
		return NULL;
	}

	memset(ctx, 0, sizeof(http_ctx_t));

	rbtree_init(&ctx->pool, rbcmp);

	ctx->timeout = timeout;

	return NULL;
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
		r = conn_send(conn);
		if (r < 0) {
			loge("http_send() error: conn_send() error\n");
			http_conn_close(ctx, conn);
			return -1;
		}
	}

	request->callback = callback;
	request->state = state;
	conn->request = request;

	return 0;
}
