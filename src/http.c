#include "http.h"
#include "dllist.h"
#include "../rbtree/rbtree.h"
#include "netutils.h"
#include "log.h"
#include "stream.h"

struct http_ctx_t {
	struct rbtree_t pool;
	int timeout;
};

typedef struct http_pool_item_t {
	sockaddr_t addr; /* server's address */
	dllist_t idle_conns;  /* connections */
	dllist_t busy_conns;  /* connections */
	struct rbnode_t rbn;
} http_pool_item_t;

typedef struct http_conn_t {
	struct conn_t conn;
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

static void http_conn_free(http_conn_t *conn)
{
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

int http_fdset(http_ctx_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	int max_fd = 0;

	return max_fd;
}

int http_step(http_ctx_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	return 0;
}

int http_send(http_ctx_t* ctx, sockaddr_t* addr, http_request_t* request,
	http_callback_fun_t callback, void* state)
{
	return 0;
}
