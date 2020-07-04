#include "channel_doh.h"
#include "../rbtree/rbtree.h"
#include "http.h"

#define _M
#define MAX_QUEUE_SIZE	30000

typedef struct channel_doh_t {
	CHANNEL_BASE(_M)
	dllist_t reqs;
	struct rbtree_t reqdic;
	int req_count;
	http_ctx_t* http;
	sockaddr_t http_addr;
	char* host;
	char* path;
	int use_proxy;
} channel_doh_t;

typedef struct myreq_t {
	uint16_t req_id;
	uint16_t id;
	ns_flags_t flags;
	ns_qr_t qr;
	channel_query_cb callback;
	void* cb_state;
	dlitem_t entry;
	struct rbnode_t rbn;
	channel_doh_t* ctx;
} myreq_t;

static uint16_t new_req_id(channel_doh_t* ctx)
{
	uint16_t newid;

	do {
		newid = (uint16_t)(rand() % 0x7FFF);
	} while (newid == 0 || rbtree_lookup(&ctx->reqdic, &newid));

	return newid;
}

static myreq_t* myreq_new(
	channel_doh_t *ctx,
	const ns_msg_t* msg,
	channel_query_cb callback, void* cb_state)
{
	myreq_t* req;

	req = (myreq_t*)malloc(sizeof(myreq_t));
	if (!req) {
		loge("myreq_new() error: alloc\n");
		return NULL;
	}

	memset(req, 0, sizeof(myreq_t));

	req->req_id = new_req_id(ctx);
	req->id = msg->id;
	req->flags = msg->flags;
	req->qr = msg->qrs[0];
	req->qr.qname = strdup(msg->qrs[0].qname);
	req->callback = callback;
	req->cb_state = cb_state;
	req->rbn.key = &req->req_id;
	req->ctx = ctx;

	return req;
}

static void myreq_destroy(myreq_t* req)
{
	free(req->qr.qname);
	free(req);
}

static void destroy(channel_t* ctx)
{
	channel_doh_t* c = (channel_doh_t*)ctx;
	dlitem_t* cur, * nxt;
	myreq_t* req;
	dllist_foreach(&c->reqs, cur, nxt,
		myreq_t, req, entry) {
		dllist_remove(&req->entry);
		if (req->callback)
			req->callback(ctx, -1, NULL, req->cb_state);
		myreq_destroy(req);
	}
	http_destroy(c->http);
	free(c->host);
	free(c->path);
	free(c);
}

static sock_t fdset(channel_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	channel_doh_t* c = (channel_doh_t*)ctx;
	return http_fdset(c->http, readset, writeset, errorset);
}

static int step(channel_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	channel_doh_t* c = (channel_doh_t*)ctx;
	return http_step(c->http, readset, writeset, errorset);
}

static void http_cb(
	int status,
	http_request_t* request,
	http_response_t* response,
	void* state)
{
	myreq_t* rq = (myreq_t*)state;
	channel_doh_t* c = rq->ctx;
	int result_status = -1;
	ns_msg_t* result = NULL;
	char* data;
	int datalen;

	dllist_remove(&rq->entry);
	rbtree_remove(&c->reqdic, &rq->rbn);
	c->req_count--;

	if (status == HTTP_OK) {
		result = (ns_msg_t*)malloc(sizeof(ns_msg_t));
		if (!result) {
			loge("http_cb() error: alloc");
			goto exit;
		}
		
		if (init_ns_msg(result)) {
			loge("req_new() error: init_ns_msg() error");
			free(result);
			result = NULL;
			goto exit;
		}

		data = http_response_get_data(response, &datalen);
		if (ns_parse(result, (const uint8_t*)data, datalen)) {
			loge("req_new() error: ns_parse() error");
			ns_msg_free(result);
			free(result);
			result = NULL;
			goto exit;
		}

		result_status = 0;
	}

exit:
	if (rq->callback) {
		rq->callback((channel_t*)c, result_status, result, rq->cb_state);
	}

	myreq_destroy(rq);
	data = http_request_get_data(request, &datalen);
	free(data);
	http_request_destroy(request);
	http_response_destroy(response);
}

static int doh_query(myreq_t* rq)
{
	channel_doh_t* c = rq->ctx;
	http_request_t* req;
	int r;

	req = http_request_create("GET", "/", c->host);
	if (!req) {
		loge("doh_query() error: http_request_create() error\n");
		return -1;
	}

	r = http_send(c->http, &c->http_addr, req, http_cb, rq);
	if (r) {
		loge("doh_query() error: http_send() error\n");
		http_request_destroy(req);
		return -1;
	}

	return r;
}

static int query(channel_t* ctx,
	const ns_msg_t* msg,
	channel_query_cb callback, void* state)
{
	channel_doh_t* c = (channel_doh_t*)ctx;
	myreq_t* req;

	if (c->req_count > MAX_QUEUE_SIZE) {
		loge("request queue is full\n");
		return -1;
	}

	req = myreq_new(c, msg, callback, state);
	if (!req)
		return -1;

	dllist_add(&c->reqs, &req->entry);
	rbtree_insert(&c->reqdic, &req->rbn);
	c->req_count++;

	if (doh_query(req)) {
		loge("doh_query() failed\n");
		dllist_remove(&req->entry);
		rbtree_remove(&c->reqdic, &req->rbn);
		c->req_count--;
		myreq_destroy(req);
		return -1;
	}

	return 0;
}

static int rbcmp(const void* a, const void* b)
{
	int x = (int)(*((uint16_t*)a));
	int y = (int)(*((uint16_t*)b));
	return x - y;
}

static int parse_args(channel_doh_t *ctx, const char* args)
{
	char* cpy;
	char* p;
	char* v;

	if (!args) return -1;

	cpy = strdup(args);

	for (p = strtok(cpy, "&");
		p && *p;
		p = strtok(NULL, "&")) {

		v = strchr(p, '=');
		if (!v) continue;

		*v = '\0';
		v++;

		if (strcmp(p, "addr") == 0) {
			p = v;
			v = strchr(p, ':');
			if (v) {
				*v = '\0';
				v++;
			}
			if (!try_parse_as_ip( &ctx->http_addr, p, (v && (*v)) ? v : "443") ) {
				loge(
					"parse address failed: %s:%s\n",
					p,
					(v && (*v)) ? v : "443"
				);
				free(cpy);
				return -1;
			}
		}
		else if (strcmp(p, "host") == 0) {
			ctx->host = strdup(v);
		}
		else if (strcmp(p, "path") == 0) {
			ctx->path = strdup(v);
		}
		else if (strcmp(p, "proxy") == 0) {
			ctx->use_proxy = strcmp(v, "0");
		}
	}

	free(cpy);
	return 0;
}

int channel_doh_create(
	channel_t** pctx,
	const char* name,
	const char* args,
	const config_t* conf,
	const proxy_t* proxies,
	const int proxy_num,
	const chnroute_ctx* chnr,
	void* data)
{
	channel_doh_t* ctx;

	ctx = (channel_doh_t*)malloc(sizeof(channel_doh_t));
	if (!ctx) {
		loge("channel_os_create() error: alloc\n");
		return CHANNEL_ALLOC;
	}

	memset(ctx, 0, sizeof(channel_doh_t));

	if (parse_args(ctx, args)) {
		loge("channel_os_create() error: parse_args() error\n");
		return CHANNEL_WRONG_ARG;
	}

	ctx->http = http_create(
		proxies,
		ctx->use_proxy ? proxy_num : 0,
		DEFAULT_HTTP_TIMEOUT);
	if (!ctx->http) {
		free(ctx);
		return CHANNEL_ALLOC;
	}

	rbtree_init(&ctx->reqdic, rbcmp);
	dllist_init(&ctx->reqs);

	ctx->name = name;
	ctx->conf = conf;
	ctx->proxies = proxies;
	ctx->proxy_num = proxy_num;
	ctx->chnr = chnr;
	ctx->data = data;

	ctx->fdset = fdset;
	ctx->step = step;
	ctx->query = query;
	ctx->destroy = destroy;

	*pctx = (channel_t*)ctx;

	return CHANNEL_OK;
}
