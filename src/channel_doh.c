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
	free(ctx);
}

static int fdset(channel_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	channel_doh_t* c = (channel_doh_t*)ctx;
	if (!http_fdset(c->http, readset, writeset, errorset))
		return -1;
	return 0;
}

static void reslove(channel_t* ctx, myreq_t* req)
{
	sockaddr_t addr = { 0 };
	void* ip = (struct sockaddr_in*) & addr.addr;
	int family, r;
	ns_msg_t msg;
	ns_flags_t flg = { 0 };

	if (req->qr.qtype == NS_QTYPE_A) {
		family = AF_INET;
		ip = &((struct sockaddr_in*)(&addr.addr))->sin_addr;
	}
	else if (req->qr.qtype == NS_QTYPE_AAAA) {
		family = AF_INET6;
		ip = &((struct sockaddr_in6*)(&addr.addr))->sin6_addr;
	}
	else {
		loge("channel_os_reslove() error: invalid qtype %s - %s\n",
			ns_typename(req->qr.qtype),
			req->qr.qname);
		goto error;
	}

	r = host2addr(&addr, req->qr.qname, "55555", family);
	if (r) {
		goto error;
	}

	flg.bits.qr = 1;
	if (channel_build_msg(&msg, req->id, &flg, &req->qr, ip, family)) {
		loge("channel_os_reslove() error: channel_build_msg() error");
		goto error;
	}

	if (req->callback)
		req->callback(ctx, 0, &msg, req->cb_state);

	ns_msg_free(&msg);

	return;

error:
	if (req->callback)
		req->callback(ctx, -1, NULL, req->cb_state);
}

static int step(channel_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	channel_doh_t* c = (channel_doh_t*)ctx;
	dlitem_t* cur, * nxt;
	myreq_t* req;
	
	dllist_foreach(&c->reqs, cur, nxt,
		myreq_t, req, entry) {
		dllist_remove(&req->entry);
		rbtree_remove(&c->reqdic, &req->rbn);
		c->req_count--;
		reslove(ctx, req);
		myreq_destroy(req);
	}
	if (!http_step(c->http, readset, writeset, errorset))
		return -1;
	return 0;
}

static int query(channel_t* ctx,
	const ns_msg_t* msg,
	channel_query_cb callback, void* state)
{
	channel_doh_t* c = (channel_doh_t*)ctx;
	myreq_t* req;

	if (c->req_count > MAX_QUEUE_SIZE) {
		loge("request queue is full");
		return -1;
	}

	req = myreq_new(c, msg, callback, state);
	if (!req)
		return -1;

	dllist_add(&c->reqs, &req->entry);
	rbtree_insert(&c->reqdic, &req->rbn);
	c->req_count++;

	return 0;
}

static int rbcmp(const void* a, const void* b)
{
	int x = (int)(*((uint16_t*)a));
	int y = (int)(*((uint16_t*)b));
	return x - y;
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

	ctx->http = http_create(DEFAULT_HTTP_TIMEOUT);
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
