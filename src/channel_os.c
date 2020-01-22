#include "channel_os.h"

#define _M

typedef struct channel_os_t {
	CHANNEL_BASE(_M)
	dllist_t reqs;
} channel_os_t;

typedef struct myreq_t {
	uint16_t id;
	ns_flags_t flags;
	ns_qr_t qr;
	channel_query_cb callback;
	void* state;
	dlitem_t entry;
} myreq_t;

static myreq_t* myreq_new(
	const ns_msg_t* msg,
	channel_query_cb callback, void* state)
{
	myreq_t* req;

	req = (myreq_t*)malloc(sizeof(myreq_t));
	if (!req) {
		loge("myreq_new() error: alloc\n");
		return NULL;
	}

	memset(req, 0, sizeof(myreq_t));

	req->id = msg->id;
	req->flags = msg->flags;
	req->qr = msg->qrs[0];
	req->qr.qname = strdup(msg->qrs[0].qname);
	req->callback = callback;
	req->state = state;

	return req;
}

static void myreq_destroy(myreq_t* req)
{
	free(req->qr.qname);
	free(req);
}

static void destroy(channel_t* ctx)
{
	channel_os_t* c = (channel_os_t*)ctx;
	dlitem_t* cur, * nxt;
	myreq_t* req;
	dllist_foreach(&c->reqs, cur, nxt,
		myreq_t, req, entry) {
		dllist_remove(&req->entry);
		if (req->callback)
			req->callback(ctx, -1, NULL, req->state);
		myreq_destroy(req);
	}
	free(ctx);
}

static int fdset(channel_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
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
		req->callback(ctx, 0, &msg, req->state);

	ns_msg_free(&msg);

	return;

error:
	if (req->callback)
		req->callback(ctx, -1, NULL, req->state);
}

static int step(channel_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	channel_os_t* c = (channel_os_t*)ctx;
	dlitem_t* cur, * nxt;
	myreq_t* req;
	dllist_foreach(&c->reqs, cur, nxt,
		myreq_t, req, entry) {
		dllist_remove(&req->entry);
		reslove(ctx, req);
		myreq_destroy(req);
	}
	return 0;
}

static int query(channel_t* ctx,
	const ns_msg_t* msg,
	channel_query_cb callback, void* state)
{
	channel_os_t* c = (channel_os_t*)ctx;
	myreq_t* req;

	req = myreq_new(msg, callback, state);
	if (!req)
		return -1;
	dllist_add(&c->reqs, &req->entry);
	return 0;
}

channel_t* channel_os_create(
	const char* name,
	const config_t* conf,
	const proxy_t* proxies,
	const int proxy_num,
	const chnroute_ctx* chnr,
	void* data)
{
	channel_os_t* ctx;

	ctx = (channel_os_t*)malloc(sizeof(channel_os_t));
	if (!ctx) {
		loge("channel_os_create() error: alloc\n");
		return NULL;
	}

	memset(ctx, 0, sizeof(channel_os_t));

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

	return (channel_t*)ctx;
}
