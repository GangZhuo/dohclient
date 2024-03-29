#include "channel_os.h"
#include "mleak.h"

#define _M

typedef struct channel_os_t {
	CHANNEL_BASE(_M)
} channel_os_t;

static void destroy(channel_t* ctx)
{
	channel_os_t* c = (channel_os_t*)ctx;
	free(ctx);
}

static sock_t fdset(channel_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	return 0;
}

static int step(channel_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	return 0;
}

static int query(channel_t* ctx,
	const ns_msg_t* msg,
	channel_query_cb callback, void* state)
{
	sockaddr_t addr = { 0 };
	void* ip = (struct sockaddr_in*)&addr.addr;
	int family, r;
	ns_msg_t* result = NULL;
	ns_flags_t flg = { 0 };

	if (msg->qdcount <= 0) {
		loge("no question\n");
		goto error;
	}
	else if (msg->qrs->qtype == NS_QTYPE_A) {
		family = AF_INET;
		ip = &((struct sockaddr_in*)(&addr.addr))->sin_addr;
	}
	else if (msg->qrs->qtype == NS_QTYPE_AAAA) {
		family = AF_INET6;
		ip = &((struct sockaddr_in6*)(&addr.addr))->sin6_addr;
	}
	else {
		loge("invalid qtype %s - %s\n",
			ns_typename(msg->qrs->qtype),
			msg->qrs->qname);
		goto error;
	}

	r = host2addr(&addr, msg->qrs->qname, "55555", family);
	if (r) {
		goto error;
	}

	flg.qr = 1;
	flg.aa = 1;
	flg.ra = 1;

	result = (ns_msg_t*)malloc(sizeof(ns_msg_t));
	if (!result) {
		loge("alloc\n");
		goto error;
	}

	if (channel_build_msg(result, msg->id, &flg, msg->qrs, ip, family)) {
		loge("channel_build_msg() error\n");
		goto error;
	}

	if (callback)
		callback(ctx, 0, result, FALSE, TRUE, state);

	return 0;

error:
	if (result) {
		ns_msg_free(result);
		free(result);
	}
	if (callback)
		callback(ctx, -1, NULL, FALSE, FALSE, state);
	return 0;
}

int channel_os_create(
	channel_t** pctx,
	const char* name,
	const char* args,
	const config_t* conf,
	const proxy_t* proxies,
	const int proxy_num,
	const chnroute_ctx chnr,
	const chnroute_ctx blacklist,
	void* data)
{
	channel_os_t* ctx;

	ctx = (channel_os_t*)malloc(sizeof(channel_os_t));
	if (!ctx) {
		loge("alloc\n");
		return CHANNEL_ALLOC;
	}

	memset(ctx, 0, sizeof(channel_os_t));

	ctx->name = name;
	ctx->conf = conf;
	ctx->proxies = proxies;
	ctx->proxy_num = proxy_num;
	ctx->chnr = chnr;
	ctx->blacklist = blacklist;
	ctx->data = data;

	ctx->fdset = fdset;
	ctx->step = step;
	ctx->query = query;
	ctx->destroy = destroy;

	*pctx = (channel_t*)ctx;

	return CHANNEL_OK;
}
