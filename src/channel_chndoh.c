#include "channel_chndoh.h"
#include "../rbtree/rbtree.h"
#include "http.h"
#include "base64url.h"
#include "channel_udp.h"
#include "channel_tcp.h"
#include "mleak.h"

#define _M
#define MAX_QUEUE_SIZE	30000

#define FLG_NONE		0
#define FLG_POLLUTE		1
#define FLG_A			(1 << 1)
#define FLG_A_CHN		(1 << 2)
#define FLG_A_FRN		(1 << 3)
#define FLG_AAAA		(1 << 4)
#define FLG_AAAA_CHN	(1 << 5)
#define FLG_AAAA_FRN	(1 << 6)
#define FLG_PTR			(1 << 7)
#define FLG_OPT			(1 << 8)
#define FLG_ECS			(1 << 9)
#define FLG_ECS_CHN		(1 << 10)
#define FLG_ECS_FRN		(1 << 11)
#define FLG_BLACKLIST	(1 << 12)

#define CH_NONE	0
#define CH_DOH	1
#define CH_UDP	2
#define CH_TCP	3

typedef int (*doh_query_func)(
	channel_t* ctx,
	const ns_msg_t* request,
	int use_proxy, subnet_t* subnet,
	channel_query_cb callback, void* state);

typedef struct doh_server_t {
	time_t addr_expire;
	sockaddr_t addr;
	int post;
	char* host;
	char* path;
	int keep_alive;
	int use_proxy;
	int ecs;
	int timeout;
	subnet_t net;
	subnet_t net6;
	int channel; /* CH_[DOH|UDP|TCP] */
	union {
		channel_t* chctx;
		http_ctx_t* http;
	};
	doh_query_func query;
	int auto_resolve_host;
} doh_server_t;

typedef struct channel_chndoh_t {
	CHANNEL_BASE(_M)
	dllist_t reqs;
	struct rbtree_t reqdic;
	int req_count;

	/* China DoH server */
	doh_server_t chndoh;

	/* Foreign DoH server */
	doh_server_t frndoh;

} channel_chndoh_t;

typedef struct channel_req_t {
	uint16_t req_id;
	uint16_t id;
	ns_flags_t flags;
	ns_qr_t qr;
	channel_query_cb callback;
	void* cb_state;
	dlitem_t entry;
	struct rbnode_t rbn;
	channel_chndoh_t* ctx;
	ns_msg_t** results;
	int result_num;
	int wait_num;
	int untrust;
	unsigned long start_time;
} channel_req_t;

#define is_auto_relolve(_s) \
	((_s)->channel == CH_DOH && \
	 (_s)->auto_resolve_host && \
	 (_s)->addr_expire < time(NULL))

static int doh_query(channel_req_t* rq);

static uint16_t new_req_id(channel_chndoh_t* ctx)
{
	uint16_t newid;

	do {
		newid = (uint16_t)(rand() % 0x7FFF);
	} while (newid == 0 || rbtree_lookup(&ctx->reqdic, &newid));

	return newid;
}

static channel_req_t* myreq_new(
	channel_chndoh_t *ctx,
	const ns_msg_t* msg,
	channel_query_cb callback, void* cb_state)
{
	channel_req_t* req;

	req = (channel_req_t*)malloc(sizeof(channel_req_t));
	if (!req) {
		loge("myreq_new() error: alloc\n");
		return NULL;
	}

	memset(req, 0, sizeof(channel_req_t));

	req->req_id = new_req_id(ctx);
	req->id = msg->id;
	req->flags = msg->flags;
	req->qr = msg->qrs[0];
	req->qr.qname = strdup(msg->qrs[0].qname);
	req->callback = callback;
	req->cb_state = cb_state;
	req->rbn.key = &req->req_id;
	req->ctx = ctx;
	req->start_time = OS_GetTickCount();

	return req;
}

static void myreq_destroy(channel_req_t* req)
{
	int i;
	ns_msg_t* msg;
	for (i = 0; i < req->result_num; i++) {
		msg = req->results[i];
		if (msg) {
			ns_msg_free(msg);
			free(msg);
		}
	}
	free(req->results);
	free(req->qr.qname);
	free(req);
}

static void destroy(channel_t* ctx)
{
	channel_chndoh_t* c = (channel_chndoh_t*)ctx;
	dlitem_t* cur, * nxt;
	channel_req_t* req;

	dllist_foreach(&c->reqs, cur, nxt,
		channel_req_t, req, entry) {
		dllist_remove(&req->entry);
		if (req->callback)
			req->callback(ctx, -1, NULL, FALSE, FALSE, req->cb_state);
		myreq_destroy(req);
	}

	free(c->chndoh.host);
	free(c->chndoh.path);
	free(c->chndoh.net.name);
	free(c->chndoh.net6.name);
	if (c->chndoh.channel == CH_DOH && c->chndoh.http) {
		http_destroy(c->chndoh.http);
		c->chndoh.http = NULL;
	}
	else if (c->chndoh.chctx) {
		c->chndoh.chctx->destroy(c->chndoh.chctx);
		c->chndoh.chctx = NULL;
	}

	free(c->frndoh.host);
	free(c->frndoh.path);
	free(c->frndoh.net.name);
	free(c->frndoh.net6.name);
	if (c->frndoh.channel == CH_DOH && c->frndoh.http) {
		http_destroy(c->frndoh.http);
		c->frndoh.http = NULL;
	}
	else if (c->frndoh.chctx) {
		c->frndoh.chctx->destroy(c->frndoh.chctx);
		c->frndoh.chctx = NULL;
	}

	free(c);
}

static int query_doh_addr_cb(channel_t* ctx,
	int status,
	ns_msg_t* result,
	int fromcache,
	int trust,
	void* state)
{
	channel_chndoh_t* c = (channel_chndoh_t*)ctx;
	doh_server_t* doh = (doh_server_t*)state;
	const char* key;
	int i, rrcount;
	ns_rr_t* rr;
	uint16_t port;

	/* ignore failed result */
	if (status || !result || result->qdcount < 1) {
		if (doh->addr_expire < time(NULL) + 1 * 60 * 60) {
			doh->addr_expire += 60;
		}
		return 0;
	}

	key = msg_key(result);

	logd("new DoH server's IP: %s - %s\n",
		key, msg_answers(result));
	
	doh->addr_expire = time(NULL) + ns_get_ttl(result);

	if (doh->addr.addr.ss_family == AF_INET) {
		port = ((struct sockaddr_in*)&doh->addr.addr)->sin_port;
	}
	else {
		port = ((struct sockaddr_in6*)&doh->addr.addr)->sin6_port;
	}

	rrcount = result->ancount + result->nscount;
	for (i = 0; i < rrcount; i++) {
		rr = result->rrs + i;
		if (rr->type == NS_QTYPE_A) {
			struct in_addr* in = (struct in_addr*)rr->rdata;
			struct sockaddr_in* addr = (struct sockaddr_in*)&doh->addr.addr;
			memset(&doh->addr, 0, sizeof(sockaddr_t));
			doh->addr.addrlen = sizeof(struct sockaddr_in);
			addr->sin_family = AF_INET;
			addr->sin_port = port;
			memcpy(&addr->sin_addr, in, sizeof(struct in_addr));
			break;
		}
		else if (rr->type == NS_QTYPE_AAAA) {
			struct in6_addr* in6 = (struct in6_addr*)rr->rdata;
			struct sockaddr_in6* addr = (struct sockaddr_in6*)&doh->addr.addr;
			memset(&doh->addr, 0, sizeof(sockaddr_t));
			doh->addr.addrlen = sizeof(struct sockaddr_in6);
			addr->sin6_family = AF_INET;
			addr->sin6_port = port;
			memcpy(&addr->sin6_addr, in6, sizeof(struct in6_addr));
			break;
		}
	}

	if (result && !fromcache) {
		ns_msg_free(result);
		free(result);
	}
	return 0;
}

static void query_doh_addr(channel_chndoh_t* c, doh_server_t* doh)
{
	channel_req_t* req;
	ns_msg_t msg;

	doh->addr_expire = time(NULL) + 60;

	init_ns_msg(&msg);

	msg.id = 0;
	msg.flags.bits.aa = 1;
	msg.flags.bits.ra = 1;
	msg.qdcount = 1;
	msg.qrs = (ns_qr_t*)malloc(sizeof(ns_qr_t));
	if (!msg.qrs) {
		return;
	}

	msg.qrs->qclass = NS_QCLASS_IN;
	msg.qrs->qtype = NS_QTYPE_A;
	msg.qrs->qname = (char*)malloc(strlen(doh->host) + 2);
	strcpy(msg.qrs->qname, doh->host);
	strcat(msg.qrs->qname, ".");

	req = myreq_new(c, &msg, query_doh_addr_cb, doh);

	ns_msg_free(&msg);

	if (!req) {
		return;
	}

	dllist_add(&c->reqs, &req->entry);
	rbtree_insert(&c->reqdic, &req->rbn);
	c->req_count++;

	if (doh_query(req)) {
		loge("query_doh_addr() failed\n");
		dllist_remove(&req->entry);
		rbtree_remove(&c->reqdic, &req->rbn);
		c->req_count--;
		myreq_destroy(req);
		return;
	}
}

static sock_t fdset(channel_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	channel_chndoh_t* c = (channel_chndoh_t*)ctx;
	sock_t maxfd = 0, fd;

	if (c->chndoh.channel == CH_DOH) {
		if (c->chndoh.http) {
			fd = http_fdset(c->chndoh.http, readset, writeset, errorset);
			if (fd < 0) return -1;
			maxfd = MAX(maxfd, fd);
		}
	}
	else if (c->chndoh.chctx) {
		fd = c->chndoh.chctx->fdset(c->chndoh.chctx, readset, writeset, errorset);
		if (fd < 0) return -1;
		maxfd = MAX(maxfd, fd);
	}

	if (c->frndoh.channel == CH_DOH) {
		if (c->frndoh.http) {
			fd = http_fdset(c->frndoh.http, readset, writeset, errorset);
			if (fd < 0) return -1;
			maxfd = MAX(maxfd, fd);
		}
	}
	else if (c->frndoh.chctx) {
		fd = c->frndoh.chctx->fdset(c->frndoh.chctx, readset, writeset, errorset);
		if (fd < 0) return -1;
		maxfd = MAX(maxfd, fd);
	}

	return maxfd;
}

static int step(channel_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	channel_chndoh_t* c = (channel_chndoh_t*)ctx;
	int r;

	if (is_auto_relolve(&c->chndoh)) {
		query_doh_addr(c, &c->chndoh);
	}

	if (is_auto_relolve(&c->frndoh)) {
		query_doh_addr(c, &c->frndoh);
	}

	if (c->chndoh.channel == CH_DOH) {
		if (c->chndoh.http) {
			http_step(c->chndoh.http, readset, writeset, errorset);
		}
	}
	else if (c->chndoh.chctx) {
		r = c->chndoh.chctx->step(c->chndoh.chctx, readset, writeset, errorset);
		if (r) return -1;
	}

	if (c->frndoh.channel == CH_DOH) {
		if (c->frndoh.http) {
			http_step(c->frndoh.http, readset, writeset, errorset);
		}
	}
	else if (c->frndoh.chctx) {
		r = c->frndoh.chctx->step(c->frndoh.chctx, readset, writeset, errorset);
		if (r) return -1;
	}

	return 0;
}

static int build_request_nsmsg(ns_msg_t* msg, channel_req_t* req)
{
	init_ns_msg(msg);

	msg->id = 0;
	msg->flags = req->flags;
	msg->qdcount = 1;
	msg->qrs = ns_qr_clone(&req->qr, 1);

	return 0;
}

static int get_rr_flags(channel_chndoh_t* ctx, ns_rr_t* rr, int index)
{
	if (rr->type == NS_QTYPE_A) {
		struct in_addr* addr = (struct in_addr*)rr->rdata;
		int flags = 0;
		/* Only the first IP needs to detect the blacklist */
		if (index == 0 && chnroute_test4(ctx->blacklist, addr)) {
			flags |= FLG_BLACKLIST;
		}
		if (chnroute_test4(ctx->chnr, addr)) {
			flags |= (FLG_A | FLG_A_CHN);
		}
		else {
			flags |= (FLG_A | FLG_A_FRN);
		}
		return flags;
	}
	else if (rr->type == NS_QTYPE_AAAA) {
		struct in6_addr* addr = (struct in6_addr*)rr->rdata;
		int flags = 0;
		/* Only the first IP needs to detect the blacklist */
		if (index == 0 && chnroute_test6(ctx->blacklist, addr)) {
			flags |= FLG_BLACKLIST;
		}
		if (chnroute_test6(ctx->chnr, addr)) {
			flags |= (FLG_AAAA | FLG_AAAA_CHN);
		}
		else {
			flags |= (FLG_AAAA | FLG_AAAA_FRN);
		}
		return flags;
	}
	else if (rr->type == NS_QTYPE_PTR) {
		return FLG_PTR;
	}
	else if (rr->type == NS_QTYPE_OPT) {
		ns_opt_t* ecsopt = ns_optrr_find_ecs(rr);
		ns_ecs_t ecs = { 0 };
		if (ecsopt && ns_parse_ect(&ecs, ecsopt->data, ecsopt->length) && ecs.family) {
			if (ecs.family == ADDR_FAMILY_NUM_IP) {
				struct in_addr* addr = (struct in_addr*)ecs.subnet;
				if (chnroute_test4(ctx->chnr, addr)) {
					return (FLG_OPT | FLG_ECS | FLG_ECS_CHN);
				}
				else {
					return (FLG_OPT | FLG_ECS | FLG_ECS_FRN);
				}
			}
			else if (ecs.family == ADDR_FAMILY_NUM_IP6) {
				struct in6_addr* addr = (struct in6_addr*)ecs.subnet;
				if (chnroute_test6(ctx->chnr, addr)) {
					return (FLG_OPT | FLG_ECS | FLG_ECS_CHN);
				}
				else {
					return (FLG_OPT | FLG_ECS | FLG_ECS_FRN);
				}
			}
		}
		return FLG_OPT;
	}
	return FLG_NONE;
}

static int get_nsmsg_flags(channel_chndoh_t* ctx, ns_msg_t* msg)
{
	int i, rrcount, flags = 0;
	ns_rr_t* rr;

	rrcount = msg->ancount + msg->nscount;
	for (i = 0; i < rrcount; i++) {
		rr = msg->rrs + i;
		flags |= get_rr_flags(ctx, rr, i);
	}

	rrcount = ns_rrcount(msg);
	for (; i < rrcount; i++) {
		rr = msg->rrs + i;
		flags |= get_rr_flags(ctx, rr, i);
	}

	return flags;
}

static void print_all_answers(channel_req_t* rq, ns_msg_t* best)
{
	channel_chndoh_t* c = rq->ctx;
	int i, flags;
	ns_msg_t* msg;
	logd("All %d answers: - %s\n", rq->result_num, qr_key(&rq->qr));
	for (i = 0; i < rq->result_num; i++) {
		msg = rq->results[i];
		flags = get_nsmsg_flags(c, msg);
		logd("(%d):%s%s%s%s%s%s%s%s%s%s%s\n",
			i + 1,
			msg == best             ? " BEST"         : "",
			(flags & FLG_A)         ? " FLG_A"        : "",
			(flags & FLG_A_CHN)     ? " FLG_A_CHN"    : "",
			(flags & FLG_A_FRN)     ? " FLG_A_FRN"    : "",
			(flags & FLG_AAAA)      ? " FLG_AAAA"     : "",
			(flags & FLG_AAAA_CHN)  ? " FLG_AAAA_CHN" : "",
			(flags & FLG_AAAA_FRN)  ? " FLG_AAAA_FRN" : "",
			(flags & FLG_ECS)       ? " FLG_ECS"      : "",
			(flags & FLG_ECS_CHN)   ? " FLG_ECS_CHN"  : "",
			(flags & FLG_ECS_FRN)   ? " FLG_ECS_FRN"  : "",
			(flags & FLG_BLACKLIST) ? " FLG_BLACKLIST" : "");
		ns_print(msg);
	}
}

static ns_msg_t* choose_best_nsmsg(channel_req_t* rq)
{
	channel_chndoh_t* c = rq->ctx;
	ns_msg_t* best = NULL;

	if (rq->result_num == 0) {
		best = NULL;
	}
	else if (rq->result_num == 1) {
		best = rq->results[0];
	}
	else if (!c->chnr) {
		best = rq->results[0];
	}
	else {
		int i;
		ns_msg_t* msg, *frn_result = NULL;
		int flags, have_ip, chn_doh, chn_ip, black;

		for (i = 0; i < rq->result_num; i++) {
			msg = rq->results[i];
			flags = get_nsmsg_flags(c, msg);

			black = flags & FLG_BLACKLIST;                /* In blacklist? */
			have_ip = flags & (FLG_A | FLG_AAAA);         /* Have IP? */
			chn_doh = msg->id == 0;                       /* From China DoH? */
			chn_ip = flags & (FLG_A_CHN | FLG_AAAA_CHN);  /* Result is China? */

			if (!chn_doh) {
				frn_result = msg;
			}

			if (black) {
				continue;
			}

			if (have_ip && chn_doh && chn_ip) {
				best = msg;
				rq->untrust = FALSE;
				break;
			}
			else if (!chn_doh) {
				best = msg;
			}
		}

		if (!best) {
			if (frn_result) {
				/* The result which from foreign server is preferred */
				best = frn_result;
			}
			else {
				/* The last one result is preferred */
				best = rq->results[rq->result_num - 1];
			}
		}
	}

	if (loglevel > LOG_DEBUG) {
		print_all_answers(rq, best);
	}

	return best;
}

static int is_best(channel_chndoh_t* c, ns_msg_t* msg)
{
	int flags, have_ip, chn_doh, chn_ip, black;

	flags = get_nsmsg_flags(c, msg);

	black = flags & FLG_BLACKLIST;                /* In blacklist? */
	have_ip = flags & (FLG_A | FLG_AAAA);         /* Have IP? */
	chn_doh = msg->id == 0;                       /* From China DoH? */
	chn_ip = flags & (FLG_A_CHN | FLG_AAAA_CHN);  /* Result is China? */

	if (black) {
		return FALSE;
	}

	if (have_ip && chn_doh && chn_ip) {
		return TRUE;
	}

	return FALSE;
}

static void detach_result(channel_req_t* rq, ns_msg_t* result)
{
	ns_msg_t* msg;
	int i;
	for (i = 0; i < rq->result_num; i++) {
		msg = rq->results[i];
		if (msg == result) {
			rq->results[i] = NULL;
		}
	}
}

static int query_cb(channel_t* ctx,
	int status,
	ns_msg_t* result,
	int fromcache,
	int trust,
	void* state)
{
	channel_req_t* rq = (channel_req_t*)state;
	channel_chndoh_t* c = rq->ctx;

	if (status == 0 && result) {

		if (ctx != NULL) {
			doh_server_t* doh = (doh_server_t*)ctx->data;

			result->id = ctx == c->chndoh.chctx ? 0 : 1;

			logd("%d. query %s success: %s - %s (%lu ms)\n",
				2 - rq->wait_num,
				rq->qr.qname,
				msg_answers(result),
				get_sockaddrname(&doh->addr),
				OS_GetTickCount() - rq->start_time);
		}

		if (!rq->results) {
			rq->results = (ns_msg_t**)malloc(sizeof(ns_msg_t*) * rq->wait_num);
			if (!rq->results) {
				loge("query_cb() error: alloc\n");
				ns_msg_free(result);
				free(result);
				result = NULL;
				goto exit;
			}
			memset(rq->results, 0, sizeof(ns_msg_t*) * rq->wait_num);
		}

		rq->results[rq->result_num++] = result;

		if (rq->callback && is_best(c, result)) {
			/* Detach the result, so can keep the result in memory,
			after myreq_destroy() called. */
			rq->results[rq->result_num - 1] = NULL;
			rq->untrust = FALSE;

			/* callback */
			rq->callback((channel_t*)c, 0, result, FALSE, TRUE, rq->cb_state);
			rq->callback = NULL;
		}
	}
	else {
		rq->untrust = TRUE;
		if (ctx != NULL) {
			doh_server_t* doh = (doh_server_t*)ctx->data;

			loge("%d. query %s failed - %s (%lu ms)\n",
				2 - rq->wait_num,
				rq->qr.qname,
				get_sockaddrname(&doh->addr),
				OS_GetTickCount() - rq->start_time);
		}
	}

exit:
	rq->wait_num--;

	if (rq->wait_num == 0) {

		dllist_remove(&rq->entry);
		rbtree_remove(&c->reqdic, &rq->rbn);
		c->req_count--;

		if (rq->callback) {
			result = choose_best_nsmsg(rq);
			rq->callback((channel_t*)c, result ? 0 : -1, result, FALSE, !rq->untrust, rq->cb_state);
		}
		else {
			result = NULL;
		}

		if (result) {
			/* Detach the result, so can keep the result in memory,
			after myreq_destroy() called. */
			detach_result(rq, result);
		}

		myreq_destroy(rq);
	}

	return 0;
}

static void http_cb(
	int status,
	http_request_t* request,
	http_response_t* response,
	void* state)
{
	channel_req_t* rq = (channel_req_t*)state;
	channel_chndoh_t* c = rq->ctx;
	doh_server_t* doh = NULL;
	ns_msg_t* result = NULL;
	char* data;
	int datalen;
	int http_status = 0;
	const char* status_text = NULL;

	doh = (doh_server_t*)http_request_get_state(request);

	if (status == HTTP_OK &&
		(http_status = http_response_get_status_code(response, &status_text)) == 200) {
		result = (ns_msg_t*)malloc(sizeof(ns_msg_t));
		if (!result) {
			loge("http_cb() error: alloc\n");
			goto exit;
		}
		
		if (init_ns_msg(result)) {
			loge("http_cb() error: init_ns_msg() error\n");
			free(result);
			result = NULL;
			goto exit;
		}

		data = http_response_get_data(response, &datalen);
		if (ns_parse(result, (const uint8_t*)data, datalen)) {
			loge("http_cb() error: ns_parse() error\n");
			ns_msg_free(result);
			free(result);
			result = NULL;
			goto exit;
		}

		result->id = doh == &c->chndoh ? 0 : 1;

		logd("%d. query %s success: %s - %s (%lu ms)\n",
			2 - rq->wait_num,
			rq->qr.qname,
			msg_answers(result),
			doh->host,
			OS_GetTickCount() - rq->start_time);
	}
	else {
		loge("%d. query %s failed: HTTP %d %s - %s (%lu ms)\n",
			2 - rq->wait_num,
			rq->qr.qname,
			http_status,
			status_text,
			http_request_get_host(request),
			OS_GetTickCount() - rq->start_time);
	}

exit:
	free(http_request_get_data(request, &datalen));
	http_request_destroy(request);
	http_response_destroy(response);

	query_cb(NULL, result ? 0 : -1, result, FALSE, !!result, rq);
}

static http_request_t* doh_build_post_request(channel_req_t* rq, doh_server_t* doh, ns_msg_t* msg)
{
	channel_chndoh_t* c = rq->ctx;
	http_request_t* req = NULL;
	int r, len;
	stream_t s = STREAM_INIT();

	if ((len = ns_serialize(&s, msg, 0)) <= 0) {
		loge("doh_build_post_request() error: ns_serialize() error\n");
		stream_free(&s);
		return NULL;
	}

	req = http_request_create("POST", doh->path, doh->host, doh->keep_alive);
	if (!req) {
		loge("doh_build_post_request() error: http_request_create() error\n");
		stream_free(&s);
		return NULL;
	}

	r = http_request_set_header(req, "Content-Type", "application/dns-message");
	if (r) {
		loge("doh_build_post_request() error: http_request_set_header() error\n");
		stream_free(&s);
		http_request_destroy(req);
		return NULL;
	}

	r = http_request_set_header(req, "Accept", "*/*");
	if (r) {
		loge("doh_build_post_request() error: http_request_set_header() error\n");
		stream_free(&s);
		http_request_destroy(req);
		return NULL;
	}

	http_request_set_data(req, s.array, s.size);

	http_request_set_state(req, doh);

	http_request_set_tag(req, rq->qr.qname);

	return req;
}

static http_request_t* doh_build_get_request(channel_req_t* rq, doh_server_t* doh, ns_msg_t* msg)
{
	channel_chndoh_t* c = rq->ctx;
	http_request_t* req = NULL;
	int r, len;
	stream_t s = STREAM_INIT();
	char* dns;
	int dns_len;

	if ((len = ns_serialize(&s, msg, 0)) <= 0) {
		loge("doh_build_get_request() error: ns_serialize() error\n");
		stream_free(&s);
		return NULL;
	}

	dns = base64url_encode(s.array, s.size, &dns_len, FALSE);
	if (!dns) {
		loge("doh_build_get_request() error: base64_encode() error\n");
		stream_free(&s);
		return NULL;
	}

	stream_reset(&s);

	if (stream_appendf(&s,
		"%s?dns=%s",
		doh->path,
		dns) == -1) {
		loge("doh_build_get_request() error: stream_appendf()\n");
		stream_free(&s);
		return NULL;
	}

	free(dns);

	req = http_request_create("GET", s.array, doh->host, doh->keep_alive);
	if (!req) {
		loge("doh_build_get_request() error: http_request_create() error\n");
		stream_free(&s);
		return NULL;
	}

	r = http_request_set_header(req, "Content-Type", "application/dns-message");
	if (r) {
		loge("doh_build_get_request() error: http_request_set_header() error\n");
		stream_free(&s);
		http_request_destroy(req);
		return NULL;
	}

	r = http_request_set_header(req, "Accept", "*/*");
	if (r) {
		loge("doh_build_get_request() error: http_request_set_header() error\n");
		stream_free(&s);
		http_request_destroy(req);
		return NULL;
	}

	http_request_set_data(req, s.array, s.size);

	http_request_set_state(req, doh);

	http_request_set_tag(req, rq->qr.qname);

	return req;
}

static int doh_channel_query(channel_req_t* rq, doh_server_t* doh,
	ns_msg_t *msg, int use_proxy, subnet_t* subnet)
{
	channel_chndoh_t* c = rq->ctx;
	http_request_t* req;
	int r;

	if (subnet) {
		ns_rr_t* rr;
		rr = ns_find_opt_rr(msg);
		if (rr == NULL) {
			rr = ns_add_optrr(msg);
			if (rr == NULL) {
				loge("doh_channel_query(): Can't add option record to ns_msg_t\n");
				return -1;
			}
		}

		rr->cls = NS_PAYLOAD_SIZE; /* reset edns payload size */

		if (ns_optrr_set_ecs(rr, (struct sockaddr*)&subnet->addr, subnet->mask, 0) != 0) {
			loge("doh_channel_query(): Can't add ecs option\n");
			return -1;
		}
	}

	req = doh->post
		? doh_build_post_request(rq, doh, msg)
		: doh_build_get_request(rq, doh, msg);

	if (!req) {
		loge("doh_channel_query() error: %s error\n",
			doh->post
			? "doh_build_post_request()"
			: "doh_build_get_request()");
		return -1;
	}

	r = http_send(doh->http, &doh->addr, use_proxy, req, doh->timeout, http_cb, rq);
	if (r) {
		loge("doh_channel_query() error: http_send() error\n");
		free(http_request_get_data(req, NULL));
		http_request_destroy(req);
		return -1;
	}

	return r;
}

static int doh_emit_query(channel_req_t* rq, doh_server_t *doh)
{
	channel_chndoh_t* c = rq->ctx;
	subnet_t* subnet = NULL;
	int r;
	ns_msg_t msg;

	if (doh->ecs) {
		if (rq->qr.qtype == NS_QTYPE_A) {
			if (doh->net.is_set) {
				subnet = &doh->net;
			}
		}
		else if (rq->qr.qtype == NS_QTYPE_AAAA) {
			if (doh->net6.is_set) {
				subnet = &doh->net6;
			}
		}
	}

	init_ns_msg(&msg);

	r = build_request_nsmsg(&msg, rq);
	if (r) {
		loge("doh_emit_query() error: build_request_nsmsg() error\n");
		return -1;
	}

	if (doh->query) {
		r = doh->query(doh->chctx, &msg, doh->use_proxy, subnet, query_cb, rq);
	}
	else {
		r = doh_channel_query(rq, doh, &msg, doh->use_proxy, subnet);
	}

	ns_msg_free(&msg);

	return r;
}

static int doh_query(channel_req_t* rq)
{
	channel_chndoh_t* c = rq->ctx;
	int r = 0;

	if (c->frndoh.channel != CH_NONE) {
		r = doh_emit_query(rq, &c->frndoh);
		if (r) {
			loge("doh_query() error: doh_emit_query() error\n");
			return -1;
		}
		rq->wait_num++;
	}

	if (c->chndoh.channel != CH_NONE) {
		r = doh_emit_query(rq, &c->chndoh);
		if (r) {
			loge("doh_query() error: doh_emit_query() error\n");
			return -1;
		}
		rq->wait_num++;
	}

	if (rq->wait_num == 0) {
		loge("doh_query() error: no DoH server\n");
		return -1;
	}

	return r;
}

static int query(channel_t* ctx,
	const ns_msg_t* msg,
	channel_query_cb callback, void* state)
{
	channel_chndoh_t* c = (channel_chndoh_t*)ctx;
	channel_req_t* req;

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

static int parse_subnet(subnet_t* subnet, const char* s)
{
	if (ns_ecs_parse_subnet((struct sockaddr*)(&subnet->addr),
		&subnet->mask, s) != 0) {
		loge("Invalid subnet %s\n", s);
		return -1;
	}
	free(subnet->name);
	subnet->name = strdup(s);
	subnet->is_set = 1;
	return 0;
}

static int parse_args(channel_chndoh_t *ctx, const char* args)
{
	char* cpy;
	char* p;
	char* v;
	doh_server_t* doh;

	if (!args) return -1;

	cpy = strdup(args);

	for (p = strtok(cpy, "&");
		p && *p;
		p = strtok(NULL, "&")) {

		v = strchr(p, '=');
		if (!v) continue;

		*v = '\0';
		v++;

		if (strcmp(p, "chndoh.addr") == 0 || strcmp(p, "frndoh.addr") == 0) {
			doh = strcmp(p, "chndoh.addr") == 0 ? &ctx->chndoh : &ctx->frndoh;
			p = v;
			if (*p == '[') {
				p++;
				v = strchr(p, ']');
				if (v) {
					*v = '\0';
					v++;
					if (*v == ':') {
						v++;
					}
				}
			}
			else {
				v = strchr(p, ':');
				if (v) {
					*v = '\0';
					v++;
				}
			}

			if (!try_parse_as_ip( &doh->addr, p,
				(v && (*v)) 
					? v 
					: (doh->channel == CH_DOH ? "443" : "53")) ) {
				loge("parse address failed: %s:%s\n",
						p,
						(v && (*v)) 
							? v 
							: (doh->channel == CH_DOH ? "443" : "53")
					);
				free(cpy);
				return -1;
			}
		}
		else if (strcmp(p, "chndoh.host") == 0 || strcmp(p, "frndoh.host") == 0) {
			if (*v) {
				doh = strcmp(p, "chndoh.host") == 0 ? &ctx->chndoh : &ctx->frndoh;
				doh->host = strdup(v);
			}
		}
		else if (strcmp(p, "chndoh.path") == 0 || strcmp(p, "frndoh.path") == 0) {
			doh = strcmp(p, "chndoh.path") == 0 ? &ctx->chndoh : &ctx->frndoh;
			doh->path = strdup(v);
		}
		else if (strcmp(p, "chndoh.keep-alive") == 0 || strcmp(p, "frndoh.keep-alive") == 0) {
			doh = strcmp(p, "chndoh.keep-alive") == 0 ? &ctx->chndoh : &ctx->frndoh;
			doh->keep_alive = atoi(v);
		}
		else if (strcmp(p, "chndoh.post") == 0 || strcmp(p, "frndoh.post") == 0) {
			doh = strcmp(p, "chndoh.post") == 0 ? &ctx->chndoh : &ctx->frndoh;
			doh->post = strcmp(v, "0");
		}
		else if (strcmp(p, "chndoh.proxy") == 0 || strcmp(p, "frndoh.proxy") == 0) {
			doh = strcmp(p, "chndoh.proxy") == 0 ? &ctx->chndoh : &ctx->frndoh;
			doh->use_proxy = strcmp(v, "0");
		}
		else if (strcmp(p, "chndoh.ecs") == 0 || strcmp(p, "frndoh.ecs") == 0) {
			doh = strcmp(p, "chndoh.ecs") == 0 ? &ctx->chndoh : &ctx->frndoh;
			doh->ecs = strcmp(v, "0");
		}
		else if (strcmp(p, "chndoh.net") == 0 || strcmp(p, "frndoh.net") == 0) {
			doh = strcmp(p, "chndoh.net") == 0 ? &ctx->chndoh : &ctx->frndoh;
			if (v && *v && parse_subnet(&doh->net, v)) {
				loge("parse \"%s\" failed: %s\n", p, v);
				free(cpy);
				return -1;
			}
		}
		else if (strcmp(p, "chndoh.net6") == 0 || strcmp(p, "frndoh.net6") == 0) {
			doh = strcmp(p, "chndoh.net6") == 0 ? &ctx->chndoh : &ctx->frndoh;
			if (v && *v && parse_subnet(&doh->net6, v)) {
				loge("parse \"%s\" failed: %s\n", p, v);
				free(cpy);
				return -1;
			}
		}
		else if (strcmp(p, "chndoh.channel") == 0 || strcmp(p, "frndoh.channel") == 0) {
			doh = strcmp(p, "chndoh.channel") == 0 ? &ctx->chndoh : &ctx->frndoh;
			if (strcmp(v, "udp") == 0) doh->channel = CH_UDP;
			else if (strcmp(v, "tcp") == 0) doh->channel = CH_TCP;
			else if (strcmp(v, "doh") == 0) doh->channel = CH_DOH;
			else {
				loge("parse \"%s=%s\" failed: Unknown channel\n", p, v);
				free(cpy);
				return -1;
			}
		}
		else if (strcmp(p, "chndoh.resolve") == 0 || strcmp(p, "frndoh.resolve") == 0) {
			doh = strcmp(p, "chndoh.resolve") == 0 ? &ctx->chndoh : &ctx->frndoh;
			doh->auto_resolve_host = strcmp(v, "0");
		}
		else if (strcmp(p, "chndoh.timeout") == 0 || strcmp(p, "frndoh.timeout") == 0) {
			doh = strcmp(p, "chndoh.timeout") == 0 ? &ctx->chndoh : &ctx->frndoh;
			doh->timeout = atoi(v);
		}
		else {
			logw("unknown argument: %s=%s\n", p, v);
		}
	}

	free(cpy);
	return 0;
}

static int create_upstream_chctx(doh_server_t* doh, channel_chndoh_t* c)
{
	if (doh->channel == CH_UDP) {
		char args[2048];
		int n;
		n = snprintf(args, sizeof(args),
			"upstream=%s&proxy=%d&timeout=%d",
			get_sockaddrname(&doh->addr),
			doh->use_proxy,
			doh->timeout);
		if (n <= 0 || n >= sizeof(args))
			return -1;
		doh->query = channel_udp_query;
		return channel_udp_create(&doh->chctx,
			"udp", args,
			c->conf,
			c->proxies,
			c->proxy_num,
			c->chnr,
			c->blacklist,
			doh);
	}
	else if (doh->channel == CH_TCP) {
		char args[2048];
		int n;
		n = snprintf(args, sizeof(args),
			"upstream=%s&proxy=%d&timeout=%d",
			get_sockaddrname(&doh->addr),
			doh->use_proxy,
			doh->timeout);
		if (n <= 0 || n >= sizeof(args))
			return -1;
		doh->query = channel_tcp_query;
		return channel_tcp_create(&doh->chctx,
			"tcp", args,
			c->conf,
			c->proxies,
			c->proxy_num,
			c->chnr,
			c->blacklist,
			doh);
	}
	else if (doh->channel == CH_DOH) {
		doh->http = http_create(
			c->proxies,
			c->proxy_num,
			doh->keep_alive);
		if (!doh->http)
			return -1;
		return 0;
	}
	return -1;
}

static int check_doh_server(doh_server_t *doh)
{
	if (is_empty_sockaddr(&doh->addr)) {
		loge("check_doh_server() error: no \"addr\"\n");
		return -1;
	}
	if (doh->channel == CH_DOH) {
		if (!doh->host || !*doh->host) {
			loge("check_doh_server() error: no \"host\"\n");
			return -1;
		}
		if (!doh->path || !*doh->path) {
			loge("check_doh_server() error: no \"path\"\n");
			return -1;
		}
	}
	if (doh->timeout <= 0) {
		loge("check_doh_server() error: invalid \"timeout\"\n");
		return -1;
	}
	if (doh->keep_alive < 0) {
		loge("check_doh_server() error: invalid \"keep-alive\"\n");
		return -1;
	}

	/* Compatible with old configuration */
	if (doh->keep_alive == 1)
		doh->keep_alive = DEFAULT_HTTP_TIMEOUT;

	return 0;
}

static int check_ctx(channel_chndoh_t *ctx)
{
	if (ctx->chndoh.channel != CH_NONE) {
		if (check_doh_server(&ctx->chndoh))
			return -1;
	}
	if (ctx->frndoh.channel != CH_NONE) {
		if (check_doh_server(&ctx->frndoh))
			return -1;
	}
	return 0;
}

int channel_chndoh_create(
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
	channel_chndoh_t* ctx;

	ctx = (channel_chndoh_t*)malloc(sizeof(channel_chndoh_t));
	if (!ctx) {
		loge("channel_chndoh_create() error: alloc\n");
		return CHANNEL_ALLOC;
	}

	memset(ctx, 0, sizeof(channel_chndoh_t));

	ctx->name = name;
	ctx->conf = conf;
	ctx->proxies = proxies;
	ctx->proxy_num = proxy_num;
	ctx->chnr = chnr;
	ctx->blacklist = blacklist;
	ctx->data = data;

	ctx->chndoh.timeout = conf->timeout;
	ctx->frndoh.timeout = conf->timeout;
	ctx->chndoh.keep_alive = TRUE;
	ctx->frndoh.keep_alive = TRUE;
	ctx->chndoh.auto_resolve_host = TRUE;
	ctx->frndoh.auto_resolve_host = TRUE;

	if (parse_args(ctx, args)) {
		loge("channel_chndoh_create() error: parse_args() error\n");
		free(ctx);
		return CHANNEL_WRONG_ARG;
	}

	if (check_ctx(ctx)) {
		free(ctx);
		return CHANNEL_WRONG_ARG;
	}

	rbtree_init(&ctx->reqdic, rbcmp);
	dllist_init(&ctx->reqs);

	ctx->fdset = fdset;
	ctx->step = step;
	ctx->query = query;
	ctx->destroy = destroy;

	if (ctx->chndoh.channel != CH_NONE && create_upstream_chctx(&ctx->chndoh, ctx)) {
		loge("channel_chndoh_create() error: create_upstream_chctx(chndoh) error\n");
		destroy((channel_t*)ctx);
		return CHANNEL_ERROR;
	}

	if (ctx->frndoh.channel != CH_NONE && create_upstream_chctx(&ctx->frndoh, ctx)) {
		loge("channel_chndoh_create() error: create_upstream_chctx(frndoh) error\n");
		destroy((channel_t*)ctx);
		return CHANNEL_ERROR;
	}

	*pctx = (channel_t*)ctx;

	return CHANNEL_OK;
}
