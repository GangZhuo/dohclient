#include "channel_chndoh.h"
#include "../rbtree/rbtree.h"
#include "http.h"
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

typedef struct subnet_t {
	int is_set;
	char* name;
	struct sockaddr_storage addr;
	int mask;
} subnet_t;

typedef struct doh_server_t {
	time_t addr_expire;
	sockaddr_t addr;
	char* host;
	char* path;
} doh_server_t;

typedef struct channel_chndoh_t {
	CHANNEL_BASE(_M)
	dllist_t reqs;
	struct rbtree_t reqdic;
	int req_count;
	http_ctx_t* http;

	/* China DoH server */
	doh_server_t chndoh;

	/* Foreign DoH server */
	doh_server_t frndoh;

	/* Only for foreign DoH server */
	int use_proxy; 
	int ecs;
	subnet_t net;
	subnet_t net6;

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
} channel_req_t;

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
			req->callback(ctx, -1, NULL, FALSE, req->cb_state);
		myreq_destroy(req);
	}
	http_destroy(c->http);
	free(c->chndoh.host);
	free(c->chndoh.path);
	free(c->frndoh.host);
	free(c->frndoh.path);
	free(c->net.name);
	free(c->net6.name);
	free(c);
}

static int query_doh_addr_cb(channel_t* ctx,
	int status,
	ns_msg_t* result,
	int fromcache,
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

	logn("new DoH server's IP: %s - %s\n",
		key, msg_answers(result));
	
	doh->addr_expire = time(NULL) + result->rrs->ttl;

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
	return http_fdset(c->http, readset, writeset, errorset);
}

static int step(channel_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	channel_chndoh_t* c = (channel_chndoh_t*)ctx;
	if (c->chndoh.host && c->chndoh.addr_expire < time(NULL)) {
		query_doh_addr(c, &c->chndoh);
	}
	if (c->frndoh.host && c->frndoh.addr_expire < time(NULL)) {
		query_doh_addr(c, &c->frndoh);
	}
	return http_step(c->http, readset, writeset, errorset);
}

static int build_request_nsmsg(ns_msg_t* msg, channel_req_t* req)
{
	init_ns_msg(msg);

	msg->id = req->req_id;
	msg->flags = req->flags;
	msg->qdcount = 1;
	msg->qrs = ns_qr_clone(&req->qr, 1);

	return 0;
}

static int get_rr_flags(channel_chndoh_t* ctx, ns_rr_t* rr)
{
	if (rr->type == NS_QTYPE_A) {
		struct in_addr* addr = (struct in_addr*)rr->rdata;
		if (chnroute_test4(ctx->chnr, addr)) {
			return (FLG_A | FLG_A_CHN);
		}
		else {
			return (FLG_A | FLG_A_FRN);
		}
	}
	else if (rr->type == NS_QTYPE_AAAA) {
		struct in6_addr* addr = (struct in6_addr*)rr->rdata;
		if (chnroute_test6(ctx->chnr, addr)) {
			return (FLG_AAAA | FLG_AAAA_CHN);
		}
		else {
			return (FLG_AAAA | FLG_AAAA_FRN);
		}
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
		flags |= get_rr_flags(ctx, rr);
	}

	rrcount = ns_rrcount(msg);
	for (; i < rrcount; i++) {
		rr = msg->rrs + i;
		flags |= get_rr_flags(ctx, rr);
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
		logd("(%d):%s%s%s%s%s%s%s%s%s%s\n",
			i + 1,
			msg == best            ? " BEST"         : "",
			(flags & FLG_A)        ? " FLG_A"        : "",
			(flags & FLG_A_CHN)    ? " FLG_A_CHN"    : "",
			(flags & FLG_A_FRN)    ? " FLG_A_FRN"    : "",
			(flags & FLG_AAAA)     ? " FLG_AAAA"     : "",
			(flags & FLG_AAAA_CHN) ? " FLG_AAAA_CHN" : "",
			(flags & FLG_AAAA_FRN) ? " FLG_AAAA_FRN" : "",
			(flags & FLG_ECS)      ? " FLG_ECS"      : "",
			(flags & FLG_ECS_CHN)  ? " FLG_ECS_CHN"  : "",
			(flags & FLG_ECS_FRN)  ? " FLG_ECS_FRN"  : "");
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
		ns_msg_t* msg;
		int flags, have_ip, chn_doh, chn_ip;

		for (i = 0; i < rq->result_num; i++) {
			msg = rq->results[i];
			flags = get_nsmsg_flags(c, msg);

			have_ip = flags & (FLG_A | FLG_AAAA);         /* Have IP? */
			chn_doh = msg->id == 0;                       /* From China DoH? */
			chn_ip = flags & (FLG_A_CHN | FLG_AAAA_CHN);  /* Result is China? */

			if (have_ip && chn_doh && chn_ip) {
				best = msg;
				break;
			}
			else if (!chn_doh) {
				best = msg;
			}
		}

		if (!best) {
			best = rq->results[0];
		}
	}

	if (loglevel > LOG_DEBUG) {
		print_all_answers(rq, best);
	}

	return best;
}

static int is_best(channel_chndoh_t* c, ns_msg_t* msg)
{
	int flags, have_ip, chn_doh, chn_ip;

	flags = get_nsmsg_flags(c, msg);

	have_ip = flags & (FLG_A | FLG_AAAA);         /* Have IP? */
	chn_doh = msg->id == 0;                       /* From China DoH? */
	chn_ip = flags & (FLG_A_CHN | FLG_AAAA_CHN);  /* Result is China? */

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

	doh = (doh_server_t*)http_request_get_state(request);

	if (status == HTTP_OK && http_response_get_status_code(response, NULL) == 200) {
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

		if (!rq->results) {
			rq->results = (ns_msg_t**)malloc(sizeof(ns_msg_t*) * rq->wait_num);
			if (!rq->results) {
				loge("http_cb() error: alloc\n");
				ns_msg_free(result);
				free(result);
				result = NULL;
				goto exit;
			}
			memset(rq->results, 0, sizeof(ns_msg_t*) * rq->wait_num);
		}
		rq->results[rq->result_num++] = result;
		result->id = doh == &c->chndoh ? 0 : 1;
		if (rq->callback && is_best(c, result)) {
			/* Detach the result, so can keep the result in memory,
			after myreq_destroy() called. */
			rq->results[rq->result_num - 1] = NULL;
			
			/* callback */
			rq->callback((channel_t*)c, 0, result, FALSE, rq->cb_state);
			rq->callback = NULL;
		}
	}
	else {
		loge("query %s failed\n", rq->qr.qname);
	}

exit:
	free(http_request_get_data(request, &datalen));
	http_request_destroy(request);
	http_response_destroy(response);

	rq->wait_num--;

	if (rq->wait_num == 0) {

		dllist_remove(&rq->entry);
		rbtree_remove(&c->reqdic, &rq->rbn);
		c->req_count--;

		if (rq->callback) {
			result = choose_best_nsmsg(rq);
			rq->callback((channel_t*)c, result ? 0 : -1, result, FALSE, rq->cb_state);
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
}

static http_request_t* doh_build_http_request(channel_req_t* rq, doh_server_t* doh, subnet_t* subnet)
{
	channel_chndoh_t* c = rq->ctx;
	http_request_t* req = NULL;
	ns_msg_t msg;
	int r, len;
	stream_t s = STREAM_INIT();

	init_ns_msg(&msg);

	r = build_request_nsmsg(&msg, rq);
	if (r) {
		loge("doh_build_http_request() error: build_request_nsmsg() error\n");
		return NULL;
	}

	if (subnet) {
		ns_rr_t* rr;
		rr = ns_find_opt_rr(&msg);
		if (rr == NULL) {
			rr = ns_add_optrr(&msg);
			if (rr == NULL) {
				loge("doh_build_http_request(): Can't add option record to ns_msg_t\n");
				ns_msg_free(&msg);
				return NULL;
			}
		}

		rr->cls = NS_PAYLOAD_SIZE; /* reset edns payload size */

		if (ns_optrr_set_ecs(rr, (struct sockaddr*)&subnet->addr, subnet->mask, 0) != 0) {
			loge("doh_build_http_request(): Can't add ecs option\n");
			ns_msg_free(&msg);
			return NULL;
		}
	}

	if ((len = ns_serialize(&s, &msg, 0)) <= 0) {
		loge("doh_build_http_request() error: ns_serialize() error\n");
		stream_free(&s);
		ns_msg_free(&msg);
		return NULL;
	}

	ns_msg_free(&msg);

	req = http_request_create("POST", doh->path, doh->host);
	if (!req) {
		loge("doh_build_http_request() error: http_request_create() error\n");
		stream_free(&s);
		return NULL;
	}

	r = http_request_set_header(req, "Content-Type", "application/dns-message");
	if (r) {
		loge("doh_build_http_request() error: http_request_set_header() error\n");
		stream_free(&s);
		http_request_destroy(req);
		return NULL;
	}

	r = http_request_set_header(req, "Pragma", "no-cache");
	if (r) {
		loge("doh_build_http_request() error: http_request_set_header() error\n");
		stream_free(&s);
		http_request_destroy(req);
		return NULL;
	}

	r = http_request_set_header(req, "Cache-Control", "no-cache");
	if (r) {
		loge("doh_build_http_request() error: http_request_set_header() error\n");
		stream_free(&s);
		http_request_destroy(req);
		return NULL;
	}

	r = http_request_set_header(req, "Accept", "*/*");
	if (r) {
		loge("doh_build_http_request() error: http_request_set_header() error\n");
		stream_free(&s);
		http_request_destroy(req);
		return NULL;
	}

	r = http_request_set_header(req, "Connection", "keep-alive");
	if (r) {
		loge("doh_build_http_request() error: http_request_set_header() error\n");
		stream_free(&s);
		http_request_destroy(req);
		return NULL;
	}

	http_request_set_data(req, s.array, s.size);

	http_request_set_state(req, doh);

	return req;
}

static int doh_http_query(channel_req_t* rq, doh_server_t *doh, int use_proxy, subnet_t* subnet)
{
	channel_chndoh_t* c = rq->ctx;
	http_request_t* req;
	int r;

	req = doh_build_http_request(rq, doh, subnet);
	if (!req) {
		loge("doh_http_query() error: doh_build_http_request() error\n");
		return -1;
	}

	r = http_send(c->http, &doh->addr, c->use_proxy, req, http_cb, rq);
	if (r) {
		loge("doh_http_query() error: http_send() error\n");
		free(http_request_get_data(req, NULL));
		http_request_destroy(req);
		return -1;
	}

	return r;
}

static int doh_query(channel_req_t* rq)
{
	channel_chndoh_t* c = rq->ctx;
	int r = 0;

	if (c->chndoh.host) {
		r = doh_http_query(rq, &c->chndoh, FALSE, NULL);
		if (r) {
			loge("doh_query() error: doh_http_query() error\n");
			return -1;
		}
		rq->wait_num++;
	}

	if (c->frndoh.host) {
		subnet_t* subnet = NULL;
		if (c->ecs) {
			if (rq->qr.qtype == NS_QTYPE_A) {
				if (c->net.is_set) {
					subnet = &c->net;
				}
			}
			else if (rq->qr.qtype == NS_QTYPE_AAAA) {
				if (c->net6.is_set) {
					subnet = &c->net6;
				}
			}
		}
		r = doh_http_query(rq, &c->frndoh, c->use_proxy, subnet);
		if (r) {
			loge("doh_query() error: doh_http_query() error\n");
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

            if (!try_parse_as_ip( &doh->addr, p, (v && (*v)) ? v : "443") ) {
                loge("parse address failed: %s:%s\n",
                        p,
                        (v && (*v)) ? v : "443"
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
        else if (strcmp(p, "proxy") == 0) {
            ctx->use_proxy = strcmp(v, "0");
        }
        else if (strcmp(p, "ecs") == 0) {
            ctx->ecs = strcmp(v, "0");
        }
        else if (strcmp(p, "net") == 0) {
            if (v && *v && parse_subnet(&ctx->net, v)) {
                loge("parse \"china-ip4\" failed: %s\n", v);
                free(cpy);
                return -1;
            }
        }
        else if (strcmp(p, "net6") == 0) {
            if (v && *v && parse_subnet(&ctx->net6, v)) {
                loge("parse \"china-ip6\" failed: %s\n", v);
                free(cpy);
                return -1;
            }
        }
        else {
            logw("unknown argument: %s=%s\n", p, v);
        }
    }

	free(cpy);
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
	void* data)
{
	channel_chndoh_t* ctx;

	ctx = (channel_chndoh_t*)malloc(sizeof(channel_chndoh_t));
	if (!ctx) {
		loge("channel_chndoh_create() error: alloc\n");
		return CHANNEL_ALLOC;
	}

	memset(ctx, 0, sizeof(channel_chndoh_t));

	if (parse_args(ctx, args)) {
		loge("channel_chndoh_create() error: parse_args() error\n");
		return CHANNEL_WRONG_ARG;
	}

	ctx->http = http_create(
		proxies,
		proxy_num,
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
