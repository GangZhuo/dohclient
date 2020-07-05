#include "channel_doh.h"
#include "../rbtree/rbtree.h"
#include "http.h"

#define _M
#define MAX_QUEUE_SIZE	30000

typedef struct subnet_t {
	int is_set;
	char* name;
	struct sockaddr_storage addr;
	int mask;
} subnet_t;

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
	int ecs;
	subnet_t china_net;
	subnet_t foreign_net;
	subnet_t china_net6;
	subnet_t foreign_net6;
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
	ns_msg_t** results;
	int result_num;
	int wait_num;
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
			req->callback(ctx, -1, NULL, FALSE, req->cb_state);
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

static int build_request_nsmsg(ns_msg_t* msg, myreq_t* req)
{
	init_ns_msg(msg);

	msg->id = req->req_id;
	msg->flags = req->flags;
	msg->qdcount = 1;
	msg->qrs = ns_qr_clone(&req->qr, 1);

	return 0;
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

		result_status = 0;

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
		if (rq->callback) {
			rq->callback((channel_t*)c, result_status, result, FALSE, rq->cb_state);
		}
		myreq_destroy(rq);
	}
}

static http_request_t* doh_build_http_request(myreq_t* rq, subnet_t* subnet)
{
	channel_doh_t* c = rq->ctx;
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

	req = http_request_create("POST", c->path, c->host);
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

	return req;
}

static int doh_http_query(myreq_t* rq, subnet_t* subnet)
{
	channel_doh_t* c = rq->ctx;
	http_request_t* req;
	int r;

	req = doh_build_http_request(rq, subnet);
	if (!req) {
		loge("doh_http_query() error: doh_build_http_request() error\n");
		return -1;
	}

	r = http_send(c->http, &c->http_addr, req, http_cb, rq);
	if (r) {
		loge("doh_http_query() error: http_send() error\n");
		free(http_request_get_data(req, NULL));
		http_request_destroy(req);
		return -1;
	}

	return r;
}

static int doh_query(myreq_t* rq)
{
	channel_doh_t* c = rq->ctx;
	int r = 0;

	if (c->ecs) {
		if (rq->qr.qtype == NS_QTYPE_AAAA) {
			if (c->china_net6.is_set) {
				r = doh_http_query(rq, &c->china_net6);
				if (r) {
					loge("doh_query() error: doh_http_query() error\n");
					return -1;
				}
				rq->wait_num++;
			}
			if (c->foreign_net6.is_set) {
				r = doh_http_query(rq, &c->foreign_net6);
				if (r) {
					loge("doh_query() error: doh_http_query() error\n");
					return -1;
				}
				rq->wait_num++;
			}
		}
		else if (rq->qr.qtype == NS_QTYPE_A) {
			if (c->china_net.is_set) {
				r = doh_http_query(rq, &c->china_net);
				if (r) {
					loge("doh_query() error: doh_http_query() error\n");
					return -1;
				}
				rq->wait_num++;
			}
			if (c->foreign_net.is_set) {
				r = doh_http_query(rq, &c->foreign_net);
				if (r) {
					loge("doh_query() error: doh_http_query() error\n");
					return -1;
				}
				rq->wait_num++;
			}
		}
	}

	if (rq->wait_num == 0) {
		r = doh_http_query(rq, NULL);
		if (r) {
			loge("doh_query() error: doh_http_query() error\n");
			return -1;
		}
		rq->wait_num++;
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
				loge("parse address failed: %s:%s\n",
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
		else if (strcmp(p, "ecs") == 0) {
			ctx->ecs = strcmp(v, "0");
		}
		else if (strcmp(p, "china-ip4") == 0) {
			if (v && *v && parse_subnet(&ctx->china_net, v)) {
				loge("parse \"china-ip4\" failed: %s\n", v);
				free(cpy);
				return -1;
			}
		}
		else if (strcmp(p, "china-ip6") == 0) {
			if (v && *v && parse_subnet(&ctx->china_net6, v)) {
				loge("parse \"china-ip6\" failed: %s\n", v);
				free(cpy);
				return -1;
			}
		}
		else if (strcmp(p, "foreign-ip4") == 0) {
			if (v && *v && parse_subnet(&ctx->foreign_net, v)) {
				loge("parse \"foreign-ip4\" failed: %s\n", v);
				free(cpy);
				return -1;
			}
		}
		else if (strcmp(p, "foreign-ip6") == 0) {
			if (v && *v && parse_subnet(&ctx->foreign_net6, v)) {
				loge("parse \"foreign-ip6\" failed: %s\n", v);
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
