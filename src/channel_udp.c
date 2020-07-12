#include "channel_udp.h"
#include "../rbtree/rbtree.h"
#include "mleak.h"

#define _M

typedef struct channel_udp_t {
	CHANNEL_BASE(_M)
	dllist_t reqs;
	struct rbtree_t reqdic;
	int req_count;
	sock_t sock;
	sockaddr_t upstream_addr;
	int use_proxy;
	int timeout;
	char recv_buffer[NS_PAYLOAD_SIZE];
} channel_udp_t;

typedef struct udpreq_t {
	uint16_t req_id;
	uint16_t id;
	ns_flags_t flags;
	ns_qr_t qr;
	time_t expire;
	channel_query_cb callback;
	void* cb_state;
	dlitem_t entry;
	struct rbnode_t rbn;
	channel_udp_t* ctx;
} udpreq_t;

static inline void update_expire(udpreq_t* req)
{
	channel_udp_t* ctx = req->ctx;
	req->expire = time(NULL) + ctx->timeout;
}

static inline int is_expired(udpreq_t* req, time_t now)
{
	return req->expire <= now;
}

static uint16_t new_req_id(channel_udp_t* ctx)
{
	uint16_t newid;

	do {
		newid = (uint16_t)(rand() % 0x7FFF);
	} while (newid == 0 || rbtree_lookup(&ctx->reqdic, &newid));

	return newid;
}

static udpreq_t* req_new(
	channel_udp_t* ctx,
	const ns_msg_t* msg,
	channel_query_cb callback, void* state)
{
	udpreq_t* req;

	req = (udpreq_t*)malloc(sizeof(udpreq_t));
	if (!req) {
		loge("req_new() error: alloc\n");
		return NULL;
	}

	memset(req, 0, sizeof(udpreq_t));

	req->req_id = new_req_id(ctx);
	req->id = msg->id;
	req->flags = msg->flags;
	req->qr = msg->qrs[0];
	req->qr.qname = strdup(msg->qrs[0].qname);
	req->callback = callback;
	req->cb_state = state;
	req->rbn.key = &req->req_id;
	req->ctx = ctx;

	update_expire(req);

	return req;
}

static void req_destroy(udpreq_t* req)
{
	free(req->qr.qname);
	free(req);
}

static void destroy(channel_t* ctx)
{
	channel_udp_t* c = (channel_udp_t*)ctx;
	dlitem_t* cur, * nxt;
	udpreq_t* req;
	dllist_foreach(&c->reqs, cur, nxt,
		udpreq_t, req, entry) {
		dllist_remove(&req->entry);
		if (req->callback) {
			req->callback(ctx, -1, NULL, FALSE, FALSE, req->cb_state);
			req->callback = NULL;
		}
		req_destroy(req);
	}
	if (c->sock) {
		close(c->sock);
	}
	free(ctx);
}

static int udp_query(udpreq_t* rq, subnet_t* subnet)
{
	channel_udp_t* c = rq->ctx;
	int r = 0;
	ns_msg_t msg;
	int len;
	stream_t s = STREAM_INIT();

	init_ns_msg(&msg);

	msg.id = rq->req_id;
	msg.flags = rq->flags;
	msg.qdcount = 1;
	msg.qrs = ns_qr_clone(&rq->qr, 1);

	if (subnet) {
		ns_rr_t* rr;
		rr = ns_find_opt_rr(&msg);
		if (rr == NULL) {
			rr = ns_add_optrr(&msg);
			if (rr == NULL) {
				loge("udp_query(): Can't add option record to ns_msg_t\n");
				ns_msg_free(&msg);
				return -1;
			}
		}

		rr->cls = NS_PAYLOAD_SIZE; /* reset edns payload size */

		if (ns_optrr_set_ecs(rr, (struct sockaddr*)&subnet->addr, subnet->mask, 0) != 0) {
			loge("udp_query(): Can't add ecs option\n");
			ns_msg_free(&msg);
			return -1;
		}
	}

	if ((len = ns_serialize(&s, &msg, 0)) <= 0) {
		loge("udp_query() error: ns_serialize() error\n");
		stream_free(&s);
		ns_msg_free(&msg);
		return -1;
	}

	ns_msg_free(&msg);

	s.pos = 0;

	r = udp_send(c->sock, &s, (const struct sockaddr*)&c->upstream_addr.addr, c->upstream_addr.addrlen);
	if (r != s.size) {
		loge("udp_query() error: udp_send() error\n");
		stream_free(&s);
		return -1;
	}

	stream_free(&s);

	return 0;
}

static int parse_recv(channel_udp_t* c, char* buf, int buf_len, struct sockaddr* from, int from_len)
{
	udpreq_t* req;
	ns_msg_t* result = NULL;
	rbnode_t* rbn;

	result = (ns_msg_t*)malloc(sizeof(ns_msg_t));
	if (!result) {
		loge("parse_recv() error: alloc\n");
		return -1;
	}

	if (init_ns_msg(result)) {
		loge("parse_recv() error: init_ns_msg() error\n");
		free(result);
		return -1;
	}

	if (ns_parse(result, (const uint8_t*)buf, buf_len)) {
		loge("parse_recv() error: ns_parse() error\n");
		ns_msg_free(result);
		free(result);
		return -1;
	}

	rbn = rbtree_lookup(&c->reqdic, &result->id);
	if (!rbn) {
		logd("request have been destroyed - %s\n", msg_key(result));
		ns_msg_free(result);
		free(result);
		return -1;
	}

	req = rbtree_container_of(rbn, udpreq_t, rbn);

	dllist_remove(&req->entry);
	rbtree_remove(&c->reqdic, &req->rbn);
	c->req_count--;

	if (req->callback) {
		req->callback((channel_t*)c, 0, result, FALSE, TRUE, req->cb_state);
		req->callback = NULL;
	}

	req_destroy(req);

	return 0;
}

static int check_expire(channel_udp_t* c)
{
	dlitem_t* cur, * nxt;
	udpreq_t* req;
	time_t now = time(NULL);

	dllist_foreach(&c->reqs, cur, nxt,
		udpreq_t, req, entry) {
		if (is_expired(req, now)) {

			dllist_remove(&req->entry);
			rbtree_remove(&c->reqdic, &req->rbn);
			c->req_count--;

			loge("udp_query() timeout - %s\n", qr_key(&req->qr));

			if (req->callback) {
				req->callback((channel_t*)c, -1, NULL, FALSE, FALSE, req->cb_state);
				req->callback = NULL;
			}

			req_destroy(req);
		}
	}

	return 0;
}

static sock_t fdset(channel_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	channel_udp_t* c = (channel_udp_t*)ctx;
	FD_SET(c->sock, readset);
	FD_SET(c->sock, errorset);
	return c->sock;
}

static int step(channel_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	channel_udp_t* c = (channel_udp_t*)ctx;
	struct sockaddr_storage addr = { 0 };
	struct sockaddr* from = (struct sockaddr*)&addr;
	int from_len = sizeof(struct sockaddr_storage);
	int r;
	
	if (FD_ISSET(c->sock, errorset)) {
		int err = getsockerr(c->sock);
		loge("step(): sock error: errno=%d, %s \n",
			err, strerror(err));
		return -1;
	}
	else if (FD_ISSET(c->sock, readset)) {
		r = udp_recv(c->sock, c->recv_buffer, NS_PAYLOAD_SIZE, from, &from_len);
		if (r >= 0) {
			parse_recv(c, c->recv_buffer, r, from, from_len);
		}
		else {
			int err = getsockerr(c->sock);
			loge("step() error: errno=%d, %s\n",
				err, strerror(err));
			return -1;
		}
	}
	return check_expire(c);
}

static int query(channel_t* ctx,
	const ns_msg_t* msg,
	channel_query_cb callback, void* state)
{
	channel_udp_t* c = (channel_udp_t*)ctx;

	return channel_udp_query(ctx, msg, c->use_proxy, NULL, callback, state);
}

int channel_udp_query(channel_t* ctx,
	const ns_msg_t* msg,
	int use_proxy, subnet_t* subnet,
	channel_query_cb callback, void* state)
{
	channel_udp_t* c = (channel_udp_t*)ctx;
	udpreq_t* req;

	req = req_new(c, msg, callback, state);
	if (!req)
		return -1;

	dllist_add(&c->reqs, &req->entry);
	rbtree_insert(&c->reqdic, &req->rbn);
	c->req_count++;

	if (udp_query(req, subnet)) {
		loge("channel_udp_query() failed\n");
		dllist_remove(&req->entry);
		rbtree_remove(&c->reqdic, &req->rbn);
		c->req_count--;
		req_destroy(req);
		return -1;
	}

	return 0;
}

static int parse_args(channel_udp_t* ctx, const char* args)
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

		if (strcmp(p, "upstream") == 0) {
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

			if (!try_parse_as_ip(&ctx->upstream_addr, p, (v && (*v)) ? v : "53")) {
				loge("parse address failed: %s:%s\n",
					p,
					(v && (*v)) ? v : "53"
				);
				free(cpy);
				return -1;
			}
		}
		else if (strcmp(p, "proxy") == 0) {
			ctx->use_proxy = strcmp(v, "0");
		}
		else if (strcmp(p, "timeout") == 0) {
			if (*v) {
				ctx->timeout = atoi(v);
			}
		}
		else {
			logw("unknown argument: %s=%s\n", p, v);
		}
	}

	free(cpy);
	return 0;
}

static int rbcmp(const void* a, const void* b)
{
	int x = (int)(*((uint16_t*)a));
	int y = (int)(*((uint16_t*)b));
	return x - y;
}

int channel_udp_create(
	channel_t** pctx,
	const char* name,
	const char* args,
	const config_t* conf,
	const proxy_t* proxies,
	const int proxy_num,
	const chnroute_ctx chnr,
	void* data)
{
	channel_udp_t* ctx;
	sock_t sock;

	ctx = (channel_udp_t*)malloc(sizeof(channel_udp_t));
	if (!ctx) {
		loge("channel_udp_create() error: alloc\n");
		return CHANNEL_ALLOC;
	}

	memset(ctx, 0, sizeof(channel_udp_t));

	if (parse_args(ctx, args)) {
		loge("channel_udp_create() error: parse_args() error\n");
		return CHANNEL_WRONG_ARG;
	}

	sock = socket(ctx->upstream_addr.addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);

	if (!sock) {
		loge("channel_udp_create() error: create socket error. errno=%d, %s - %s\n",
			errno, strerror(errno), get_sockaddrname(&ctx->upstream_addr));
		free(ctx);
		return CHANNEL_CREATE_SOCKET;
	}

	if (setnonblock(sock) != 0) {
		loge("channel_udp_create() error: set sock non-block failed - %s\n",
			get_sockaddrname(&ctx->upstream_addr));
		close(sock);
		free(ctx);
		return CHANNEL_CREATE_SOCKET;
	}

	rbtree_init(&ctx->reqdic, rbcmp);
	dllist_init(&ctx->reqs);

	ctx->name = name;
	ctx->conf = conf;
	ctx->proxies = proxies;
	ctx->proxy_num = proxy_num;
	ctx->chnr = chnr;
	ctx->data = data;
	ctx->sock = sock;

	ctx->fdset = fdset;
	ctx->step = step;
	ctx->query = query;
	ctx->destroy = destroy;

	*pctx = (channel_t*)ctx;

	return CHANNEL_OK;
}
