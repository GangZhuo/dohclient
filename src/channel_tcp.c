#include "channel_tcp.h"
#include "../rbtree/rbtree.h"
#include "mleak.h"

#define _M

typedef struct channel_tcp_t {
	CHANNEL_BASE(_M)
	dllist_t reqs;
	int req_count;
	sockaddr_t upstream_addr;
	int use_proxy;
	int timeout;
} channel_tcp_t;

typedef struct tcpreq_t {
	uint16_t id;
	ns_flags_t flags;
	ns_qr_t qr;
	time_t expire;
	int use_proxy;
	struct conn_t conn;
	channel_query_cb callback;
	stream_t proxy_stream;
	void* cb_state;
	dlitem_t entry;
	channel_tcp_t* ctx;
} tcpreq_t;

static inline void update_expire(tcpreq_t* req)
{
	channel_tcp_t* ctx = req->ctx;
	req->expire = time(NULL) + ctx->timeout;
}

static inline int is_expired(tcpreq_t* req, time_t now)
{
	return req->expire <= now;
}

static void req_close(tcpreq_t* req)
{
	req->conn.status = cs_closing;
	if (req->conn.sock) {
		shutdown(req->conn.sock, SHUT_RDWR);
	}
}

static tcpreq_t* req_new(
	channel_tcp_t* ctx,
	const ns_msg_t* msg,
	int use_proxy,
	channel_query_cb callback,
	void* state)
{
	tcpreq_t* req;
	conn_status cs;
	sock_t sock = 0;

	req = (tcpreq_t*)malloc(sizeof(tcpreq_t));
	if (!req) {
		loge("req_new() error: alloc\n");
		return NULL;
	}

	memset(req, 0, sizeof(tcpreq_t));

	if (use_proxy && ctx->proxy_num > 0) {
		req->use_proxy = use_proxy;
		cs = tcp_connect(&ctx->proxies->addr, &sock);
	}
	else {
		cs = tcp_connect(&ctx->upstream_addr, &sock);
	}
	if (cs != cs_connected && cs != cs_connecting) {
		loge("req_new() error: tcp_connect() error\n");
		free(req);
		return NULL;
	}

	if (conn_init(&req->conn, sock)) {
		loge("req_new() error: conn_init() error\n");
		close(sock);
		free(req);
		return NULL;
	}

	req->conn.status = cs;

	req->id = msg->id;
	req->flags = msg->flags;
	req->qr = msg->qrs[0];
	req->qr.qname = strdup(msg->qrs[0].qname);
	req->callback = callback;
	req->cb_state = state;
	req->ctx = ctx;

	update_expire(req);

	return req;
}

static void req_destroy(tcpreq_t* req)
{
	conn_free(&req->conn);
	free(req->qr.qname);
	free(req);
}

static void destroy(channel_t* ctx)
{
	channel_tcp_t* c = (channel_tcp_t*)ctx;
	dlitem_t* cur, * nxt;
	tcpreq_t* req;
	dllist_foreach(&c->reqs, cur, nxt,
		tcpreq_t, req, entry) {
		dllist_remove(&req->entry);
		if (req->callback)
			req->callback(ctx, -1, NULL, FALSE, FALSE, req->cb_state);
		req_destroy(req);
	}
	free(ctx);
}

static int parse_result(tcpreq_t* req, char* buf, int buf_len)
{
	channel_tcp_t* c = req->ctx;
	ns_msg_t* result = NULL;

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

	if (req->callback) {
		req->callback((channel_t*)c, 0, result, FALSE, TRUE, req->cb_state);
		req->callback = NULL;
	}

	req_close(req);

	return 0;
}

static int parse_recv(tcpreq_t* req)
{
	stream_t* s = &req->conn.rs;
	int msglen, left;

	while ((left = stream_rsize(s)) >= 2) {
		msglen = stream_geti(s, s->pos, 2);
		if (msglen > NS_PAYLOAD_SIZE) {
			loge("parse_recv() error: too large dns-message (msglen=0x%.4x)\n", msglen);
			return -1;
		}
		else if (left >= (msglen + 2)) {
			if (parse_result(req, s->array + s->pos + 2, msglen)) {
				return -1;
			}
			else {
				s->pos += (msglen + 2);
			}
		}
		else {
			break;
		}
	}

	if (s->pos > 0) {
		if (stream_quake(s)) {
			loge("parse_recv() error: stream_quake() failed\n");
			return -1;
		}
	}

	return 0;
}

static int req_recv(tcpreq_t* req)
{
	stream_t* s = &req->conn.rs;
	char* buffer;
	int buflen, nread;

	if (stream_set_cap(s, NS_PAYLOAD_SIZE + 2)) {
		return -1;
	}

	buffer = s->array + s->size;
	buflen = s->cap - s->size;

	nread = tcp_recv(req->conn.sock, buffer, buflen);

	if (nread == -1)
		return -1;

	if (nread == 0)
		return 0;

	s->size += nread;

	logv("req_recv(): recv %d bytes\n", nread);

	if (parse_recv(req)) {
		return -1;
	}

	return nread;

}

static int tcp_query(tcpreq_t* rq, int use_proxy, subnet_t* subnet)
{
	channel_tcp_t* c = rq->ctx;
	int r = 0;
	ns_msg_t msg;
	int len;
	stream_t* s = &rq->conn.ws;
	conn_status cs;

	init_ns_msg(&msg);

	msg.id = rq->id;
	msg.flags = rq->flags;
	msg.qdcount = 1;
	msg.qrs = ns_qr_clone(&rq->qr, 1);

	if (subnet) {
		ns_rr_t* rr;
		rr = ns_find_opt_rr(&msg);
		if (rr == NULL) {
			rr = ns_add_optrr(&msg);
			if (rr == NULL) {
				loge("tcp_query(): Can't add option record to ns_msg_t\n");
				ns_msg_free(&msg);
				return -1;
			}
		}

		rr->cls = NS_PAYLOAD_SIZE; /* reset edns payload size */

		if (ns_optrr_set_ecs(rr, (struct sockaddr*)&subnet->addr, subnet->mask, 0) != 0) {
			loge("tcp_query(): Can't add ecs option\n");
			ns_msg_free(&msg);
			return -1;
		}
	}

	stream_reset(s);

	if (s->cap < NS_PAYLOAD_SIZE) {
		if (stream_set_cap(s, NS_PAYLOAD_SIZE)) {
			loge("tcp_query(): stream_set_cap() error\n");
			ns_msg_free(&msg);
			return -1;
		}
	}

	// write length
	stream_writei16(s, 0);

	if ((len = ns_serialize(s, &msg, 0)) <= 0) {
		loge("tcp_query() error: ns_serialize() error\n");
		stream_free(s);
		ns_msg_free(&msg);
		return -1;
	}

	ns_msg_free(&msg);

	s->pos = 0;

	stream_seti16(s, 0, len);

	cs = rq->conn.status;
	if (cs == cs_socks5_handshaked || (rq->use_proxy == 0 && cs == cs_connected)) {
		r = tcp_send(rq->conn.sock, s);
		if (r == -1) {
			loge("tcp_query() error: tcp_send() error\n");
			stream_free(s);
			return -1;
		}
		else if (stream_rsize(s) == 0) {
			stream_free(s);
		}
	}
	
	return 0;
}

static int check_expire(channel_tcp_t* c)
{
	dlitem_t* cur, * nxt;
	tcpreq_t* req;
	time_t now = time(NULL);

	dllist_foreach(&c->reqs, cur, nxt,
		tcpreq_t, req, entry) {
		if (is_expired(req, now)) {

			dllist_remove(&req->entry);
			c->req_count--;

			loge("tcp_query() timeout - %s\n", qr_key(&req->qr));

			if (req->callback) {
				req->callback((channel_t*)c, -1, NULL, FALSE, FALSE, req->cb_state);
			}

			req_destroy(req);
		}
	}

	return 0;
}

static int socks5_handshake(channel_tcp_t* ctx, tcpreq_t* req)
{
	int r;
	conn_status cs = req->conn.status;
	stream_t* s = &req->proxy_stream;
	int rsize = stream_rsize(s);

	if (s->cap < 1024) {
		if (stream_set_cap(s, 1024)) {
			return -1;
		}
	}

	switch (cs) {
	case cs_connected:
		if (rsize == 0) {
			s->array[0] = 0x05;
			s->array[1] = 0x01;
			s->array[2] = 0x00;
			s->pos = 0;
			s->size = 3;
		}
		r = tcp_send(req->conn.sock, s);
		if (r < 0) {
			loge("socks5_handshake() error: tcp_send() error\n");
			return -1;
		}
		if (stream_rsize(s) > 0) {
			req->conn.status = cs_socks5_sending_method;
		}
		else {
			req->conn.status = cs_socks5_waiting_method;
		}
		break;
	case cs_socks5_waiting_method:
		r = tcp_recv(req->conn.sock, s->array, s->cap);
		if (r != 2) {
			loge("socks5_handshake() error: tcp_recv() error\n");
			return -1;
		}
		if (s->array[0] == 0x05 && s->array[1] == 0x00) {
			s->array[0] = 0x05;
			s->array[1] = 0x01;
			s->array[2] = 0x00;
			if (ctx->upstream_addr.addr.ss_family == AF_INET) {
				struct sockaddr_in* addr = (struct sockaddr_in*)&ctx->upstream_addr.addr;
				int port = htons(addr->sin_port);
				s->array[3] = 0x01;
				memcpy(s->array + 4, &addr->sin_addr, 4);
				s->array[8] = (char)((port >> 8) & 0xff);
				s->array[9] = (char)((port >> 0) & 0xff);
				s->size = 10;
			}
			else {
				s->array[3] = 0x04;
				struct sockaddr_in6* addr = (struct sockaddr_in6*)&ctx->upstream_addr.addr;
				int port = htons(addr->sin6_port);
				s->array[3] = 0x01;
				memcpy(s->array + 4, &addr->sin6_addr, 16);
				s->array[20] = (char)((port >> 8) & 0xff);
				s->array[21] = (char)((port >> 0) & 0xff);
				s->size = 22;
			}
			s->pos = 0;
			req->conn.status = cs_socks5_sending_connect;
			r = tcp_send(req->conn.sock, s);
			if (r < 0) {
				loge("socks5_handshake() error: tcp_send() error\n");
				return -1;
			}
			if (stream_rsize(s) > 0) {
				req->conn.status = cs_socks5_sending_connect;
			}
			else {
				req->conn.status = cs_socks5_waiting_connect;
			}
		}
		else {
			loge("socks5_handshake() error: no support method\n");
			return -1;
		}
		break;
	case cs_socks5_sending_connect:
		r = tcp_send(req->conn.sock, s);
		if (r < 0) {
			loge("socks5_handshake() error: tcp_send() error\n");
			return -1;
		}
		if (stream_rsize(s) > 0) {
			req->conn.status = cs_socks5_sending_connect;
		}
		else {
			req->conn.status = cs_socks5_waiting_connect;
		}
		break;
	case cs_socks5_waiting_connect:
		r = tcp_recv(req->conn.sock, s->array, s->cap);
		if (r <= 0) {
			loge("socks5_handshake() error: tcp_recv() error\n");
			return -1;
		}
		if (s->array[0] == 0x05 && s->array[1] == 0x00) {
			req->conn.status = cs_socks5_handshaked;
			stream_free(s);
			logv("socks5_handshake(): socks5 handshaked\n");
			return 0;
		}
		else {
			loge("socks5_handshake() error: connect error\n");
			return -1;
		}
		break;
	default:
		loge("socks5_handshake() error: unknown status\n");
		return -1;
	}

	return 0;
}

static sock_t fdset(channel_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	channel_tcp_t* c = (channel_tcp_t*)ctx;
	dlitem_t* cur, * nxt;
	tcpreq_t* req;
	conn_status cs;
	int is_sending;
	sock_t maxfd = 0;
	dllist_foreach(&c->reqs, cur, nxt, tcpreq_t, req, entry) {
		cs = req->conn.status;
		if (cs == cs_socks5_handshaked || (req->use_proxy == 0 && cs == cs_connected)) {
			maxfd = MAX(maxfd, req->conn.sock);
			is_sending = stream_rsize(&req->conn.ws) > 0;
			if (is_sending)
				FD_SET(req->conn.sock, writeset);
			else
				FD_SET(req->conn.sock, readset);
			FD_SET(req->conn.sock, errorset);
		}
		else if (cs == cs_socks5_waiting_method || cs == cs_socks5_waiting_connect) {
			maxfd = MAX(maxfd, req->conn.sock);
			FD_SET(req->conn.sock, readset);
			FD_SET(req->conn.sock, errorset);
		}
		else if (cs == cs_socks5_sending_method || cs == cs_socks5_sending_connect) {
			maxfd = MAX(maxfd, req->conn.sock);
			FD_SET(req->conn.sock, writeset);
			FD_SET(req->conn.sock, errorset);
		}
		else if (cs == cs_connecting) {
			maxfd = MAX(maxfd, req->conn.sock);
			FD_SET(req->conn.sock, writeset);
			FD_SET(req->conn.sock, errorset);
		}
	}
	return maxfd;
}

static int step(channel_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	channel_tcp_t* c = (channel_tcp_t*)ctx;
	dlitem_t* cur, * nxt;
	tcpreq_t* req;
	conn_status cs;
	int is_sending;
	time_t now;
	int r = 0;

	now = time(NULL);

	dllist_foreach(&c->reqs, cur, nxt, tcpreq_t, req, entry) {
		cs = req->conn.status;
		r = 0;
		if (cs == cs_closing || cs == cs_rsp_closing) {
			r = -1;
		}
		else if (FD_ISSET(req->conn.sock, errorset)) {
			int err = getsockerr(req->conn.sock);
			loge("step(): sock error: errno=%d, %s \n",
				err, strerror(err));
			r = -1;
		}
		else {
			if (cs == cs_socks5_handshaked || (req->use_proxy == 0 && cs == cs_connected)) {
				is_sending = stream_rsize(&req->conn.ws) > 0;
				if (is_sending) {
					if (FD_ISSET(req->conn.sock, writeset)) {
						r = tcp_send(req->conn.sock, &req->conn.ws);
						if (r >= 0)
							r = 0;
					}
				}
				else if (FD_ISSET(req->conn.sock, readset)) {
					r = req_recv(req);
					if (r >= 0)
						r = 0;
				}
			}
			else if (cs == cs_socks5_waiting_method || cs == cs_socks5_waiting_connect) {
				if (FD_ISSET(req->conn.sock, readset)) {
					r = socks5_handshake(c, req);
				}
			}
			else if (cs == cs_socks5_sending_method || cs == cs_socks5_sending_connect) {
				if (FD_ISSET(req->conn.sock, writeset)) {
					r = socks5_handshake(c, req);
				}
			}
			else if (cs == cs_connecting) {
				if (FD_ISSET(req->conn.sock, writeset)) {
					req->conn.status = cs_connected;
					if (req->use_proxy && c->proxy_num > 0) {
						r = socks5_handshake(c, req);
					}
					else {
						req->use_proxy = FALSE;
						/* do nothing, send request at next loop step */
					}
				}
			}
		}

		if (r == 0 && is_expired(req, now)) {
			loge("tcp timeout - %s\n", get_sockname(req->conn.sock));
			r = -1;
			if (req->callback) {
				req->callback((channel_t*)c, -1, NULL, FALSE, FALSE, req->cb_state);
				req->callback = NULL;
			}
			req_close(req);
		}
		else if (r != 0) {
			if (req->callback) {
				req->callback((channel_t*)c, -1, NULL, FALSE, FALSE, req->cb_state);
				req->callback = NULL;
			}

			dllist_remove(&req->entry);
			c->req_count--;
			req_destroy(req);
		}
	}

	return 0;
}

static int query(channel_t* ctx,
	const ns_msg_t* msg,
	channel_query_cb callback, void* state)
{
	channel_tcp_t* c = (channel_tcp_t*)ctx;
	tcpreq_t* req;

	req = req_new(c, msg, c->use_proxy, callback, state);
	if (!req)
		return -1;

	dllist_add(&c->reqs, &req->entry);
	c->req_count++;

	if (tcp_query(req, c->use_proxy, NULL)) {
		loge("tcp_query() failed\n");
		dllist_remove(&req->entry);
		c->req_count--;
		req_destroy(req);
		return -1;
	}

	return 0;
}

static int parse_args(channel_tcp_t* ctx, const char* args)
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

int channel_tcp_create(
	channel_t** pctx,
	const char* name,
	const char* args,
	const config_t* conf,
	const proxy_t* proxies,
	const int proxy_num,
	const chnroute_ctx chnr,
	void* data)
{
	channel_tcp_t* ctx;

	ctx = (channel_tcp_t*)malloc(sizeof(channel_tcp_t));
	if (!ctx) {
		loge("channel_tcp_create() error: alloc\n");
		return CHANNEL_ALLOC;
	}

	memset(ctx, 0, sizeof(channel_tcp_t));

	if (parse_args(ctx, args)) {
		loge("channel_tcp_create() error: parse_args() error\n");
		return CHANNEL_WRONG_ARG;
	}

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
