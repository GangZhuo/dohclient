#include "version.h"
#include "channel_tcp.h"
#include "../rbtree/rbtree.h"
#include "netutils.h"
#include "base64url.h"
#include "../http-parser/http_parser.h"
#include "mleak.h"

#define _M

typedef struct channel_tcp_t {
	CHANNEL_BASE(_M)
	dllist_t reqs;
	int req_count;
	sockaddr_t upstreams[MAX_UPSTREAM];
	int upstream_num;
	int use_proxy;
	int timeout;
} channel_tcp_t;

typedef struct tcpreq_t {
	uint16_t id;
	uint16_t flags;
	ns_qr_t qr;
	time_t expire;
	channel_query_cb callback;
	void* cb_state;
	dlitem_t entry;
	channel_tcp_t* ctx;
	dllist_t conns;
	int is_closing;
} tcpreq_t;

typedef struct reqconn_t {
	struct conn_t  conn;
	int            use_proxy;
	int            proxy_index;
	stream_t       proxy_stream;
	tcpreq_t      *req;
	int            upstream;
} reqconn_t;

static int proxy_handshake(channel_tcp_t *ctx, tcpreq_t *req, reqconn_t *conn);

static inline void update_expire(tcpreq_t* req)
{
	channel_tcp_t* ctx = req->ctx;
	req->expire = time(NULL) + ctx->timeout;
}

static inline int is_expired(tcpreq_t* req, time_t now)
{
	return req->expire <= now;
}

static reqconn_t *reqconn_new(tcpreq_t *req, int upstream, int proxy_index)
{
	reqconn_t *conn;
	sock_t sock = -1;
	conn_status cs;
	channel_tcp_t* c = req->ctx;

	conn = (reqconn_t*)malloc(sizeof(reqconn_t));
	if (!conn) {
		loge("reqconn_new() error: alloc\n");
		return NULL;
	}

	memset(conn, 0, sizeof(reqconn_t));

	conn->req = req;
	conn->upstream = upstream;

	if (proxy_index >= 0 && proxy_index < c->proxy_num) {
		conn->use_proxy = TRUE;
		conn->proxy_index = proxy_index;
		cs = tcp_connect(&c->proxies[proxy_index].addr, &sock);
	}
	else {
		cs = tcp_connect(c->upstreams + upstream, &sock);
	}
	if (cs != cs_connected && cs != cs_connecting) {
		loge("tcp_query() error: tcp_connect() error\n");
		free(conn);
		return NULL;
	}

	if (conn_init(&conn->conn, sock)) {
		loge("tcp_query() error: conn_init() error\n");
		close(sock);
		free(conn);
		return NULL;
	}

	conn->conn.status = cs;

	return conn;
}

static void reqconn_close(reqconn_t *conn)
{
	conn->conn.status = cs_closing;
	if (conn->conn.sock) {
		shutdown(conn->conn.sock, SHUT_RDWR);
	}
}

static void reqconn_destroy(reqconn_t *conn)
{
	conn_free(&conn->conn);
	stream_free(&conn->proxy_stream);
	free(conn);
}

static void req_close(tcpreq_t* req)
{
	dlitem_t *cur, *nxt;
	reqconn_t *conn;
	dllist_foreach(&req->conns, cur, nxt,
		reqconn_t, conn, conn.entry) {
		conn->conn.status = cs_closing;
		if (conn->conn.sock) {
			shutdown(conn->conn.sock, SHUT_RDWR);
		}
	}
	req->is_closing = TRUE;
}

static tcpreq_t* req_new(
	channel_tcp_t* ctx,
	const ns_msg_t* msg,
	channel_query_cb callback,
	void* state)
{
	tcpreq_t* req;

	req = (tcpreq_t*)malloc(sizeof(tcpreq_t));
	if (!req) {
		loge("req_new() error: alloc\n");
		return NULL;
	}

	memset(req, 0, sizeof(tcpreq_t));

	req->id = msg->id;
	req->flags = msg->flags;
	req->qr = msg->qrs[0];
	req->qr.qname = strdup(msg->qrs[0].qname);
	req->callback = callback;
	req->cb_state = state;
	req->ctx = ctx;

	dllist_init(&req->conns);

	update_expire(req);

	return req;
}

static void req_destroy(tcpreq_t* req)
{
	dlitem_t *cur, *nxt;
	reqconn_t *conn;
	dllist_foreach(&req->conns, cur, nxt,
		reqconn_t, conn, conn.entry) {
		dllist_init_remove(&conn->conn.entry);
		reqconn_destroy(conn);
	}
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

static int parse_result(tcpreq_t* req, char* buf, int buf_len, reqconn_t *conn)
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

	logd("request got answer(s) - %s - %s\n",
		msg_key(result), get_sockaddrname(&c->upstreams[conn->upstream]));

	if (req->callback) {
		req->callback((channel_t*)c, 0, result, FALSE, TRUE, req->cb_state);
		req->callback = NULL;
	}

	req_close(req);

	return 0;
}

static int parse_recv(tcpreq_t* req, reqconn_t *conn)
{
	stream_t* s = &conn->conn.rs;
	int msglen, left;

	while ((left = stream_rsize(s)) >= 2) {
		msglen = stream_geti(s, s->pos, 2);
		if (msglen > NS_PAYLOAD_SIZE) {
			loge("parse_recv() error: too large dns-message (msglen=0x%.4x)\n", msglen);
			return -1;
		}
		else if (left >= (msglen + 2)) {
			if (parse_result(req, s->array + s->pos + 2, msglen, conn)) {
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

static int req_recv(tcpreq_t* req, reqconn_t *conn)
{
	stream_t* s = &conn->conn.rs;
	char* buffer;
	int buflen, nread;

	if (stream_set_cap(s, NS_PAYLOAD_SIZE + 2)) {
		return -1;
	}

	buffer = s->array + s->size;
	buflen = s->cap - s->size;

	nread = tcp_recv(conn->conn.sock, buffer, buflen);

	if (nread == -1)
		return -1;

	if (nread == 0)
		return 0;

	s->size += nread;

	logv("req_recv(): recv %d bytes - %s\n",
			nread, get_sockaddrname(req->ctx->upstreams + conn->upstream));

	if (parse_recv(req, conn)) {
		return -1;
	}

	return nread;
}

static int tcp_create_nsmsg(stream_t *s, tcpreq_t *rq, subnet_t *subnet)
{
	int r = 0;
	ns_msg_t msg;
	int len;

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
				loge("tcp_create_nsmsg(): Can't add option record to ns_msg_t\n");
				ns_msg_free(&msg);
				return -1;
			}
		}

		rr->cls = NS_PAYLOAD_SIZE; /* reset edns payload size */

		if (ns_optrr_set_ecs(rr, (struct sockaddr*)&subnet->addr, subnet->mask, 0) != 0) {
			loge("tcp_create_nsmsg(): Can't add ecs option\n");
			ns_msg_free(&msg);
			return -1;
		}
	}

	stream_reset(s);

	if (s->cap < NS_PAYLOAD_SIZE) {
		if (stream_set_cap(s, NS_PAYLOAD_SIZE)) {
			loge("tcp_create_nsmsg(): stream_set_cap() error\n");
			ns_msg_free(&msg);
			return -1;
		}
	}

	// write length
	stream_writei16(s, 0);

	if ((len = ns_serialize(s, &msg, 0)) <= 0) {
		loge("tcp_create_nsmsg() error: ns_serialize() error\n");
		stream_free(s);
		ns_msg_free(&msg);
		return -1;
	}

	ns_msg_free(&msg);

	s->pos = 0;

	stream_seti16(s, 0, len);

	return len;
}

static int tcp_query(tcpreq_t *rq, int upstream, int proxy_index, subnet_t *subnet)
{
	channel_tcp_t* c = rq->ctx;
	int r = 0;
	int len;
	reqconn_t *conn;
	stream_t *s;
	conn_status cs;

	conn = reqconn_new(rq, upstream, proxy_index);
	if (!conn) {
		loge("tcp_query(): Can't create reqconn_t\n");
		return -1;
	}

	s = &conn->conn.ws;

	len = tcp_create_nsmsg(s, rq, subnet);
	if (len <= 0) {
		loge("tcp_query(): Can't create ns_msg_t binary data\n");
		reqconn_destroy(conn);
		return -1;
	}

	dllist_add(&rq->conns, &conn->conn.entry);

	cs = conn->conn.status;
	if (!conn->use_proxy && cs == cs_connected) {
		r = tcp_send(conn->conn.sock, s);
		if (r == -1) {
			loge("tcp_query() error: tcp_send() error\n");
			stream_free(s);
			return -1;
		}
		else if (stream_rsize(s) == 0) {
			stream_free(s);
		}
	}
	else if (conn->use_proxy && cs == cs_connected) {
		r = proxy_handshake(c, rq, conn);
		if (r == -1) {
			loge("tcp_query() error: proxy_handshake() error\n");
			stream_free(s);
			return -1;
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

			dllist_init_remove(&req->entry);
			c->req_count--;

			loge("check_expire() timeout - %s\n", qr_key(&req->qr));

			if (req->callback) {
				req->callback((channel_t*)c, -1, NULL, FALSE, FALSE, req->cb_state);
			}

			req_destroy(req);
		}
	}

	return 0;
}

static int socks5_handshake(channel_tcp_t* ctx, tcpreq_t* req, reqconn_t *conn)
{
	int r;
	conn_status cs = conn->conn.status;
	stream_t* s = &conn->proxy_stream;
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
		r = tcp_send(conn->conn.sock, s);
		if (r < 0) {
			loge("socks5_handshake() error: tcp_send() error\n");
			return -1;
		}
		if (stream_rsize(s) > 0) {
			conn->conn.status = cs_socks5_sending_method;
		}
		else {
			conn->conn.status = cs_socks5_waiting_method;
		}
		break;
	case cs_socks5_waiting_method:
		r = tcp_recv(conn->conn.sock, s->array, s->cap);
		if (r != 2) {
			loge("socks5_handshake() error: tcp_recv() error\n");
			return -1;
		}
		if (s->array[0] == 0x05 && s->array[1] == 0x00) {
			sockaddr_t *upstream = &ctx->upstreams[conn->upstream];
			s->array[0] = 0x05;
			s->array[1] = 0x01;
			s->array[2] = 0x00;
			if (upstream->addr.ss_family == AF_INET) {
				struct sockaddr_in* addr = (struct sockaddr_in*)&upstream->addr;
				int port = htons(addr->sin_port);
				s->array[3] = 0x01;
				memcpy(s->array + 4, &addr->sin_addr, 4);
				s->array[8] = (char)((port >> 8) & 0xff);
				s->array[9] = (char)((port >> 0) & 0xff);
				s->size = 10;
			}
			else {
				s->array[3] = 0x04;
				struct sockaddr_in6* addr = (struct sockaddr_in6*)&upstream->addr;
				int port = htons(addr->sin6_port);
				s->array[3] = 0x01;
				memcpy(s->array + 4, &addr->sin6_addr, 16);
				s->array[20] = (char)((port >> 8) & 0xff);
				s->array[21] = (char)((port >> 0) & 0xff);
				s->size = 22;
			}
			s->pos = 0;
			conn->conn.status = cs_socks5_sending_connect;
			r = tcp_send(conn->conn.sock, s);
			if (r < 0) {
				loge("socks5_handshake() error: tcp_send() error\n");
				return -1;
			}
			if (stream_rsize(s) > 0) {
				conn->conn.status = cs_socks5_sending_connect;
			}
			else {
				conn->conn.status = cs_socks5_waiting_connect;
			}
		}
		else {
			loge("socks5_handshake() error: no support method\n");
			return -1;
		}
		break;
	case cs_socks5_sending_connect:
		r = tcp_send(conn->conn.sock, s);
		if (r < 0) {
			loge("socks5_handshake() error: tcp_send() error\n");
			return -1;
		}
		if (stream_rsize(s) > 0) {
			conn->conn.status = cs_socks5_sending_connect;
		}
		else {
			conn->conn.status = cs_socks5_waiting_connect;
		}
		break;
	case cs_socks5_waiting_connect:
		r = tcp_recv(conn->conn.sock, s->array, s->cap);
		if (r <= 0) {
			loge("socks5_handshake() error: tcp_recv() error\n");
			return -1;
		}
		if (s->array[0] == 0x05 && s->array[1] == 0x00) {
			conn->conn.status = cs_socks5_handshaked;
			stream_free(s);
			logv("socks5_handshake(): socks5 handshaked\n");
			r = 0;
			if (stream_rsize(&conn->conn.ws) > 0) {
				r = tcp_send(conn->conn.sock, &conn->conn.ws);
				if (r >= 0)
					r = 0;
			}
			return r;
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

/* http proxy handshake */
static int hp_handshake(channel_tcp_t *ctx, tcpreq_t *req, reqconn_t *conn)
{
	int r;
	const proxy_t *proxy = ctx->proxies + conn->proxy_index;
	conn_status cs = conn->conn.status;
	stream_t* s = &conn->proxy_stream;
	int rsize = stream_rsize(s);

	if (stream_rcap(s) < 1024) {
		int new_cap = MAX(s->cap * 2, 1024);
		if (stream_set_cap(s, new_cap)) {
			return -1;
		}
	}

	switch (cs) {
	case cs_connected:
		logv("hp_handshake(): CONNECT\n");
		if (rsize == 0) {
			sockaddr_t *upstream = &ctx->upstreams[conn->upstream];
			const char *target_host = get_sockaddrname(upstream);
			const int authorization = strlen(proxy->username) > 0;
			char *auth_code = NULL;
			int auth_code_len = 0;
			if (authorization) {
				char auth_str[PROXY_USERNAME_LEN + PROXY_PASSWORD_LEN];
				sprintf(auth_str, "%s:%s", proxy->username, proxy->password);
				auth_code = base64url_encode((const unsigned char*)auth_str,
						strlen(auth_str), &auth_code_len, TRUE, FALSE);
			}
			r = stream_writef(s,
				"CONNECT %s HTTP/1.1\r\n"
				"Host: %s\r\n"
				"User-Agent: "DOHCLIENT_NAME"/"DOHCLIENT_VERSION"\r\n"
				"Proxy-Connection: keep-alive\r\n"
				"Connection: keep-alive\r\n"
				"%s%s%s"
				"\r\n",
				target_host,
				target_host,
				authorization ? "Proxy-Authorization: Basic " : "",
				authorization ? auth_code : "",
				authorization ? "\r\n" : "");
			if (r == -1) {
				loge("hp_handshake() error: stream_writef()\n");
				free(auth_code);
				return -1;
			}
			logv("hp_handshake(): send\r\n%s\n", s->array);
			s->pos = 0;
			free(auth_code);
		}
		r = tcp_send(conn->conn.sock, s);
		if (r < 0) {
			loge("hp_handshake() error: tcp_send() error\n");
			return -1;
		}
		if (stream_rsize(s) > 0) {
			conn->conn.status = cs_hp_sending_connect;
		}
		else {
			conn->conn.status = cs_hp_waiting_connect;
			s->pos = s->size = 0;
		}
		break;
	case cs_hp_waiting_connect:
		logv("hp_handshake(): receiving connection status\n");
		r = tcp_recv(conn->conn.sock, s->array + s->pos, s->cap - s->pos - 1);
		if (r <= 0) {
			loge("hp_handshake() error: tcp_recv() error\n");
			return -1;
		}
		s->pos += r;
		s->size += r;
		s->array[s->pos] = '\0';
		logv("hp_handshake(): recv\r\n%s\n", s->array);
		if (s->size >= sizeof("HTTP/1.1 XXX")) {
			char *space;
			if (strncmp(s->array, "HTTP/", 5) == 0 &&
				(space = strchr(s->array, ' ')) != NULL) {
				char http_code_str[4];
				int http_code;
				strncpy(http_code_str, space + 1, sizeof(http_code_str));
				http_code_str[3] = '\0';
				http_code = atoi(http_code_str);
				if (http_code == 200) {
					if (strstr(s->array, "\r\n\r\n")) {
						conn->conn.status = cs_hp_handshaked;
						stream_free(s);
						logv("hp_handshake(): http proxy handshaked\n");
						r = 0;
						if (stream_rsize(&conn->conn.ws) > 0) {
							r = tcp_send(conn->conn.sock, &conn->conn.ws);
							if (r >= 0)
								r = 0;
						}
						return r;
					}
					else {
						conn->conn.status = cs_hp_waiting_data;
					}
				}
				else {
					loge("hp_handshake() error: http_code=%d\n%s\n", http_code, s->array);
					return -1;
				}
			}
			else {
				loge("hp_handshake() error: wrong response \"%s\"\n", s->array);
				return -1;
			}
		}
		else {
			loge("hp_handshake() error: connect error\n");
			return -1;
		}
		break;
	case cs_hp_waiting_data:
		logv("hp_handshake(): receiving left headers\n");
		r = tcp_recv(conn->conn.sock, s->array + s->pos, s->cap - s->pos - 1);
		if (r <= 0) {
			loge("hp_handshake() error: tcp_recv() error\n");
			return -1;
		}
		s->size += r;
		s->pos += r;
		s->array[s->pos] = '\0';
		if (strstr(s->array, "\r\n\r\n")) {
			conn->conn.status = cs_hp_handshaked;
			stream_free(s);
			logv("hp_handshake(): http proxy handshaked\n");
			r = 0;
			if (stream_rsize(&conn->conn.ws) > 0) {
				r = tcp_send(conn->conn.sock, &conn->conn.ws);
				if (r >= 0)
					r = 0;
			}
			return r;
		}
		else if (s->size >= HTTP_MAX_HEADER_SIZE) {
			loge("hp_handshake() error: received too large (>= %s bytes)"
				" header data from http proxy.\n", s->pos);
			stream_free(s);
			return -1;
		}
		else {
			conn->conn.status = cs_hp_waiting_data;
		}
		break;
	default:
		loge("hp_handshake() error: unknown status\n");
		return -1;
	}

	return 0;
}

static int proxy_handshake(channel_tcp_t *ctx, tcpreq_t *req, reqconn_t *conn)
{
	const proxy_t *proxy = ctx->proxies + conn->proxy_index;

	switch (proxy->proxy_type) {
		case SOCKS5_PROXY:
			return socks5_handshake(ctx, req, conn);
		case HTTP_PROXY:
			return hp_handshake(ctx, req, conn);
		default:
			loge("proxy_handshake() error: unsupport proxy type");
			return -1;
	}
}

static sock_t req_fdset(channel_t* ctx, tcpreq_t *req,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	channel_tcp_t* c = (channel_tcp_t*)ctx;
	dlitem_t* cur, * nxt;
	reqconn_t* conn;
	conn_status cs;
	int is_sending;
	sock_t maxfd = 0;
	dllist_foreach(&req->conns, cur, nxt, reqconn_t, conn, conn.entry) {
		cs = conn->conn.status;
		if (cs == cs_socks5_handshaked || cs == cs_hp_handshaked ||
				(!conn->use_proxy && cs == cs_connected)) {
			maxfd = MAX(maxfd, conn->conn.sock);
			is_sending = stream_rsize(&conn->conn.ws) > 0;
			if (is_sending)
				FD_SET(conn->conn.sock, writeset);
			else
				FD_SET(conn->conn.sock, readset);
			FD_SET(conn->conn.sock, errorset);
		}
		else if (cs == cs_socks5_waiting_method || cs == cs_socks5_waiting_connect ||
				cs == cs_hp_waiting_connect || cs == cs_hp_waiting_data) {
			maxfd = MAX(maxfd, conn->conn.sock);
			FD_SET(conn->conn.sock, readset);
			FD_SET(conn->conn.sock, errorset);
		}
		else if (cs == cs_socks5_sending_method || cs == cs_socks5_sending_connect ||
				cs == cs_hp_sending_connect) {
			maxfd = MAX(maxfd, conn->conn.sock);
			FD_SET(conn->conn.sock, writeset);
			FD_SET(conn->conn.sock, errorset);
		}
		else if (cs == cs_connecting) {
			maxfd = MAX(maxfd, conn->conn.sock);
			FD_SET(conn->conn.sock, writeset);
			FD_SET(conn->conn.sock, errorset);
		}
	}
	return maxfd;
}

static sock_t fdset(channel_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	channel_tcp_t *c = (channel_tcp_t*)ctx;
	dlitem_t *cur, *nxt;
	tcpreq_t *req;
	sock_t maxfd = 0, fd;
	dllist_foreach(&c->reqs, cur, nxt, tcpreq_t, req, entry) {
		if (!req->is_closing) {
			fd = req_fdset(ctx, req, readset, writeset, errorset);
			maxfd = MAX(maxfd, fd);
		}
	}
	return maxfd;
}

static int req_step(channel_t* ctx, tcpreq_t *req, time_t now,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	channel_tcp_t *c = (channel_tcp_t*)ctx;
	dlitem_t *cur, *nxt;
	reqconn_t *conn;
	conn_status cs;
	int is_sending;
	int r = 0, rv = -1;
	dllist_foreach(&req->conns, cur, nxt, reqconn_t, conn, conn.entry) {
		cs = conn->conn.status;
		r = 0;
		if (cs == cs_closing || cs == cs_rsp_closing) {
			r = -1;
		}
		else if (FD_ISSET(conn->conn.sock, errorset)) {
			int err = getsockerr(conn->conn.sock);
			loge("req_step(): sock error: errno=%d, %s - %s\n",
				err, strerror(err), get_sockaddrname(&c->upstreams[conn->upstream]));
			r = -1;
		}
		else {
			if (cs == cs_socks5_handshaked || cs == cs_hp_handshaked ||
					(!conn->use_proxy && cs == cs_connected)) {
				is_sending = stream_rsize(&conn->conn.ws) > 0;
				if (is_sending) {
					if (FD_ISSET(conn->conn.sock, writeset)) {
						r = tcp_send(conn->conn.sock, &conn->conn.ws);
						if (r >= 0)
							r = 0;
					}
				}
				else if (FD_ISSET(conn->conn.sock, readset)) {
					r = req_recv(req, conn);
					if (r >= 0)
						r = 0;
				}
			}
			else if (cs == cs_socks5_waiting_method || cs == cs_socks5_waiting_connect ||
					cs == cs_hp_waiting_connect || cs == cs_hp_waiting_data) {
				if (FD_ISSET(conn->conn.sock, readset)) {
					r = proxy_handshake(c, req, conn);
				}
			}
			else if (cs == cs_socks5_sending_method || cs == cs_socks5_sending_connect ||
					cs == cs_hp_sending_connect) {
				if (FD_ISSET(conn->conn.sock, writeset)) {
					r = proxy_handshake(c, req, conn);
				}
			}
			else if (cs == cs_connecting) {
				if (FD_ISSET(conn->conn.sock, writeset)) {
					conn->conn.status = cs_connected;
					if (conn->use_proxy) {
						r = proxy_handshake(c, req, conn);
					}
					else {
						if (stream_rsize(&conn->conn.ws) > 0) {
							r = tcp_send(conn->conn.sock, &conn->conn.ws);
							if (r >= 0)
								r = 0;
						}
					}
				}
			}
		}

		if (r == 0) {
			/* Return success when more than one connection have no error */
			rv = 0;
		}
		else if (r != 0) {
			dllist_init_remove(&conn->conn.entry);
			reqconn_destroy(conn);
		}
	}

	return rv;
}

static int step(channel_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset)
{
	channel_tcp_t *c = (channel_tcp_t*)ctx;
	dlitem_t *cur, *nxt;
	tcpreq_t *req;
	time_t now;
	now = time(NULL);
	dllist_foreach(&c->reqs, cur, nxt, tcpreq_t, req, entry) {
		if (req->is_closing) {
			if (req->callback) {
				req->callback((channel_t*)c, -1, NULL, FALSE, FALSE, req->cb_state);
				req->callback = NULL;
			}
			dllist_init_remove(&req->entry);
			c->req_count--;
			req_destroy(req);
		}
		else {
			int r = req_step(ctx, req, now, readset, writeset, errorset);
			if (r != 0 || is_expired(req, now)) {
				if (r == 0)
					loge("request timeout - %s\n", req->qr.qname);
				if (req->callback) {
					req->callback((channel_t*)c, -1, NULL, FALSE, FALSE, req->cb_state);
					req->callback = NULL;
				}
				dllist_init_remove(&req->entry);
				c->req_count--;
				req_destroy(req);
			}
		}
	}
	return 0;
}

static int query(channel_t* ctx,
	const ns_msg_t* msg,
	channel_query_cb callback, void* state)
{
	channel_tcp_t* c = (channel_tcp_t*)ctx;

	return channel_tcp_query(ctx, msg, c->use_proxy, NULL, callback, state);
}

int channel_tcp_query(channel_t* ctx,
	const ns_msg_t* msg,
	int use_proxy, subnet_t* subnet,
	channel_query_cb callback, void* state)
{
	channel_tcp_t* c = (channel_tcp_t*)ctx;
	tcpreq_t* req;
	int i, n = 0;

	if (use_proxy == -1) use_proxy = c->use_proxy;

	req = req_new(c, msg, callback, state);
	if (!req)
		return -1;

	dllist_add(&c->reqs, &req->entry);
	c->req_count++;

	for (i = 0; i < c->upstream_num; i++) {
		if (tcp_query(req, i, use_proxy ? 0 : -1, subnet)) {
			logw("channel_tcp_query() error: tcp_query() error\n");
		}
		else {
			n++;
		}
	}

	if (n == 0) {
		loge("channel_tcp_query() error: no invalid upstream\n");
		dllist_init_remove(&req->entry);
		c->req_count--;
		req_destroy(req);
		return -1;
	}

	return 0;
}

static int parse_args(channel_tcp_t* ctx, const char* args)
{
	char* cpy, *saveptr = NULL;
	char* p;
	char* v;

	if (!args) return -1;

	cpy = strdup(args);

	for (p = strtok_r(cpy, "&", &saveptr);
		p && *p;
		p = strtok_r(NULL, "&", &saveptr)) {

		v = strchr(p, '=');
		if (!v) continue;

		*v = '\0';
		v++;

		if (strcmp(p, "upstream") == 0) {
			int n = str2addrs(v, &ctx->upstreams[0], MAX_UPSTREAM,
					sizeof(sockaddr_t), "53");
			if (n <= 0) {
				loge("parse address failed: %s:%s\n",
					p,
					(v && (*v)) ? v : "53"
				);
				free(cpy);
				return -1;
			}
			ctx->upstream_num = n;
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
	const chnroute_ctx blacklist,
	void* data)
{
	channel_tcp_t* ctx;

	ctx = (channel_tcp_t*)malloc(sizeof(channel_tcp_t));
	if (!ctx) {
		loge("channel_tcp_create() error: alloc\n");
		return CHANNEL_ALLOC;
	}

	memset(ctx, 0, sizeof(channel_tcp_t));

	ctx->name = name;
	ctx->conf = conf;
	ctx->proxies = proxies;
	ctx->proxy_num = proxy_num;
	ctx->chnr = chnr;
	ctx->blacklist = blacklist;
	ctx->data = data;
	ctx->timeout = conf->timeout;

	if (parse_args(ctx, args)) {
		loge("channel_tcp_create() error: parse_args() error\n");
		free(ctx);
		return CHANNEL_WRONG_ARG;
	}

	if (ctx->timeout <= 0) {
		loge("channel_tcp_create() error: invalid \"timeout\"\n");
		free(ctx);
		return CHANNEL_WRONG_ARG;
	}

	dllist_init(&ctx->reqs);

	ctx->fdset = fdset;
	ctx->step = step;
	ctx->query = query;
	ctx->destroy = destroy;

	*pctx = (channel_t*)ctx;

	return CHANNEL_OK;
}
