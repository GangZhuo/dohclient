#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>

#include "version.h"
#include "utils.h"
#include "log.h"
#include "dllist.h"
#include "stream.h"
#include "chnroute.h"
#include "netutils.h"
#include "config.h"
#include "ns_msg.h"
#include "dns_request.h"
#include "../rbtree/rbtree.h"
#include "channel.h"
#include "channel_cache.h"
#include "channel_hosts.h"
#include "cache_api.h"
#include "http.h"
#include "httpserver.h"
#include "mleak.h"

/* rb-tree node */
typedef struct rbn_t {
	char *key;
	unsigned long ctime;
	struct rbnode_t node;
	dllist_t reqs;
} rbn_t;

static int req_rbkeycmp(const void* a, const void* b);
static config_t conf = {
	.timeout = -1,
	.cache_timeout = -1,
	.channel_choose_mode = -1,
};
static int running = 0;
static listen_t listens[MAX_LISTEN] = { 0 };
static int listen_num = 0;
static dllist_t peers = DLLIST_INIT(peers);
static proxy_t proxy_list[MAX_PROXY] = { 0 };
static int proxy_num = 0;
static chnroute_ctx chnr = NULL;
static chnroute_ctx blacklist = NULL;
static dllist_t reqs = DLLIST_INIT(reqs);
static struct rbtree_t reqdic = RBTREE_INIT(req_rbkeycmp);
static channel_t* hosts = NULL;
static channel_t *cache = NULL;
static channel_t** channels = NULL;
static int channel_num = 0;
static int save_cache_when_close = 0;

#ifdef WINDOWS

static SERVICE_STATUS ServiceStatus = {
	.dwServiceType = SERVICE_WIN32,
	.dwCurrentState = SERVICE_START_PENDING,
	.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
};
static SERVICE_STATUS_HANDLE hStatus = NULL;

static void ServiceMain(int argc, char** argv);
static void ControlHandler(DWORD request);
BOOL WINAPI sig_handler(DWORD signo);

#else
static void sig_handler(int signo);
#endif

static void usage()
{
	printf("%s\n", "\n"
		DOHCLIENT_NAME " " DOHCLIENT_VERSION "\n\
\n\
Usage:\n\
\n\
dohclient [-b BIND_ADDR] [-p BIND_PORT] [--config=CONFIG_PATH]\n\
         [--channel=CHANNEL] [--channel-args=ARGS]\n\
         [--log=LOG_FILE_PATH] [--log-level=LOG_LEVEL]\n\
         [--chnroute=CHNROUTE_FILE] [--proxy=SOCKS5_PROXY]\n\
         [--daemon] [--pid=PID_FILE_PATH] [-v] [-V] [-h]\n\
\n\
DoH client.\n\
\n\
Options:\n\
\n\
  -b BIND_ADDR             Address that listens, default: " DEFAULT_LISTEN_ADDR ".\n\
                           Use comma to separate multi addresses, \n\
                           e.g. -b 127.0.0.1:5354,[::1]:5354.\n\
  -p BIND_PORT             Port that listen on, default: " DEFAULT_LISTEN_PORT ".\n\
                           The port specified in \"-b\" is priority .\n\
  -t TIMEOUT               Timeout (seconds), default: " XSTR(DEFAULT_TIMEOUT) ".\n\
  --cache-timeout=TIMEOUT  Cache Timeout (seconds), default: 1.\n\
                           0 - Nevel expire, 1 - Following TTL, Other - Expire seconds.\n\
  --cache-db=PATH          Load cache from.\n\
                           e.g. --cache-db=\"/etc/dohclient/db0,/etc/dohclient/db1\".\n\
                           First comes have a higher priority.\n\
  --cache-autosave=PATH    Save cache to a file (when closing).\n\
                           e.g. --cache-db=\"/etc/dohclient/db0\".\n\
  --mode=[0|1|2]           Specify how to choose a channel.\n\
                           0 - Random, 1 - Concurrent, 2 - Polling.\n\
  --channel=CHANNEL        Channel name, e.g. os,doh,chinadns.\n\
  --channel-args=ARGS      Channel arguments. e.g. --channel-args=\"addr=8.8.4.4:443\n\
                           &host=dns.google&path=/dns-query&proxy=1&ecs=1\n\
                           &china-ip4=114.114.114.114/24&china-ip6=2405:2d80::/32\n\
                           &foreign-ip4=8.8.8.8/24&foreign-ip6=2001:df2:8300::/48\".\n\
  --daemon                 Daemonize.\n\
  --pid=PID_FILE_PATH      pid file, default: " DEFAULT_PID_FILE ", \n\
                           only available on daemonize.\n\
  --log=LOG_FILE_PATH      Write log to a file.\n\
  --log-level=LOG_LEVEL    Log level, range: [0, 7], default: " LOG_DEFAULT_LEVEL_NAME ".\n\
  --config=CONFIG_PATH     Config file, find sample at \n\
                           https://github.com/GangZhuo/dohclient.\n\
  --chnroute=CHNROUTE_FILE Path to china route file, \n\
                           e.g.: --chnroute=lan.txt,chnroute.txt,chnroute6.txt.\n\
  --blacklist=BLACKLIST_FILE \n\
                           Path to black list file, e.g.: --blacklist=blacklist.txt.\n\
                           The format of the file is same as chnroute file.\n\
  --hosts=HOSTS_FILE       Path to hosts file, e.g.: --hosts=/etc/hosts.\n\
  --proxy=PROXY_URL        Proxy url, e.g. --proxy=[socks5://]127.0.0.1:1080\n\
                           or --proxy=http://username:password@[::1]:80.\n\
                           Supports socks5 (no authentication) and http proxy.");
#if DOHCLIENT_CACHE_API
	printf("%s\n","\
  --cache-api=API_LIST     Enabled cache api. (get,list,put,delete,save,load)\n\
  --wwwroot=PATH           Directory path for web root.");
#endif
	printf("%s\n","\
  -v                       Verbose logging.\n\
  -h                       Show this help message and exit.\n\
  -V                       Print version and then exit.\n\
\n\
Online help: <https://github.com/GangZhuo/dohclient>\n");
}

static inline void close_after(conn_t* conn, int interval)
{
	time_t t = time(NULL);
	conn->expire = t + interval;
}

static inline int is_expired(conn_t* conn, time_t now)
{
	return conn->expire <= now;
}

static inline void close_conn(conn_t* conn)
{
	conn->status = cs_closing;
}

static inline void update_expire(conn_t* conn)
{
	close_after(conn, conf.timeout);
}

static inline void close_conn_after_rsp(conn_t* conn)
{
	conn->status = cs_rsp_closing;
}

static inline int is_close_after_rsp(conn_t* conn)
{
	return conn->status == cs_rsp_closing;
}

static int req_rbkeycmp(const void* a, const void* b)
{
	const char* x = a;
	const char* y = b;
	return strcmp(x, y);
}

/* check dns-message */
static int msg_check(ns_msg_t* msg)
{
	ns_flags_t flags;
	if (!msg ||
		msg->qdcount < 1 ||
		!msg->qrs[0].qname ||
		!msg->qrs[0].qname[0]) {
		loge("no question\n");
		return FALSE;
	}
	else if (msg->qdcount > 1) {
		logw("multi questions\n");
	}
	flags = ns_get_flags(msg);
	if (flags.qr)
		return FALSE;
	if (flags.opcode)
		return FALSE;
	if (flags.tc)
		return FALSE;
	if (msg->qrs->qtype != NS_QTYPE_A && msg->qrs->qtype != NS_QTYPE_AAAA)
		return FALSE;
	if (msg->qrs->qclass != NS_QCLASS_IN)
		return FALSE;
	return TRUE;
}

static inline const char* req_key(req_t* req)
{
	return msg_key(req->msg);
}

/* add to request dictionary */
static int reqdic_add(req_t *req, const char* key)
{
	struct rbnode_t* n;
	rbn_t* rbn;

	n = rbtree_lookup(&reqdic, (void*)key);
	if (n) {
		rbn = rbtree_container_of(n, rbn_t, node);
		dllist_add(&rbn->reqs, &req->entry_rbn);
	}
	else {
		rbn = (rbn_t*)malloc(sizeof(rbn_t));
		if (!rbn) {
			loge("alloc\n");
			return FALSE;
		}
		memset(rbn, 0, sizeof(rbn_t));
		dllist_init(&rbn->reqs);
		rbn->key = strdup(key);
		rbn->ctime = OS_GetTickCount();
		rbn->node.key = rbn->key;
		rbtree_insert(&reqdic, &rbn->node);
		dllist_add(&rbn->reqs, &req->entry_rbn);
		logd("reqdic added - %s\n", rbn->key);
	}
	return TRUE;
}

/* remove from request dictionary */
static void reqdic_remove(req_t* req, const char* key)
{
	rbn_t* rbn;

	dllist_remove(&req->entry_rbn);

	/* empty list, so remove the rb-tree node */
	if (req->entry_rbn.prev->next == req->entry_rbn.prev) {
		rbn = rbtree_container_of(req->entry_rbn.prev, rbn_t, reqs.head);
		rbtree_remove(&reqdic, &rbn->node);
		logd("reqdic removed - %s\n", rbn->key);
		free(rbn->key);
		free(rbn);
	}
}

/* find request by key */
static rbn_t* reqdic_find(const char* key)
{
	rbn_t* rbn = NULL;
	struct rbnode_t* n;

	n = rbtree_lookup(&reqdic, key);

	if (n) {
		rbn = rbtree_container_of(n, rbn_t, node);
	}

	return rbn;
}

static req_t* req_add_new(const char* data, int datalen,
	int listen,
	void* from, int fromlen, int fromtcp)
{
	req_t* req;
	const char* key;

	req = req_new(data, datalen, listen, from, fromlen, fromtcp);
	if (!req) {
		return NULL;
	}

	if (loglevel > LOG_DEBUG) {
		req_print(req);
	}

	if (!msg_check(req->msg)) {
		req_destroy(req);
		return NULL;
	}

	key = req_key(req);

	if (loglevel >= LOG_INFO) {
		logi("query %s from %s by %s\n",
			key,
			req->fromtcp
			? get_sockname(((peer_t*)req->from)->conn.sock)
			: get_addrname((struct sockaddr*)req->from),
			req->fromtcp ? "tcp" : "udp");
	}

	if (!reqdic_add(req, key)) {
		req_destroy(req);
		return NULL;
	}

	/* add to peer's request list */
	if (fromtcp) {
		peer_t* peer = from;
		dllist_add(&peer->reqs, &req->entry_peer);
	}

	/* add to global request list */
	dllist_add(&reqs, &req->entry);

	/* set expire */
	req->expire = time(NULL) + conf.timeout;

	logd("request added (id:%d) - %s\n",
		req->id,
		key);

	return req;
}

static void req_remove(req_t* req)
{
	peer_t* peer;
	const char* key;
	if (req->fromtcp) {
		peer = req->from;
		dllist_remove(&req->entry_peer);
	}
	dllist_remove(&req->entry);
	key = req_key(req);
	reqdic_remove(req, key);
	logd("request removed (id:%d) - %s\n",
		req->id,
		key);
	req_destroy(req);
}

static int req_send_result(req_t* req, ns_msg_t* msg)
{
	int len, r;

	msg->id = req->msg->id;

	if (req->fromtcp) {
		peer_t* peer = req->from;
		stream_t* ws = &peer->conn.ws;
		int pos = ws->pos,
			start = ws->size;

		ws->pos = start;

		stream_writei16(ws, 0);

		if ((len = ns_serialize(ws, msg, 0)) <= 0) {
			loge("ns_serialize() error\n");
			ws->pos = pos;
			ws->size = start;
			return -1;
		}

		stream_seti16(ws, start, len);

		ws->pos = pos;

		if (loglevel > LOG_DEBUG) {
			bprint(ws->array + ws->pos, stream_rsize(ws));
		}

		r = tcp_send(peer->conn.sock, ws);
		if (r < 0)
			return -1;
	}
	else {
		stream_t s = STREAM_INIT();
		struct sockaddr* to = (struct sockaddr*)req->from;
		int tolen = req->fromlen;
		listen_t* listen = listens + req->listen;

		if ((len = ns_serialize(&s, msg, 0)) <= 0) {
			loge("ns_serialize() error\n");
			stream_free(&s);
			return -1;
		}

		s.pos = 0;

		if (loglevel > LOG_DEBUG) {
			bprint(s.array, s.size);
		}

		r = udp_send(listen->usock, &s, to, tolen);
		stream_free(&s);
		if (r < 0)
			return -1;
	}

	return 0;
}

static void req_check_expire(time_t now)
{
	dlitem_t* cur, * nxt;
	req_t* req;
	dllist_foreach(&reqs, cur, nxt, req_t, req, entry) {
		if (req->expire > 0 && req->expire <= now) {
			loge("request timeout (id:%d) - %s %s %s\n",
				req->id,
				ns_typename(req->msg->qrs[0].qtype),
				ns_classname(req->msg->qrs[0].qclass),
				req->msg->qrs[0].qname);
			req_remove(req);
		}
		else {
			break;
		}
	}
}

typedef struct {
	int current;
} chooser_t;

static int last_choosed_channel = -1;

static channel_t *choose_channel(chooser_t *chooser)
{
	channel_t *ch = NULL;
	int i;
	if (!chooser)
		return NULL;
	switch (conf.channel_choose_mode) {
		case CHOOSE_MODE_CONCUR:
			if (chooser->current >= channel_num)
				return NULL;
			i = chooser->current++;
			ch = channels[i];
			break;
		case CHOOSE_MODE_POLL:
			if (chooser->current)
				return NULL;
			i = (++last_choosed_channel) % channel_num;
			chooser->current = i + 1;
			ch = channels[i];
			break;
		case CHOOSE_MODE_RANDOM:
		default:
			if (chooser->current)
				return NULL;
			if (channel_num > 1) {
				i = rand() % channel_num;
			}
			else {
				i = 0;
			}
			chooser->current = i + 1;
			ch = channels[i];
			break;
	}
	return ch;
}

/* get a query result */
static int _query_cb(channel_t* ctx,
	int status,
	ns_msg_t* result,
	int fromcache,
	int trust,
	void* state)
{
	const char* key;
	rbn_t* rbn;
	dlitem_t* cur, * nxt;
	req_t* req;
	int is_last_one;
	int is_add_cache = FALSE;

	/* ignore failed result */
	if (status || !result || result->qdcount < 1) {
		if (result) {
			ns_msg_free(result);
			free(result);
		}
		return 0;
	}

	key = msg_key(result);

	rbn = reqdic_find(key);

	if (rbn) {
		logi("answer: %s - %s - %s (%lu ms)\n", key, msg_answers(result),
				ctx->name, OS_GetTickCount() - rbn->ctime);
	}
	else {
		logi("drop answer: %s - %s - %s\n", key, msg_answers(result), ctx->name);
	}

	if (loglevel > LOG_DEBUG) {
		ns_print(result);
	}

	if (result && !fromcache && trust) {
		if (cache_add(cache, key, result, rbn ? TRUE : FALSE) == 0) {
			is_add_cache = TRUE;
		}
	}

	if (!rbn) {
		if (result && !fromcache) {
			ns_msg_free(result);
			free(result);
		}
		return 0;
	}

	dllist_foreach(&rbn->reqs, cur, nxt,
		req_t, req, entry_rbn) {
		is_last_one = dllist_is_end(&rbn->reqs, nxt);

		req_send_result(req, result);

		req_remove(req);
		/* after removed the last one, rbn should be destroyed,
		so we break the loop, otherwise may access a NULL point. */
		if (is_last_one)
			break;
	}

	if (result && !fromcache) {
		ns_msg_free(result);
		free(result);
	}
	return 0;
}

/* get a query result */
static int query_cb(channel_t* ctx,
	int status,
	ns_msg_t* result,
	int fromcache,
	int trust,
	void* state)
{
	return _query_cb(ctx, status, result, fromcache, trust, state);
}

static int cache_cb(channel_t* ctx,
	int status,
	ns_msg_t* result,
	int fromcache,
	int trust,
	void* state)
{
	req_t* req = state;

	if (status || !result || result->qdcount < 1) {
		chooser_t chooser[1] = {0};
		channel_t* channel;
		int n = 0, r;
		while ((channel = choose_channel(chooser)) != NULL) {
			r = channel->query(channel, req->msg, query_cb, req);
			if (r == 0) {
				n++;
			}
		}
		if (n > 0)
			return 0;
	}
	return _query_cb(ctx, status, result, fromcache, trust, state);
}

static int hosts_cb(channel_t* ctx,
	int status,
	ns_msg_t* result,
	int fromcache,
	int trust,
	void* state)
{
	req_t* req = state;

	if (status || !result || result->qdcount < 1) {
		return cache->query(cache, req->msg, cache_cb, req);
	}
	else {
		return _query_cb(ctx, status, result, fromcache, trust, state);
	}
}

/* recv a request */
static int server_recv_msg(const char *data, int datalen,
	int listen,
	void *from, int fromlen, int fromtcp)
{
	req_t* req;

#if DOHCLIENT_CACHE_API
	if (conf.cache_api) {
		int r;

		r = cache_api_try_parse(cache, data, datalen, &listens[listen],
				from, fromlen, fromtcp);
		if (r == 0) {
			return 0;
		}
		else if (r == -1) {
			return -1;
		}
	}
#endif

	req = req_add_new(data, datalen, listen, from, fromlen, fromtcp);
	if (!req) {
		return -1;
	}

	if (hosts) {
		return hosts->query(hosts, req->msg, hosts_cb, req);
	}
	else {
		return cache->query(cache, req->msg, cache_cb, req);
	}
}

static int server_udp_recv(int listen_index)
{
	listen_t* ctx = listens + listen_index;
	sock_t sock = ctx->usock;
	int nread;
	char buffer[NS_PAYLOAD_SIZE + 1];
	struct sockaddr_storage from = { 0 };
	int fromlen = sizeof(struct sockaddr_storage);

	nread = udp_recv(sock, buffer, sizeof(buffer),
		(struct sockaddr*) & from, &fromlen);

	if (nread == -1)
		return -1;

	if (nread == 0)
		return 0;

	logv("server  recv %d bytes - %s \tproto:udp\n",
		nread, get_addrname((struct sockaddr*) & from));

	if (loglevel > LOG_DEBUG) {
		bprint(buffer, nread);
	}

	if (nread > NS_PAYLOAD_SIZE) {
		loge("too large dns-message\n");
		return -1;
	}

	buffer[nread] = '\0'; /* so, can print as string */

	if (server_recv_msg(buffer, nread, listen_index, &from, fromlen, FALSE)) {
		return -1;
	}

	return 0;
}

static int peer_accept(int listen_index)
{
	listen_t* ctx = listens + listen_index;
	sock_t sock;
	sockaddr_t from = {
		.addr = {0},
		.addrlen = sizeof(struct sockaddr_storage),
	};
	peer_t* peer;

	sock = accept(ctx->sock, (struct sockaddr*) & from.addr, &from.addrlen);
	if (sock == -1) {
		loge("accept() error: errno=%d, %s \n",
			errno, strerror(errno));
		return -1;
	}
	logv("server  accept - %s\n", get_sockaddrname(&from));

	if (setnonblock(sock) != 0) {
		loge("set sock non-block failed\n");
		close(sock);
		return -1;
	}

	if (setnodelay(sock) != 0) {
		loge("set sock nodelay failed\n");
		close(sock);
		return -1;
	}

	peer = peer_new(sock, listen_index);
	if (!peer) {
		close(sock);
		return -1;
	}

	dllist_add(&peers, &peer->conn.entry);

	update_expire(&peer->conn);

	return 0;
}

static int peer_handle_recv(peer_t* peer)
{
	stream_t* s = &peer->conn.rs;
	int msglen, left;

#if DOHCLIENT_CACHE_API
	if (conf.cache_api && peer->is_hs) {
		return hs_onrecv(peer);
	}
#endif

	while ((left = stream_rsize(s)) >= 6) {
		msglen = stream_geti(s, s->pos, 2);
		if (msglen > NS_PAYLOAD_SIZE) {
#if DOHCLIENT_CACHE_API
			if (conf.cache_api && hs_can_parse(s->array + s->pos)) {
				return hs_onrecv(peer);
			}
			else
#endif
			{
				loge("too large dns-message (msglen=0x%.4x)\n", msglen);
				return -1;
			}
		}
		else if (left >= (msglen + 2)) {
			if (server_recv_msg(s->array + s->pos + 2, msglen, peer->listen, peer, 0, TRUE)) {
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
			loge("stream_quake() failed\n");
			return -1;
		}
	}

	return 0;
}

static int peer_recv(peer_t* peer)
{
	sock_t sock = peer->conn.sock;
	stream_t* s = &peer->conn.rs;
	char* buffer;
	int buflen, nread;

	buflen = s->cap - s->size;

	/* 2 bytes for length of dns-message, 1 byte for '\0' */
	if (buflen < NS_PAYLOAD_SIZE + 3) {
		if (stream_set_cap(s, s->size + NS_PAYLOAD_SIZE + 3)) {
			return -1;
		}
		buflen = s->cap - s->size - 1; /* reserve 1 bytes for '\0' */
	}

	buffer = s->array + s->size;

	nread = tcp_recv(sock, buffer, buflen);

	if (nread == -1)
		return -1;

	if (nread == 0)
		return 0;

	s->size += nread;

	s->array[s->size] = '\0'; /* so we can print as string */

	peer->conn.rx += nread;

	logv("server  recv %d bytes - %s \tproto:tcp\n",
		nread, get_sockname(peer->conn.sock));

	if (loglevel > LOG_DEBUG) {
		bprint(buffer, nread);
	}

	if (peer_handle_recv(peer)) {
		return -1;
	}

	update_expire(&peer->conn);

	return 0;
}

static int peer_write(peer_t* peer)
{
	sock_t sock = peer->conn.sock;
	stream_t* s = &peer->conn.ws;
	int nsend;

	nsend = tcp_send(sock, s);

	if (nsend == -1)
		return -1;

	if (nsend == 0)
		return 0;

	peer->conn.tx += nsend;

	logv("write to %s\n", get_sockname(sock));

	if (is_close_after_rsp(&peer->conn)) {
		/* wait 3 seconds */
		close_after(&peer->conn, 3);
	}
	else {
		update_expire(&peer->conn);
	}

	return 0;
}

static void peer_close(peer_t* peer)
{
	dlitem_t* cur, * nxt;
	req_t* req;
	dllist_remove(&peer->conn.entry);
	dllist_foreach(&peer->reqs, cur, nxt,
		req_t, req, entry_peer) {
		req_remove(req);
	}
#if DOHCLIENT_CACHE_API
	if (peer->hsctx)
		hsctx_free(peer->hsctx);
#endif
	peer_destroy(peer);
}

static int do_loop()
{
	fd_set readset, writeset, errorset;
	sock_t max_fd, fd;
	int i, r;
	time_t now;

	dlitem_t* cur, * nxt;
	peer_t* peer;
	listen_t* listen;

	int is_local_sending;
	int is_closing;

	struct timeval timeout;

	running = 1;
	while (running) {

		FD_ZERO(&readset);
		FD_ZERO(&writeset);
		FD_ZERO(&errorset);

		max_fd = 0;

		for (i = 0; i < listen_num; i++) {
			listen = listens + i;

			if (!running) break;

			max_fd = MAX(max_fd, listen->sock);

			FD_SET(listen->sock, &readset);
			FD_SET(listen->sock, &errorset);

			max_fd = MAX(max_fd, listen->usock);

			FD_SET(listen->usock, &readset);
			FD_SET(listen->usock, &errorset);
		}

		dllist_foreach(&peers, cur, nxt, peer_t, peer, conn.entry) {

			if (!running) break;

			max_fd = MAX(max_fd, peer->conn.sock);
			is_local_sending = stream_rsize(&peer->conn.ws) > 0;
			is_closing = peer->conn.status == cs_closing ||
				peer->conn.status == cs_rsp_closing;
			if (is_local_sending)
				FD_SET(peer->conn.sock, &writeset);
			/* read when request header is not complete,
			   or remote connection established and not sending data */
			else if (!is_closing)
				FD_SET(peer->conn.sock, &readset);
			FD_SET(peer->conn.sock, &errorset);
		}

		if (!running) break;

		fd = cache->fdset(cache, &readset, &writeset, &errorset);
		if (fd < 0) {
			return -1;
		}

		max_fd = MAX(max_fd, fd);

		for (i = 0; i < channel_num; i++) {
			fd = channels[i]->fdset(channels[i], &readset, &writeset, &errorset);
			if (fd < 0) {
				return -1;
			}
			max_fd = MAX(max_fd, fd);
		}

		timeout.tv_sec = 0;
		timeout.tv_usec = 50 * 1000;

		if (select(max_fd + 1, &readset, &writeset, &errorset, &timeout) == -1) {
			if (errno == EINTR) {
				logd("select(): errno=%d, %s \n", errno, strerror(errno));
				if (!running)
					break;
				continue;
			}
			else {
				loge("select() error: errno=%d, %s \n",
					errno, strerror(errno));
				return -1;
			}
		}

		if (!running) break;

		now = time(NULL);

		for (i = 0; i < listen_num; i++) {
			listen = listens + i;

			if (!running) break;

			if (FD_ISSET(listen->sock, &errorset)) {
				loge("listen.sock error\n");
				return -1;
			}

			if (FD_ISSET(listen->usock, &errorset)) {
				loge("listen.usock error\n");
				return -1;
			}

			if (FD_ISSET(listen->sock, &readset)) {
				r = peer_accept(i);
			}

			if (FD_ISSET(listen->usock, &readset)) {
				r = server_udp_recv(i);
			}
		}

		dllist_foreach(&peers, cur, nxt, peer_t, peer, conn.entry) {

			if (!running) break;

			if (FD_ISSET(peer->conn.sock, &errorset)) {
				int err = getsockerr(peer->conn.sock);
				loge("peer.conn.sock error: errno=%d, %s \n",
					err, strerror(err));
				r = -1;
			}
			else if (FD_ISSET(peer->conn.sock, &readset)) {
				r = peer_recv(peer);
			}
			else if (FD_ISSET(peer->conn.sock, &writeset)) {
				r = peer_write(peer);
			}
			else {
				r = 0;
			}

			if (!running) break;

			if (!r &&
#if DOHCLIENT_CACHE_API
					!peer->keep_alive &&
#endif
					is_expired(&peer->conn, now)) {
				loge("peer timeout - %s\n", get_sockname(peer->conn.sock));
				r = -1;
			}

			if (r) {
				peer_close(peer);
				continue;
			}
		}

		req_check_expire(now);

		r = cache->step(cache, &readset, &writeset, &errorset);
		if (r) {
			return -1;
		}

		for (i = 0; i < channel_num; i++) {
			r = channels[i]->step(channels[i], &readset, &writeset, &errorset);
			if (r) {
				return -1;
			}
		}
	}

	return 0;
}

static int init_dohclient()
{
	int i;
	char** ch, ** args;

	srand((unsigned int)time(NULL));

#ifdef WINDOWS
	if (0 == SetConsoleCtrlHandler((PHANDLER_ROUTINE)sig_handler, TRUE)) {
		loge("can not set control handler\n");
		return EXIT_FAILURE;
	}
#else
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
#endif

	if (conf.log_file && *conf.log_file) {
		open_logfile(conf.log_file);
	}
	else if (conf.launch_log && *conf.launch_log) {
		open_logfile(conf.launch_log);
	}

	if (!conf.is_config_file_readed && conf.config_file && *conf.config_file) {
		if (conf_load_from_file(&conf, conf.config_file, FALSE)) {
			return -1;
		}
		conf.is_config_file_readed = 1;
		if (conf.log_file && *conf.log_file) {
			open_logfile(conf.log_file);
		}
	}

	if (conf_check(&conf))
		return -1;

	loglevel = conf.log_level;

	if (conf.proxy && *conf.proxy) {
		proxy_num = str2proxies(
			conf.proxy,
			proxy_list,
			MAX_PROXY);
		if (proxy_num == -1) {
			loge("parse \"%s\" failed\n",
				conf.proxy);
			return -1;
		}
		for (i = 0; i < proxy_num; i++) {
			proxy_list[i].proxy_index = i;
		}
	}

	if (conf.chnroute && *conf.chnroute) {
		if ((chnr = chnroute_create()) == NULL) {
			loge("chnroute_create()\n");
			return -1;
		}
		if (chnroute_parse(chnr, conf.chnroute)) {
			loge("invalid chnroute \"%s\"\n", conf.chnroute);
			return -1;
		}
	}

	if (conf.blacklist && *conf.blacklist) {
		if ((blacklist = chnroute_create()) == NULL) {
			loge("chnroute_create()\n");
			return -1;
		}
		if (chnroute_parse(blacklist, conf.blacklist)) {
			loge("invalid blacklist \"%s\"\n", conf.blacklist);
			return -1;
		}
	}

	if (conf.hosts && *conf.hosts) {
		int argslen = strlen(conf.hosts) + sizeof("hosts=");
		char *args = (char*)malloc(argslen);
		if (!args) {
			loge("alloc\n");
			return -1;
		}
		snprintf(args, argslen, "hosts=%s", conf.hosts);
		if (channel_create(&hosts, "hosts", args,
			&conf, proxy_list, proxy_num, chnr, blacklist, NULL) != CHANNEL_OK) {
			loge("create \"hosts\" channel error\n");
			free(args);
			return -1;
		}
		free(args);
	}

	if (http_init(&conf) != 0) {
		loge("http_init() error\n");
		return -1;
	}

	if (channel_create(&cache, "cache", NULL,
		&conf, proxy_list, proxy_num, chnr, blacklist, NULL) != CHANNEL_OK) {
		loge("create cache error\n");
		return -1;
	}

#if DOHCLIENT_CACHE_API
	hsconf->cache = cache;
	hsconf->wwwroot = conf.wwwroot;
	if (conf.cache_api && *conf.cache_api) {
		if (cache_api_config(conf.cache_api) != 0) {
			loge("cache_api_config() error\n");
			return -1;
		}
	}
#endif

	ch = conf.channels;
	while (ch && *ch) {
		ch++;
		channel_num++;
	}

	channels = (channel_t**)malloc(sizeof(channel_t*) * channel_num);
	if (!channels) {
		loge("create channels\n");
		return -1;
	}

	ch = conf.channels;
	args = conf.channel_args;
	i = 0;
	while (ch && *ch) {
		if (channel_create(
			&channels[i], *ch, *args,
			&conf, proxy_list, proxy_num, chnr, blacklist, NULL) != CHANNEL_OK) {
			loge("no channel\n");
			return -1;
		}
		ch++;
		args++;
		i++;
	}

	listen_num = str2listens(
		conf.listen_addr,
		listens,
		MAX_LISTEN,
		sizeof(listen_t),
		conf.listen_port);

	if (listen_num < 0)
		return -1;

	if (listen_num == 0) {
		loge("no listens\n");
		return -1;
	}

	if (init_listens(listens, listen_num) != 0)
		return -1;

	print_listens(listens, listen_num);
	conf_print(&conf);

	if (conf.cachedb_autosave && (*conf.cachedb_autosave) && cache) {
		save_cache_when_close = 1;
		logn("Set service flags to save cache to \"%s\" when service closing\n",
				conf.cachedb_autosave);
	}

	if (conf.cachedb && *conf.cachedb) {
		cache_load_cachedbs(cache, conf.cachedb, 0);
	}

	return 0;
}

static void uninit_dohclient()
{
	dlitem_t* cur, * nxt;
	peer_t* peer;
	req_t* req;
	int i;

	for (i = 0; i < listen_num; i++) {
		listen_t* listen = listens + i;
		if (listen->sock)
			close(listen->sock);
		if (listen->usock)
			close(listen->usock);
	}

	listen_num = 0;

	dllist_foreach(&peers, cur, nxt,
		peer_t, peer, conn.entry) {
		peer_close(peer);
	}

	dllist_foreach(&reqs, cur, nxt,
		req_t, req, entry) {
		req_remove(req);
	}

	rbtree_init(&reqdic, req_rbkeycmp);

	if (channels) {
		for (i = 0; i < channel_num; i++) {
			channels[i]->destroy(channels[i]);
		}
		free(channels);
		channels = NULL;
		channel_num = 0;
	}

	if (cache) {
		if (save_cache_when_close) {
			cache_save_cachedb(cache, conf.cachedb_autosave);
		}
		cache->destroy(cache);
		cache = NULL;
	}

	if (hosts) {
		hosts->destroy(hosts);
		hosts = NULL;
	}

	chnroute_free(chnr);
	chnr = NULL;

	chnroute_free(blacklist);
	blacklist = NULL;

	proxy_num = 0;

	http_uninit();

	if (is_use_logfile()) {
		close_logfile();
	}

	if (is_use_syslog()) {
		close_syslog();
	}
}

#ifdef WINDOWS

BOOL WINAPI sig_handler(DWORD signo)
{
	switch (signo) {
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
	case CTRL_CLOSE_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:
		running = 0;
		break;
	default:
		break;
	}
	return TRUE;
}

static void ServiceMain(int argc, char** argv)
{
	BOOL bRet;
	bRet = TRUE;

	hStatus = RegisterServiceCtrlHandler(DOHCLIENT_NAME, (LPHANDLER_FUNCTION)ControlHandler);
	if (hStatus == (SERVICE_STATUS_HANDLE)0)
	{
		loge("Cannot register service ctrl handler\n");
		return;
	}

	{
		const char* wd = win_get_exe_path();
		SetCurrentDirectory(wd);
		logn("Set working directory: %s\n", wd);
	}

	if (init_dohclient() != 0) {
		ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
		ServiceStatus.dwServiceSpecificExitCode = ERROR_SERVICE_NOT_ACTIVE;
		goto exit;
	}

	ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(hStatus, &ServiceStatus);

	if (do_loop() != 0) {
		ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
		ServiceStatus.dwServiceSpecificExitCode = ERROR_SERVICE_NOT_ACTIVE;
		goto exit;
	}

  exit:
	uninit_dohclient();

	conf_free(&conf);

	ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	SetServiceStatus(hStatus, &ServiceStatus);
}

static void ControlHandler(DWORD request)
{
	switch (request) {
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:
		running = 0;
		break;
	default:
		SetServiceStatus(hStatus, &ServiceStatus);
		break;
	}
}

#else

static void sig_handler(int signo)
{
	if (signo == SIGINT)
		exit(1);  /* for gprof*/
	else
		running = 0;
}

#endif

static void run_as_daemonize()
{
#ifdef WINDOWS
	SERVICE_TABLE_ENTRY ServiceTable[2];

	ServiceTable[0].lpServiceName = DOHCLIENT_NAME;
	ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

	ServiceTable[1].lpServiceName = NULL;
	ServiceTable[1].lpServiceProc = NULL;

	if (!StartServiceCtrlDispatcher(ServiceTable)) {
		loge("Cannot start service ctrl dispatcher\n");
	}
#else
	pid_t pid, sid;
	int dev_null;

	if (!conf.pid_file) {
		conf.pid_file = strdup(DEFAULT_PID_FILE);
	}

	pid = fork();
	if (pid < 0) {
		exit(1);
	}

	if (pid > 0) {
		if (conf.pid_file) {
			FILE* file = fopen(conf.pid_file, "w");
			if (file == NULL) {
				logc("Invalid pid file: %s\n", conf.pid_file);
				exit(1);
			}
			fprintf(file, "%d", (int)pid);
			fclose(file);
		}
		
		exit(0);
	}

	if (init_dohclient() != 0)
		exit(1);

	umask(0);

	if (!conf.log_file || !(*conf.log_file)) {
		open_syslog(DOHCLIENT_NAME);
	}

	sid = setsid();
	if (sid < 0) {
		exit(1);
	}

	if ((chdir("/")) < 0) {
		exit(1);
	}

	dev_null = open("/dev/null", O_WRONLY);
	if (dev_null) {
		dup2(dev_null, STDOUT_FILENO);
		dup2(dev_null, STDERR_FILENO);
	}
	else {
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	close(STDIN_FILENO);

	if (do_loop() != 0)
		exit(1);

	uninit_dohclient();

	conf_free(&conf);

#endif
}

int main(int argc, char** argv)
{
#ifdef WINDOWS
	win_init();
	log_init();
#endif

	conf.log_level = loglevel;

	if (conf_parse_args(&conf, argc, argv) != 0) {
		usage();
		exit(-1);
		return EXIT_FAILURE;
	}

	if (conf.is_print_help) {
		usage();
		exit(0);
		return EXIT_SUCCESS;
	}

	if (conf.is_print_version) {
		printf(DOHCLIENT_NAME " %s\n", DOHCLIENT_VERSION);
		exit(0);
		return EXIT_SUCCESS;
	}

	loglevel = conf.log_level;

	if (conf.daemonize) {
		run_as_daemonize();
		return EXIT_SUCCESS;
	}

	if (init_dohclient() != 0)
		return EXIT_FAILURE;

	if (do_loop() != 0)
		return EXIT_FAILURE;

	uninit_dohclient();

	conf_free(&conf);

	print_leak();

	return EXIT_SUCCESS;
}
