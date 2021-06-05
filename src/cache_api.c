#if DOHCLIENT_CACHE_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cache_api.h"
#include "log.h"
#include "stream.h"
#include "ns_msg.h"
#include "channel_cache.h"

typedef struct api_ctx_t api_ctx_t;
typedef struct api_data_t api_data_t;
typedef struct cache_api_t cache_api_t;
typedef int (*api_f)(api_ctx_t *ctx);

struct cache_api_t {
	const char *name;
	api_f       f;
};

struct api_ctx_t {
	channel_t   *cache;
	cache_api_t *api;
	api_data_t  *api_data;
	const char  *data;
	int          datalen;
	listen_t    *listen;
	void        *from;
	int          fromlen;
	int          fromtcp;
};

struct api_data_t {
	char        name[10];
	const char *data;
	int         datalen;
};

static int cache_api_list(api_ctx_t *ctx);

static int cache_api_get(api_ctx_t *ctx);

static int cache_api_put(api_ctx_t *ctx);

static int cache_api_delete(api_ctx_t *ctx);

static cache_api_t apis[] = {
	{ "GET",    cache_api_get },      /* UDP: "GET 'IN A www.baidu.com.'" */
	{ "LIST",   cache_api_list },     /* UDP: "LIST" */
	{ "PUT",    cache_api_put },      /* UDP: "PUT www.baidu.com. A 180.101.49.11 289" */
	{ "DELETE", cache_api_delete },   /* UDP: "DELETE 'IN A www.baidu.com.'" */
};

typedef struct range {
	const char *start;
	const char *end;
} range;

static const char *findstr(range *rg, const char *start, const char *end)
{
	const char *p = start;
	char delim = ' ';

	/* Skip space */
	while (p < end && *p == ' ') p++;

	if (p < end && (*p == '"' || *p == '\'')) {
		delim = *p++;
	}

	rg->start = p;

	while (p < end) {
		if (*p == delim) {
			rg->end = p;
			return p;
		}
		p++;
	}

	rg->end = p;

	return p;
}

static const char *copystr(char *buf, int buflen,
		const char *start, const char *end)
{
	const char *p;
	range rg[1] = {0};

	if (start >= end)
		return end;

	p = findstr(rg, start, end);
	strncpy(buf, rg->start, MIN(buflen - 1, rg->end - rg->start));

	if (p < end)
		p++;

	return p;
}

static int nsmsg_write_as_json(stream_t *s, const ns_msg_t *msg)
{
	int r;
	r = stream_appendf(s, "{\"key\":\"%s\",\"answers\":\"%s\"}",
			msg_key(msg), msg_answers(msg));
	if (r == -1) {
		loge("nsmsg_write_as_json() error: Alloc\n");
	}
	return r;
}

static char *nsmsg2json(const ns_msg_t *msg)
{
	stream_t s[1] = {0};
	int r;
	r = nsmsg_write_as_json(s, msg);
	if (r == -1) {
		loge("nsmsg2json() error: Alloc\n");
		stream_free(s);
		return NULL;
	}
	return s->array;
}

static char *jsonmsgwrap(int err, const char *msg, const char *data)
{
	stream_t s[1] = {0};
	int r;
	r = stream_writef(s, "{\"error\":%d,\"msg\":\"%s\",\"data\":%s}",
			err, msg ? msg : "",  data ? data : "null");
	if (r == -1) {
		loge("jsonmsgwrap() error: Alloc\n");
		stream_free(s);
		return NULL;
	}
	return s->array;
}

static int cache_api_send_result(api_ctx_t *ctx, const char *json)
{
	int r;

	if (ctx->fromtcp) {
		peer_t *peer = ctx->from;
		stream_t *s = &peer->conn.ws;
		int pos = s->pos, r;

		/* Write begin the end of the stream */
		s->pos = s->size;

		if (stream_writei16(s, strlen(json)) == -1) {
			loge("cache_api_send_result() error: alloc\n");
			return -1;
		}

		if (stream_writes(s, json, strlen(json)) == -1) {
			loge("cache_api_send_result() error: alloc\n");
			return -1;
		}

		/* Restore Position */
		s->pos = pos;

		if (loglevel > LOG_DEBUG) {
			bprint(s->array + s->pos, stream_rsize(s));
		}

		r = tcp_send(peer->conn.sock, s);
		if (r < 0)
			return -1;
	}
	else {
		stream_t s[1] = {STREAM_INIT()};
		struct sockaddr *to = (struct sockaddr*)ctx->from;
		int tolen = ctx->fromlen;
		listen_t *listen = ctx->listen;

		if (stream_writes(s, json, strlen(json)) == -1) {
			loge("cache_api_send_result() error: alloc\n");
			stream_free(s);
			return -1;
		}

		s->pos = 0;

		if (loglevel > LOG_DEBUG) {
			bprint(s->array, s->size);
		}

		r = udp_send(listen->usock, s, to, tolen);
		stream_free(s);
		if (r < 0)
			return -1;
	}

	logd("api result: %s\n", json);

	return 0;
}

struct each_state {
	api_ctx_t *ctx;
	stream_t  *s;
};

static int cb_each(const ns_msg_t *msg, void *data)
{
	struct each_state *st = data;
	stream_t *s = st->s;

	if (s->size > 1) {
		if (stream_appends(s, ",", 1) == -1) {
			loge("cache_api_list() error: alloc\n");
			return -1;
		}
	}

	if (nsmsg_write_as_json(s, msg) == -1) {
		loge("cache_api_list() error: alloc\n");
		return -1;
	}

	return 0;
}

static int cache_api_list(api_ctx_t *ctx)
{
	stream_t s[1] = {0};
	struct each_state st[1] = {
		{ .ctx = ctx, .s = s, }
	};
	int r;

	if (stream_appends(s, "[", 1) == -1) {
		loge("cache_api_list() error: alloc\n");
		stream_free(s);
		return -1;
	}

	if (cache_each(ctx->cache, cb_each, st) == -1) {
		loge("cache_api_list() error: alloc\n");
		stream_free(s);
		return -1;
	}

	if (stream_appends(s, "]", 1) == -1) {
		loge("cache_api_list() error: alloc\n");
		stream_free(s);
		return -1;
	}

	r = cache_api_send_result(ctx, s->array);
	stream_free(s);

	return r;
}

static int cache_api_get(api_ctx_t *ctx)
{
	api_data_t *d = ctx->api_data;
	char key[REQ_KEY_SIZE] = {0};
	const ns_msg_t *msg;
	char *json = NULL;
	int r;

	copystr(key, sizeof(key), d->data, d->data + d->datalen);

	if (!*key) {
		json = jsonmsgwrap(CACHE_API_EARG, "No Cache Key", NULL);
	}
	else if ((msg = cache_get(ctx->cache, key)) != NULL) {
		char *d = nsmsg2json(msg);
		if (d) {
			json = jsonmsgwrap(CACHE_API_OK, "OK", d);
			free(d);
		}
	}
	else {
		json = jsonmsgwrap(CACHE_API_ENOTFOUND, "Not Found", NULL);
	}

	if (!json) {
		loge("cache_api_get() error: failed to create json\n");
		return -1;
	}

	r = cache_api_send_result(ctx, json);
	free(json);

	return r;
}

static int cache_api_put(api_ctx_t *ctx)
{
	api_data_t *d = ctx->api_data;
	char name[NS_NAME_SIZE] = {0};
	char type[8] = {0}; /* A|AAAA */
	char ttl[8] = {0};
	char ip[INET6_ADDRSTRLEN + 1] = {0};
	const char *p = d->data;
	const char *e = d->data + d->datalen;
	char *json = NULL;
	int namelen;
	int r;

	p = copystr(name, sizeof(name), p, e);
	p = copystr(type, sizeof(type), p, e);
	p = copystr(ip,   sizeof(ip),   p, e);
	p = copystr(ttl,  sizeof(ttl),  p, e);

	logd("name: %s\n", name);
	logd("type: %s\n", type);
	logd("ip:   %s\n", ip);
	logd("ttl:  %s\n", ttl);

	namelen = strlen(name);

	if (namelen == 0 ||
			(name[namelen - 1] != '.' && namelen + 1 == sizeof(name)) ||
			!*type ||
			!*ip ||
			(strcasecmp(type, "A") && strcasecmp(type, "AAAA"))) {
		json = jsonmsgwrap(CACHE_API_EARG, "Invalid Arguments", NULL);
	}
	else {
		int family = !strcasecmp(type, "A") ? AF_INET : AF_INET6;
		int tl = *ttl ? atoi(ttl) : INT32_MAX;
		sockaddr_t addr[1] = {0};

		if (tl <= 0)
			tl = INT32_MAX;

		if (name[namelen - 1] != '.') {
			name[namelen++] = '.';
			name[namelen] = '\0';
		}

		if (family == AF_INET && !try_parse_as_ip4(addr, ip, "53")) {
			json = jsonmsgwrap(CACHE_API_EARG, "Invalid IPv4", NULL);
		}
		else if (family == AF_INET6 && !try_parse_as_ip6(addr, ip, "53")) {
			json = jsonmsgwrap(CACHE_API_EARG, "Invalid IPv6", NULL);
		}
		else {
			ns_msg_t msg[1] = { 0 };
			ns_qr_t  qr[1]  = { 0 };
			ns_rr_t  an[1]  = { 0 };
			ns_flags_t flags = { 0 };

			msg->id = 0;
			flags.qr = 1;
			flags.opcode = 0;
			flags.aa = 0;
			flags.tc = 0;
			flags.ra = 1;
			flags.z = 0;
			flags.rcode = 0;
			ns_set_flags(msg, &flags);

			logd("value: %x %d\n", msg->flags, flags.qr);
		
			msg->qdcount = 1;
			msg->qrs = qr;
		
			msg->ancount = 1;
			msg->rrs = an;
		
			qr->qname = name;
			qr->qclass = NS_QCLASS_IN;
			qr->qtype = family == AF_INET ? NS_QTYPE_A : NS_QTYPE_AAAA;
		
			an->name = qr->qname;
			an->type = qr->qtype;
			an->cls = qr->qclass;
			an->ttl = tl;
			an->rdlength = family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr);
			an->rdata = family == AF_INET ?
				(void*)&((struct sockaddr_in*)&addr->addr)->sin_addr :
				(void*)&((struct sockaddr_in6*)&addr->addr)->sin6_addr;

			if (cache_add(ctx->cache, msg_key(msg), msg, TRUE)) {
				json = jsonmsgwrap(CACHE_API_EALLOC, "Invalid IPv6", NULL);
			}
			else {
				json = jsonmsgwrap(CACHE_API_OK, "OK", NULL);
			}
		}
	}

	r = cache_api_send_result(ctx, json);
	free(json);

	return r;
}

static int cache_api_delete(api_ctx_t *ctx)
{
	api_data_t *d = ctx->api_data;
	char key[REQ_KEY_SIZE] = {0};
	char *json = NULL;
	int r;

	copystr(key, sizeof(key), d->data, d->data + d->datalen);

	if (!*key) {
		json = jsonmsgwrap(CACHE_API_EARG, "No Cache Key", NULL);
	}
	else if (cache_remove(ctx->cache, key) == 0) {
		json = jsonmsgwrap(CACHE_API_OK, "OK", NULL);
	}
	else {
		json = jsonmsgwrap(CACHE_API_ENOTFOUND, "Not Found", NULL);
	}

	if (!json) {
		loge("cache_api_delete() error: failed to create json\n");
		return -1;
	}

	r = cache_api_send_result(ctx, json);
	free(json);

	return r;
}

static cache_api_t *cache_api_find(const char *data, int datalen)
{
	int i;
	cache_api_t *api;
	for (i = 0; i < sizeof(apis) / sizeof(apis[0]); i++) {
		api = &apis[i];
		if (datalen >= strlen(api->name) &&
				!strncasecmp(api->name, data, strlen(api->name))) {
			return api;
		}
	}
	return NULL;
}

static int api_data_parse(api_data_t *d, const char *data, int datalen)
{
	const char *p = data;
	const char *e = data + datalen;
	p = copystr(d->name, sizeof(d->name), p, e);
	d->data = p;
	d->datalen = e - p;
	return 0;
}

int cache_api_try_parse(channel_t *cache, const char *data, int datalen,
	listen_t *listen,
	void *from, int fromlen, int fromtcp)
{
	cache_api_t *api;
	api_ctx_t ctx[1] = {0};
	api_data_t api_data[1] = {0};
	api = cache_api_find(data, datalen);
	if (api == NULL)
		return 1;
	logd("cache api: %s\n", api->name);
	if (api_data_parse(api_data, data, datalen)) {
		return -1;
	}
	ctx->cache = cache;
	ctx->api = api;
	ctx->api_data = api_data;
	ctx->data = data;
	ctx->datalen = datalen;
	ctx->listen = listen;
	ctx->from = from;
	ctx->fromlen = fromlen;
	ctx->fromtcp = fromtcp;
	return api->f(ctx);
}
#endif