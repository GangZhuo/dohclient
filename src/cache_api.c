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
	char        mime[50];
	const char *data;
	int         datalen;
};

static int cache_api_list(api_ctx_t *ctx);

static int cache_api_get(api_ctx_t *ctx);

static int cache_api_put(api_ctx_t *ctx);

static int cache_api_delete(api_ctx_t *ctx);

static cache_api_t apis[] = {
	{ "GET",    cache_api_get },
	{ "PUT",    cache_api_put },
	{ "DELETE", cache_api_delete },
};

static const char *find_space(const char *start, const char *end)
{
	const char *p = start;
	while (p < end) {
		if (*p == ' ') {
			return p;
		}
		p++;
	}
	return p;
}

static const char *copy_to_space(char *buf, int buflen,
		const char *start, const char *end)
{
	const char *p;

	if (start >= end)
		return end;

	p = find_space(start, end);
	strncpy(buf, start, MIN(buflen - 1, p - start));

	if (p < end)
		p++;

	return p;
}

static int ns_write_json(stream_t *s, const ns_msg_t *msg)
{
	return 0;
}

static int cache_api_list(api_ctx_t *ctx)
{
	return 0;
}

static int cache_api_get(api_ctx_t *ctx)
{
	api_data_t *d = ctx->api_data;
	const ns_msg_t *msg;
	if (d->datalen == 0 || !*d->data)
		return cache_api_list(ctx);
	msg = cache_get(ctx->cache, d->data);
	if (ctx->fromtcp) {
		peer_t *peer = ctx->from;
		stream_t *s = &peer->conn.ws;
		int pos = s->pos,
			start = s->size,
			r;

		s->pos = start;
		
		if (stream_writei16(s, 0) == -1)
			return -1;

		if (msg) {
			if (ns_write_json(s, msg))
				return -1;
		}
		else {
		}

		stream_seti16(s, 0, s->size - 2);

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
	}
	return 0;
}

static int cache_api_put(api_ctx_t *ctx)
{
	return 0;
}

static int cache_api_delete(api_ctx_t *ctx)
{
	return 0;
}

static cache_api_t *cache_api_find(const char *data, int datalen)
{
	int i;
	cache_api_t *api;
	for (i = 0; i < sizeof(apis) / sizeof(apis[0]); i++) {
		api = &apis[i];
		if (datalen >= strlen(api->name) &&
				strncasecmp(api->name, data, strlen(api->name))) {
			return api;
		}
	}
	return NULL;
}

static int api_data_parse(api_data_t *d, const char *data, int datalen)
{
	const char *p = data;
	const char *e = data + datalen;

	p = copy_to_space(d->name, sizeof(d->name), p, e);
	p = copy_to_space(d->mime, sizeof(d->mime), p, e);

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
