#include "channel_cache.h"
#include "../rbtree/rbtree.h"
#include "mleak.h"

#define _M
#define REQ_KEY_SIZE (NS_QNAME_SIZE + NS_QTYPE_NAME_SIZE + NS_QCLASS_NAME_SIZE)

#define CACHEDB_HEAD_SIZE 24
#define CACHEDB_MAGIC     "DCDB"
#define CACHEDB_VERSION   1

typedef struct cache_t {
	CHANNEL_BASE(_M)
	dllist_t items;
	struct rbtree_t dic;
} cache_t;

typedef struct cache_item_t {
	struct rbnode_t node;
	dlitem_t entry;
	ns_msg_t* msg;
	time_t expire;
} cache_item_t;

static int rbkeycmp(const void* a, const void* b)
{
	const char* x = a;
	const char* y = b;
	return strcmp(x, y);
}

static cache_item_t* cache_item_new(const ns_msg_t* msg, const char *key)
{
	cache_item_t* item;

	item = (cache_item_t*)malloc(sizeof(cache_item_t));
	if (!item) {
		loge("alloc\n");
		return NULL;
	}

	memset(item, 0, sizeof(cache_item_t));

	item->msg = ns_msg_clone(msg);
	if (!item->msg) {
		loge("ns_msg_clone() error\n");
		return NULL;
	}

	item->node.key = strdup(key);

	return item;
}

static void cache_item_destroy(cache_item_t* item)
{
	if (item) {
		free(item->node.key);
		ns_msg_free(item->msg);
		free(item->msg);
		free(item);
	}
}

static void cache_item_add(cache_t* c, cache_item_t* item)
{
	dlitem_t* cur, * nxt;
	cache_item_t* p;

	/* TODO: Use Heap Data Structure, see https://en.wikipedia.org/wiki/Heap_(data_structure) */
	dllist_foreach(&c->items, cur, nxt,
		cache_item_t, p, entry) {
		
		if (p->expire >= item->expire) {
			dllist_add_before(&p->entry, &item->entry);
			return;
		}
	}

	dllist_add(&c->items, &item->entry);
}

static void cache_check_expire(cache_t* c)
{
	dlitem_t* cur, * nxt;
	cache_item_t* item;
	time_t now = time(NULL);

	dllist_foreach(&c->items, cur, nxt,
		cache_item_t, item, entry) {

		if (item->expire <= now) {
			logi("cache timeout - %s\n", item->node.key);
			dllist_remove(&item->entry);
			rbtree_remove(&c->dic, &item->node);
			cache_item_destroy(item);
		}
		else {
			break;
		}
	}
}

static void destroy(channel_t* ctx)
{
	cache_t* c = (cache_t*)ctx;
	dlitem_t* cur, * nxt;
	cache_item_t* item;
	dllist_foreach(&c->items, cur, nxt,
		cache_item_t, item, entry) {
		dllist_remove(&item->entry);
		cache_item_destroy(item);
	}
	c->dic.root = NULL;
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
	cache_t* c = (cache_t*)ctx;
	if (c->conf->cache_timeout != CACHE_TIMEOUT_NEVEL_EXPIRE) {
		cache_check_expire(c);
	}
	return 0;
}

static int query(channel_t* ctx,
	const ns_msg_t* msg,
	channel_query_cb callback, void* state)
{
	cache_t* c = (cache_t*)ctx;
	const char* key;
	struct rbnode_t* rbn;
	cache_item_t* item;

	key = msg_key(msg);

	rbn = rbtree_lookup(&c->dic, key);
	if (!rbn) {
		goto error;
	}

	item = rbtree_container_of(rbn, cache_item_t, node);

	logi("hit cache: %s - %s\n", key, msg_answers(item->msg));

	if (callback)
		callback(ctx, 0, item->msg, TRUE, TRUE, state);

	return 0;

error:
	if (callback)
		callback(ctx, -1, NULL, TRUE, FALSE, state);

	return 0;
}

static inline void update_expire(cache_t *c, cache_item_t *item, int ttl)
{
	if (c->conf->cache_timeout == CACHE_TIMEOUT_FOLLOWING_TTL) {
		item->expire = time(NULL) + ttl;
	}
	else if (c->conf->cache_timeout != CACHE_TIMEOUT_NEVEL_EXPIRE) {
		item->expire = time(NULL) + c->conf->cache_timeout;
	}
}

int cache_each(channel_t *ctx,
		int (*f)(const ns_msg_t *msg, void *data), void *data)
{
	cache_t *c = (cache_t*)ctx;
	dlitem_t *cur, *nxt;
	cache_item_t *item;
	int r;
	dllist_foreach(&c->items, cur, nxt,
		cache_item_t, item, entry) {
		r = f(item->msg, data);
		if (r)
			return r;
	}
	return 0;
}

const ns_msg_t *cache_get(channel_t *ctx, const char *key)
{
	cache_t *c = (cache_t*)ctx;
	cache_item_t *item;
	struct rbnode_t *rbn;

	if (!key) {
		loge("invalid arguments\n");
		return NULL;
	}

	rbn = rbtree_lookup(&c->dic, key);
	if (!rbn) {
		loge("item not exists - %s\n", key);
		return NULL;
	}

	item = rbtree_container_of(rbn, cache_item_t, node);
	return item->msg;
}

int cache_remove(channel_t *ctx, const char *key)
{
	cache_t *c = (cache_t*)ctx;
	cache_item_t *item;
	struct rbnode_t *rbn;

	if (!key) {
		loge("invalid arguments\n");
		return -1;
	}

	rbn = rbtree_lookup(&c->dic, key);
	if (!rbn) {
		loge("item not exists - %s\n", key);
		return -1;
	}

	item = rbtree_container_of(rbn, cache_item_t, node);
	dllist_remove(&item->entry);
	rbtree_remove(&c->dic, &item->node);
	cache_item_destroy(item);
	logi("cache removed: %s\n", key);
	return 0;
}

int cache_edit(channel_t *ctx, const char *key, const ns_msg_t *msg)
{
	cache_t *c = (cache_t*)ctx;
	cache_item_t *item;
	struct rbnode_t *rbn;
	int ttl;
	ns_msg_t *newmsg;

	if (!key || !msg) {
		loge("invalid arguments\n");
		return -1;
	}

	if (!msg->qrs || !msg->rrs ||
		msg->qdcount < 1 || ns_rrcount(msg) < 1) {
		loge("invalid msg (qdcount=%d,ancount=%d,nscount=%d,arcount=%d) - %s\n",
			(int)msg->qdcount,
			(int)msg->ancount,
			(int)msg->nscount,
			(int)msg->arcount,
			key);
		return -1;
	}

	ttl = (int)ns_get_ttl(msg);

	/* no ttl */
	if (ttl < 1) {
		loge("no ttl\n");
		return -1;
	}

	rbn = rbtree_lookup(&c->dic, key);
	if (!rbn) {
		loge("item not exists - %s\n", key);
		return -1;
	}

	item = rbtree_container_of(rbn, cache_item_t, node);
	newmsg = ns_msg_clone(msg);
	if (!newmsg) {
		loge("ns_msg_clone() error\n");
		return -1;
	}
	ns_msg_free(item->msg);
	free(item->msg);
	item->msg = newmsg;
	update_expire(c, item, ttl);
	dllist_remove(&item->entry);
	cache_item_add(c, item);
	logi("cache updated: %s - %s\n", key, msg_answers(msg));
	return 0;
}

int cache_add(channel_t* ctx, const char *key, const ns_msg_t* msg, int force)
{
	cache_t* c = (cache_t*)ctx;
	cache_item_t* item;
	struct rbnode_t* rbn;
	int ttl;

	if (!key || !msg) {
		loge("invalid arguments\n");
		return -1;
	}

	if (!msg->qrs || !msg->rrs ||
		msg->qdcount < 1 || ns_rrcount(msg) < 1) {
		loge("invalid msg (qdcount=%d,ancount=%d,nscount=%d,arcount=%d) - %s\n",
			(int)msg->qdcount,
			(int)msg->ancount,
			(int)msg->nscount,
			(int)msg->arcount,
			key);
		return -1;
	}

	ttl = (int)ns_get_ttl(msg);

	/* no ttl */
	if (ttl < 1) {
		loge("no ttl\n");
		return -1;
	}

	rbn = rbtree_lookup(&c->dic, key);
	if (!rbn) {
		item = cache_item_new(msg, key);
		if (!item) {
			loge("cache_item_new() error\n");
			return -1;
		}

		update_expire(c, item, ttl);
		cache_item_add(c, item);
		rbtree_insert(&c->dic, &item->node);
		logi("cache added: %s - %s\n", key, msg_answers(msg));
	}
	else if (force) {
		item = rbtree_container_of(rbn, cache_item_t, node);
		ns_msg_t* newmsg = ns_msg_clone(msg);
		if (!newmsg) {
			loge("ns_msg_clone() error\n");
			return -1;
		}
		ns_msg_free(item->msg);
		free(item->msg);
		item->msg = newmsg;
		update_expire(c, item, ttl);
		dllist_remove(&item->entry);
		cache_item_add(c, item);
		logi("cache updated: %s - %s\n", key, msg_answers(msg));
	}
	else {
		logi("cache update ignored: %s\n", key);
	}

	return 0;
}

int cache_save_cachedb(channel_t *ctx, const char *filename)
{
	FILE *fp;
	int msglen, n;
	cache_t *c = (cache_t*)ctx;
	dlitem_t *cur, *nxt;
	cache_item_t *item;
	stream_t s[1] = {0};
	int saved = 0;

	if (!filename || !*filename) {
		loge("Invalid filename: %s\n", filename);
		return -1;
	}

	fp = fopen(filename, "wb");
	if (fp == NULL) {
		loge("Can't open file: %s\n", filename);
		return -1;
	}

	if (stream_set_cap(s, NS_PAYLOAD_SIZE + 2)) {
		loge("stream_set_cap() error\n");
		fclose(fp);
		return -1;
	}

	/* File header (24 bytes) */
	/* MAGIC (5 bytes) */
	if (stream_write(s, CACHEDB_MAGIC, sizeof(CACHEDB_MAGIC)) == -1) {
		loge("stream_write() error\n");
		fclose(fp);
		return -1;
	}

	/* Version (2 bytes) */
	if (stream_writei(s, CACHEDB_VERSION, 2) == -1) {
		loge("stream_write() error\n");
		fclose(fp);
		return -1;
	}

	/* Padding (17 bytes) */
	{
		char padding[17] = {0};
		if (stream_write(s, padding, sizeof(padding)) == -1) {
			loge("stream_write() error\n");
			fclose(fp);
			return -1;
		}
	}

	n = fwrite(s->array, 1, s->size, fp);
	if (n != s->size) {
		loge("fwrite() error: %s\n", filename);
		fclose(fp);
		stream_free(s);
		return -1;
	}

	dllist_foreach(&c->items, cur, nxt,
		cache_item_t, item, entry) {

		stream_reset(s);

		/* write length */
		stream_writei16(s, 0);

		if ((msglen = ns_serialize(s, item->msg, 0)) <= 0) {
			loge("ns_serialize() error\n");
			fclose(fp);
			stream_free(s);
			return -1;
		}

		s->pos = 0;
		stream_seti16(s, 0, msglen);

		n = fwrite(s->array, 1, s->size, fp);
		if (n != s->size) {
			loge("fwrite() error: %s\n", filename);
			fclose(fp);
			stream_free(s);
			return -1;
		}

		saved++;
	}

	fclose(fp);
	stream_free(s);

	logn("Save %d item(s) to cache database %s\n", saved, filename);

	return saved;
}

int cache_load_cachedb(channel_t *ctx, const char *filename, int override)
{
	FILE *fp;
	int msglen, n;
	unsigned char buf[NS_PAYLOAD_SIZE];
	ns_msg_t msg[1] = {0};
	const char *key;
	int dbver = 0;
	int added = 0;

	if (!filename || !*filename) {
		loge("Invalid filename: %s\n", filename);
		return -1;
	}

	fp = fopen(filename, "rb");
	if (fp == NULL) {
		loge("Can't open file: %s\n", filename);
		return -1;
	}

	n = fread(buf, 1, CACHEDB_HEAD_SIZE, fp);
	if (n != CACHEDB_HEAD_SIZE ||
			memcmp(buf, CACHEDB_MAGIC, sizeof(CACHEDB_MAGIC))) {
		loge("Invalid format: %s\n", filename);
		fclose(fp);
		return -1;
	}

	dbver = buf[sizeof(CACHEDB_MAGIC)];
	dbver <<= 8;
	dbver |= buf[sizeof(CACHEDB_MAGIC) + 1];
	if (dbver != CACHEDB_VERSION) {
		loge("Unsupport version: %d - %s\n",
				dbver, filename);
		fclose(fp);
		return -1;
	}

	while ((n = fread(buf, 1, 2, fp)) > 0) {
		if (n != 2) {
			loge("Invalid format: %s\n", filename);
			fclose(fp);
			return -1;
		}

		msglen = (int)buf[0] & 0xff;
		msglen <<= 8;
		msglen |= (int)buf[1] & 0xff;

		if (msglen == 0) {
			break;
		}

		if (msglen > NS_PAYLOAD_SIZE) {
			loge("Invalid format: %s\n", filename);
			fclose(fp);
			return -1;
		}

		n = fread(buf, 1, msglen, fp);
		if (n != msglen) {
			loge("Invalid format: %s\n", filename);
			fclose(fp);
			return -1;
		}

		memset(msg, 0, sizeof(ns_msg_t));

		if (ns_parse(msg, buf, msglen) == -1) {
			loge("Invalid format: %s\n", filename);
			fclose(fp);
			return -1;
		}

		key = msg_key(msg);
		if (cache_add(ctx, key, msg, override) == -1) {
			loge("cache_add() error: key=%s, %s\n",
					key, msg_answers(msg));
			fclose(fp);
			return -1;
		}

		ns_msg_free(msg);

		added++;
	}

	fclose(fp);

	logn("Load %d item(s) from cache database %s\n", added, filename);

	return added;
}

int cache_load_cachedbs(channel_t *ctx, const char *filenames, int override)
{
	char *s, *p, *saveptr = NULL;
	struct stat fstat = {0};

	if (!filenames || !*filenames) {
		loge("Invalid filenames: %s\n", filenames);
		return -1;
	}

	s = strdup(filenames);

	for (p = strtok_r(s, ",", &saveptr);
		p && *p;
		p = strtok_r(NULL, ",", &saveptr)) {

		if (stat(p, &fstat)) {
			logw("Failed to load cache: Failed to open the file - \"%s\"\n", p);
		}
		else if (cache_load_cachedb(ctx, p, override) == -1) {
			free(s);
			return -1;
		}
	}

	free(s);

	return 0;
}

struct cb_querystring_state_t {
	cache_t *ctx;
	int      override;
};

static int cb_querystring(char *name, char *value, void *state)
{
	struct cb_querystring_state_t *st = state;
	cache_t *ctx = st->ctx;

	if (strcmp(name, "cachedb") == 0) {
		if (cache_load_cachedbs((channel_t*)ctx, value, st->override)) {
			return -1;
		}
	}

	return 0;
}

int cache_create(
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
	cache_t* ctx;

	ctx = (cache_t*)malloc(sizeof(cache_t));
	if (!ctx) {
		loge("alloc\n");
		return CHANNEL_ALLOC;
	}

	memset(ctx, 0, sizeof(cache_t));

	dllist_init(&ctx->items);
	rbtree_init(&ctx->dic, rbkeycmp);

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

	if (args) {
		struct cb_querystring_state_t st[1] = {{
			.ctx = ctx, .override = FALSE,
		}};
		if (parse_querystring(args, cb_querystring, st)) {
			loge("invalid args: %s\n", args);
			return CHANNEL_WRONG_ARG;
		}
	}

	*pctx = (channel_t*)ctx;

	return CHANNEL_OK;
}
