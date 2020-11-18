#include "channel_cache.h"
#include "../rbtree/rbtree.h"
#include "mleak.h"

#define _M
#define REQ_KEY_SIZE (NS_QNAME_SIZE + NS_QTYPE_NAME_SIZE + NS_QCLASS_NAME_SIZE)

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
		loge("cache_item_new() error: alloc\n");
		return NULL;
	}

	memset(item, 0, sizeof(cache_item_t));

	item->msg = ns_msg_clone(msg);
	if (!item->msg) {
		loge("cache_item_new() error: ns_msg_clone() error\n");
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

	dllist_foreach_revert(&c->items, cur, nxt,
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
			logv("cache timeout - %s\n", item->node.key);
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
	cache_check_expire(c);
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

	if (loglevel > LOG_DEBUG) {
		logv("hit cache: %s - %s\n",
			key, msg_answers(item->msg));
	}
	else {
		logv("hit cache: %s\n", key);
	}

	if (callback)
		callback(ctx, 0, item->msg, TRUE, TRUE, state);

	return 0;

error:
	if (callback)
		callback(ctx, -1, NULL, TRUE, FALSE, state);

	return 0;
}

int cache_add(channel_t* ctx, const char *key, const ns_msg_t* msg)
{
	cache_t* c = (cache_t*)ctx;
	cache_item_t* item;
	struct rbnode_t* rbn;
	int ttl;

	if (!key || !msg) {
		loge("cache_add() error: invalid arguments\n");
		return -1;
	}

	if (!msg->qrs || !msg->rrs ||
		msg->qdcount < 1 || ns_rrcount(msg) < 1) {
		loge("cache_add() error: invalid msg (qdcount=%d,ancount=%d,nscount=%d,arcount=%d) - %s\n",
			(int)msg->qdcount,
			(int)msg->ancount,
			(int)msg->nscount,
			(int)msg->arcount,
			key);
		return -1;
	}

	ttl = (int)ns_get_ttl(msg);

	/* no ttl */
	if (ttl < 1)
		return -1;

	rbn = rbtree_lookup(&c->dic, key);
	if (!rbn) {
		item = cache_item_new(msg, key);
		if (!item) {
			loge("cache_add() error: cache_item_new() error\n");
			return -1;
		}

		item->expire = time(NULL) + ttl;
		cache_item_add(c, item);
		rbtree_insert(&c->dic, &item->node);
		if (loglevel > LOG_DEBUG) {
			logv("cache added: %s - %s\n", key, msg_answers(msg));
		}
		else {
			logv("cache added: %s\n", key);
		}
	}
	else {
		item = rbtree_container_of(rbn, cache_item_t, node);
		ns_msg_t* newmsg = ns_msg_clone(msg);
		if (!newmsg) {
			loge("cache_add() error: ns_msg_clone() error\n");
			return -1;
		}
		ns_msg_free(item->msg);
		free(item->msg);
		item->msg = newmsg;
		item->expire = time(NULL) + ttl;
		dllist_remove(&item->entry);
		cache_item_add(c, item);
		if (loglevel > LOG_DEBUG) {
			logv("cache updated: %s - %s\n", key, msg_answers(msg));
		}
		else {
			logv("cache updated: %s\n", key);
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
	void* data)
{
	cache_t* ctx;

	ctx = (cache_t*)malloc(sizeof(cache_t));
	if (!ctx) {
		loge("cache_create() error: alloc\n");
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
	ctx->data = data;

	ctx->fdset = fdset;
	ctx->step = step;
	ctx->query = query;
	ctx->destroy = destroy;


	*pctx = (channel_t*)ctx;

	return CHANNEL_OK;
}
