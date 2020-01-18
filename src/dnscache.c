#include "dnscache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../rbtree/rbtree.h"
#include "dllist.h"
#include "log.h"

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

typedef struct item_t {
	struct rbnode_t node;
	dlitem_t entry;
	int datalen;
	char* data;
	time_t expire;
} item_t;

static struct rbtree_t tree = { 0 };
static struct dllist_t list = { 0 };
static int timeout = 10 * 60; /* 10 minutes */

static int update_item(item_t* item, const char* data, int datalen)
{
	char* buf;

	buf = (char*)realloc(item->data, datalen);
	if (!buf) {
		loge("update_item() error: realloc\n");
		return -1;
	}

	memcpy(buf, data, datalen);

	item->data = buf;
	item->datalen = datalen;

	if (timeout > 0)
		item->expire = time(NULL) + timeout;
	else
		item->expire = 0;

	return 0;
}

static item_t* new_item(const char *domain, const char *data, int datalen)
{
	item_t* item = (item_t*)malloc(sizeof(item_t));
	if (!item) {
		loge("new_item() error: alloc\n");
		return NULL;
	}

	memset(item, 0, sizeof(item_t));

	item->node.key = strdup(domain);
	if (!item->node.key) {
		loge("new_item() error: alloc\n");
		free(item);
		return NULL;
	}

	if (update_item(item, data, datalen)) {
		loge("new_item() error: update_item()\n");
		free(item->node.key);
		free(item);
		return NULL;
	}

	return item;
}

static void free_item(item_t *item)
{
	free(item->node.key);
	item->node.key = NULL;

	free(item->data);
	item->data = NULL;
}

static void destroy_item(item_t* item)
{
	free_item(item);
	free(item);
}

static int rbnkeycmp(void* a, void* b)
{
	const char* x = (const char*)a;
	const char* y = (const char*)b;
	return strcmp(x, y);
}

int* dnscache_ptimeout()
{
	return &timeout;
}

int dnscache_init()
{
	dllist_init(&list);
	rbtree_init(&tree, rbnkeycmp);
	return 0;
}

void dnscache_free()
{
	dlitem_t* cur, * nxt;
	item_t* item;
	rbtree_init(&tree, rbnkeycmp);
	dllist_foreach(&list, cur, nxt, item_t, item, entry) {
		destroy_item(item);
	}
	dllist_init(&list);
}

int dnscache_add(const char* domain, const char* data, int datalen)
{
	item_t* item;

	item = new_item(domain, data, datalen);

	if (!item) return -1;

	if (rbtree_insert(&tree, &item->node)) {
		logd("dnscache_add() error: domain exists - %s\n", domain);
		destroy_item(item);
		return -1;
	}

	dllist_add(&list, &item->entry);

	return 0;
}

static int dnscache_update_node(struct rbnode_t* node, const char* data, int datalen)
{
	item_t* item;

	item = rbtree_container_of(node, item_t, node);

	if (update_item(item, data, datalen)) {
		loge("dnscache_update_node() error: update_item()\n");
		return -1;
	}

	return 0;
}

int dnscache_update(const char* domain, const char* data, int datalen)
{
	struct rbnode_t* n;

	n = rbtree_lookup(&tree, (void*)domain);

	if (!n) {
		logd("dnscache_update() error: not exists - %s\n", domain);
		return -1;
	}

	return dnscache_update_node(n, data, datalen);
}

int dnscache_set(const char* domain, const char* data, int datalen)
{
	struct rbnode_t* n;

	n = rbtree_lookup(&tree, (void*)domain);

	if (n) {
		logd("dnscache_set(): update dns cache - %s\n", domain);
		return dnscache_update_node(n, data, datalen);
	}
	else {
		logd("dnscache_set(): add dns cache - %s\n", domain);
		return dnscache_add(domain, data, datalen);
	}

	return 0;
}

int dnscache_remove(const char* domain)
{
	struct rbnode_t* n;
	item_t* item;

	n = rbtree_lookup(&tree, (void*)domain);

	if (!n) {
		logd("dnscache_remove() error: not exists - %s\n", domain);
		return -1;
	}

	item = rbtree_container_of(n, item_t, node);
	
	rbtree_remove(&tree, &item->node);
	dllist_remove(&item->entry);
	destroy_item(item);

	return 0;
}

int dnscache_get(const char *domain, char *buf)
{
	struct rbnode_t* n;

	n = rbtree_lookup(&tree, (void*)domain);

	if (!n) return FALSE;

	if (buf) {
		item_t* item = rbtree_container_of(n, item_t, node);
		memcpy(buf, item->data, item->datalen);
	}

	return TRUE;
}

void dnscache_check_expire(time_t now)
{
	dlitem_t* cur, * nxt;
	item_t* item;
	dllist_foreach(&list, cur, nxt, item_t, item, entry) {
		if (item->expire > 0 && item->expire <= now) {
			logd("dnscache timeout - %s\n", item->node.key);
			rbtree_remove(&tree, &item->node);
			dllist_remove(&item->entry);
			destroy_item(item);
		}
		else {
			break;
		}
	}
}

