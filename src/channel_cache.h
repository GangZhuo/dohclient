#ifndef DOHCLIENT_CHANNEL_CACHE_H_
#define DOHCLIENT_CHANNEL_CACHE_H_

#include "channel.h"
#include "dllist.h"

#ifdef __cplusplus
extern "C" {
#endif

int cache_create(
	channel_t** pctx,
	const char* name,
	const char* args,
	const config_t* conf,
	const proxy_t* proxies,
	const int proxy_num,
	const chnroute_ctx chnr,
	const chnroute_ctx blacklist,
	void* data);

int cache_add(channel_t* ctx, const char* key, const ns_msg_t* msg, int force);
int cache_remove(channel_t *ctx, const char *key);
int cache_edit(channel_t *ctx, const char *key, const ns_msg_t *msg);
const ns_msg_t *cache_get(channel_t *ctx, const char *key);
void cache_each(channel_t *ctx,
		int (*f)(const ns_msg_t *msg, void *data), void *data);

#ifdef __cplusplus
}
#endif

#endif
