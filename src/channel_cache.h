#ifndef DOHCLIENT_CHANNEL_CACHE_H_
#define DOHCLIENT_CHANNEL_CACHE_H_

#include "channel.h"
#include "dllist.h"

#ifdef __cplusplus
extern "C" {
#endif

channel_t* cache_create(
	const char* name,
	const config_t* conf,
	const proxy_t* proxies,
	const int proxy_num,
	const chnroute_ctx* chnr,
	void* data);

int cache_add(channel_t* ctx, const char* key, const ns_msg_t* msg);

#ifdef __cplusplus
}
#endif

#endif