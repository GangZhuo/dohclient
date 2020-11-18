#ifndef DOHCLIENT_CHANNEL_OS_H_
#define DOHCLIENT_CHANNEL_OS_H_

#include "channel.h"
#include "dllist.h"

#ifdef __cplusplus
extern "C" {
#endif

int channel_os_create(
	channel_t** pctx,
	const char* name,
	const char* args,
	const config_t* conf,
	const proxy_t* proxies,
	const int proxy_num,
	const chnroute_ctx chnr,
	const chnroute_ctx blacklist,
	void* data);

#ifdef __cplusplus
}
#endif

#endif
