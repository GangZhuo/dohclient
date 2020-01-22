#ifndef DOHCLIENT_CHANNEL_OS_H_
#define DOHCLIENT_CHANNEL_OS_H_

#include "channel.h"
#include "dllist.h"

#ifdef __cplusplus
extern "C" {
#endif

channel_t* channel_os_create(
	const char* name,
	const config_t* conf,
	const proxy_t* proxies,
	const int proxy_num,
	const chnroute_ctx* chnr,
	void* data);

#ifdef __cplusplus
}
#endif

#endif
