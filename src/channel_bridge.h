#ifndef DOHCLIENT_CHANNEL_BRIDGE_H_
#define DOHCLIENT_CHANNEL_BRIDGE_H_

#include "channel.h"
#include "dllist.h"

#ifdef __cplusplus
extern "C" {
#endif

int channel_bridge_create(
	channel_t** pctx,
	const char* name, /* fixed as bridge */
	const char* args, /* example: server=8.8.8.8:53&tcp=1&proxy=1 */
	const config_t* conf,
	const proxy_t* proxies,
	const int proxy_num,
	const chnroute_ctx* chnr,
	void* data);

#ifdef __cplusplus
}
#endif

#endif
