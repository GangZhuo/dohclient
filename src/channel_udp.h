#ifndef DOHCLIENT_CHANNEL_UDP_H_
#define DOHCLIENT_CHANNEL_UDP_H_

#include "channel.h"
#include "dllist.h"

#ifdef __cplusplus
extern "C" {
#endif

int channel_udp_create(
	channel_t** pctx,
	const char* name,
	const char* args,
	const config_t* conf,
	const proxy_t* proxies,
	const int proxy_num,
	const chnroute_ctx chnr,
	const chnroute_ctx blacklist,
	void* data);

int channel_udp_query(channel_t* ctx,
	const ns_msg_t* msg,
	int use_proxy, subnet_t* subnet,
	channel_query_cb callback, void* state);

#ifdef __cplusplus
}
#endif

#endif
