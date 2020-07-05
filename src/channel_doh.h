#ifndef DOHCLIENT_CHANNEL_DOH_H_
#define DOHCLIENT_CHANNEL_DOH_H_

#include "channel.h"
#include "dllist.h"

#ifdef __cplusplus
extern "C" {
#endif

int channel_doh_create(
	channel_t** pctx,
	const char* name, /* fixed as 'doh' */
	const char* args, /* example: addr=8.8.4.4:443&host=dns.google&path=/dns-query&proxy=1&ecs=1&china-ip4=114.114.114.114/24&china-ip6=2405:2d80::/32&foreign-ip4=8.8.8.8/24&foreign-ip6=2001:df2:8300::/48 */
	const config_t* conf,
	const proxy_t* proxies,
	const int proxy_num,
	const chnroute_ctx chnr,
	void* data);

#ifdef __cplusplus
}
#endif

#endif
