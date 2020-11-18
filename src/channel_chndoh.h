#ifndef DOHCLIENT_CHANNEL_CHNDOH_H_
#define DOHCLIENT_CHANNEL_CHNDOH_H_

#include "channel.h"
#include "dllist.h"

#ifdef __cplusplus
extern "C" {
#endif

/* work like ChinaDNS */
int channel_chndoh_create(
	channel_t** pctx,
	const char* name, /* fixed as 'chndoh' */
	const char* args, /* example: "chndoh.addr=223.5.5.5:443&chndoh.host=dns.alidns.com&chndoh.path=/dns-query&frndoh.addr=172.67.153.59:443&frndoh.host=doh.xxx.workers.dev&frndoh.path=/dns-query&frndoh.post=0&frndoh.keep-alive=1&frndoh.proxy=0&frndoh.ecs=1&frndoh.net=199.19.0.0/24&frndoh.net6=2001:19f0:6401::/48" */
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
