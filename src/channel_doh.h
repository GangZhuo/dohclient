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
	const char* args, /* example: ip=172.67.153.110&port=443&host=doh.beike.workers.dev&path=/dns-query&proxy=0 */
	const config_t* conf,
	const proxy_t* proxies,
	const int proxy_num,
	const chnroute_ctx* chnr,
	void* data);

#ifdef __cplusplus
}
#endif

#endif
