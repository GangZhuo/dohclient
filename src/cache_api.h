#ifndef DOHCLIENT_CACHE_API_H_
#define DOHCLIENT_CACHE_API_H_

#include "netutils.h"
#include "channel.h"

#ifdef __cplusplus
extern "C" {
#endif

int cache_api_try_parse(channel_t *cache, const char *data, int datalen,
	listen_t *listen,
	void *from, int fromlen, int fromtcp);

#ifdef __cplusplus
}
#endif

#endif

