#ifndef DOHCLIENT_CACHE_API_H_
#define DOHCLIENT_CACHE_API_H_

#include "netutils.h"
#include "channel.h"

/* Errors */
#define CACHE_API_OK        0 /* OK */
#define CACHE_API_EARG      1 /* Invalid Arguments */
#define CACHE_API_ENOTFOUND 2 /* Not Found */
#define CACHE_API_EALLOC    3 /* Alloc */

#ifdef __cplusplus
extern "C" {
#endif

char *cache_api_list(channel_t *cache, int offset, int limit);
char *cache_api_get(channel_t *cache, const char *key);
char *cache_api_put(channel_t *cache, const char *name, const char *type,
		const char *ip, const char *ttl);
char *cache_api_delete(channel_t *cache, const char *key);

int cache_api_try_parse(channel_t *cache, const char *data, int datalen,
	listen_t *listen,
	void *from, int fromlen, int fromtcp);

#ifdef __cplusplus
}
#endif

#endif

