#ifndef DOHCLIENT_CACHE_API_H_
#define DOHCLIENT_CACHE_API_H_

#include "netutils.h"
#include "channel.h"

/* Errors */
#define CACHE_API_OK            0 /* OK */
#define CACHE_API_EARG          1 /* Invalid Arguments */
#define CACHE_API_ENOTFOUND     2 /* Not Found */
#define CACHE_API_EALLOC        3 /* Alloc */
#define CACHE_API_ENORMAL       4 /* Normal Error */
#define CACHE_API_EFORBIDDEN    5 /* Forbidden */

#ifdef __cplusplus
extern "C" {
#endif

int cache_api_config(const char *configstring);

char *cache_api_list(channel_t *cache, const char *keyword, int offset, int limit);
char *cache_api_get(channel_t *cache, const char *key);
char *cache_api_put(channel_t *cache, const char *name, const char *type,
		const char *ip, const char *ttl);
char *cache_api_delete(channel_t *cache, const char *key);
char *cache_api_save(channel_t *cache, const char *filename);
char *cache_api_load(channel_t *cache, const char *filename, int override);
char *cache_api_wrapjson(int err, const char *msg, const char *data);

int cache_api_try_parse(channel_t *cache, const char *data, int datalen,
	listen_t *listen,
	void *from, int fromlen, int fromtcp);

#ifdef __cplusplus
}
#endif

#endif

