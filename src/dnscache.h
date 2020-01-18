#ifndef DOHCLIENT_DNSCACHE_H_
#define DOHCLIENT_DNSCACHE_H_

#include <stdarg.h>
#include <stdlib.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define dnscache_timeout (*dnscache_ptimeout())

int* dnscache_ptimeout();

int dnscache_init();

void dnscache_free();

int dnscache_add(const char* domain, const char* data, int datalen);

int dnscache_update(const char* domain, const char* data, int datalen);

int dnscache_set(const char* domain, const char* data, int datalen);

/* remove from cache. return 0 when success, return -1 when not exists. */
int dnscache_remove(const char* domain);

int dnscache_get(const char* domain, char* buf);

void dnscache_check_expire(time_t now);

#ifdef __cplusplus
}
#endif

#endif
