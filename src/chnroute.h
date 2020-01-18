#ifndef DOHCLIENT_CHNROUTE_H_
#define DOHCLIENT_CHNROUTE_H_

#include <stdint.h>
#ifdef WINDOWS
#include "../windows/win.h"
#else
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef void* chnroute_ctx;

chnroute_ctx chnroute_create();

void chnroute_free(chnroute_ctx ctx);

int chnroute_test4(chnroute_ctx ctx, struct in_addr* ip);

int chnroute_test6(chnroute_ctx ctx, struct in6_addr* ip);

int chnroute_test(chnroute_ctx ctx, struct sockaddr* addr);

int chnroute_parse(chnroute_ctx ctx, const char* filename);

#ifdef __cplusplus
}
#endif

#endif
