#ifndef DOHCLIENT_HTTPSERVER_H_
#define DOHCLIENT_HTTPSERVER_H_

/* HttpServer */

#include "netutils.h"
#include "channel.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct hsctx_t hsctx_t;

typedef struct hsconfig_t hsconfig_t;

struct hsconfig_t {
	channel_t  *cache;
	const char *wwwroot;
};

typedef struct mime_t {
	const char *ext;  /* e.g. "html" */
	const char *mime;
} mime_t;

extern hsconfig_t hsconf[1];

int hs_can_parse(char *buf);
void hsctx_free(hsctx_t *ctx);
int hs_onrecv(peer_t *peer);

#ifdef __cplusplus
}
#endif

#endif


