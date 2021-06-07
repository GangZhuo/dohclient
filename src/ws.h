#ifndef DOHCLIENT_WS_H_
#define DOHCLIENT_WS_H_

/* WebSocket */

#include "netutils.h"
#include "channel.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wsctx_t wsctx_t;

int ws_can_parse(char *buf);
void wsctx_free(wsctx_t *ctx);
int ws_onrecv(peer_t *peer);

#ifdef __cplusplus
}
#endif

#endif


