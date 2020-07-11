#ifndef DOHCLIENT_CHANNEL_H_
#define DOHCLIENT_CHANNEL_H_

#include "config.h"
#include "netutils.h"
#include "chnroute.h"
#include "ns_msg.h"
#include "log.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct channel_t channel_t;
typedef int (*channel_create_func)(
	channel_t** pctx,
	const char *name,
	const char *args,
	const config_t* conf,
	const proxy_t* proxies,
	const int proxy_num,
	const chnroute_ctx chnr,
	void *data);
typedef void (*channel_destroy_func)(channel_t* ctx);
typedef sock_t(*channel_fdset_func)(channel_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset);
typedef int (*channel_step_func)(channel_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset);
typedef int (*channel_query_cb)(channel_t* ctx,
	int status,
	ns_msg_t* result,
	int fromcache,
	int trust,
	void *state);
typedef int (*channel_query_func)(channel_t* ctx,
	const ns_msg_t* request,
	channel_query_cb callback, void* state);

#define CHANNEL_BASE(M)					\
	const char* name;					\
	const config_t* conf;				\
	const proxy_t* proxies;				\
	M int proxy_num;					\
	M chnroute_ctx chnr;			    \
										\
	M channel_fdset_func fdset;			\
	M channel_step_func step;			\
	M channel_query_func query;			\
	M channel_destroy_func destroy;		\
										\
	void* data;

struct channel_t {
	CHANNEL_BASE(const)
};

#define CHANNEL_OK				0
#define CHANNEL_NO_EXIST		1
#define CHANNEL_WRONG_ARG		2
#define CHANNEL_ALLOC			3

int channel_create(
	channel_t** pctx,
	const char* name,
    const char* args,
	const config_t* conf,
	const proxy_t* proxies,
	const int proxy_num,
	const chnroute_ctx chnr,
	void* data);

void channel_destroy(channel_t* ctx);

int channel_build_msg(
	ns_msg_t* msg,
	const uint16_t id,
	const ns_flags_t* flags,
	const ns_qr_t* qr,
	void* ip, int family);

#ifdef __cplusplus
}
#endif

#endif
