#include "channel.h"
#include "channel_cache.h"
#include "channel_os.h"

typedef struct channel_info_t{
	const char* name;
	channel_create_func create;
} channel_info_t;

static channel_info_t _infos[] = {
	{
		.name = "os",
		.create = channel_os_create,
	},
	{
		.name = "cache",
		.create = cache_create,
	},
	NULL
};

channel_t* channel_create(
	const char* name,
    const char* args,
	const config_t* conf,
	const proxy_t* proxies,
	const int proxy_num,
	const chnroute_ctx* chnr,
	void* data)
{
	channel_info_t* info;

	info = _infos;
	while (info) {

		if (strcmp(info->name, name) == 0) {
			return info->create(
				name, args, conf,
				proxies, proxy_num,
				chnr, data);
		}

		info++;
	}
	return NULL;
}

void channel_destroy(channel_t *ctx)
{
	if (ctx) {
		ctx->destroy(ctx);
	}
}

int channel_build_msg(
	ns_msg_t *msg,
	const uint16_t id,
	const ns_flags_t *flags,
	const ns_qr_t* qr,
	void *ip, int family)
{
	if (init_ns_msg(msg)) {
		loge("channel_build_msg() error: init_ns_msg() error\n");
		return -1;
	}

	msg->id = id;
	msg->flags = *flags;

	if (qr) {
		msg->qrs = ns_qr_clone(qr, 1);
		if (!msg->qrs) {
			loge("channel_build_msg() error: ns_qr_clone() error\n");
			return -1;
		}
		msg->qdcount = 1;
	}

	if (qr && ip) {
		msg->rrs = (ns_rr_t*)malloc(sizeof(ns_rr_t));
		if (!msg->rrs) {
			loge("channel_build_msg() error: alloc \n");
			ns_msg_free(msg);
			return -1;
		}
		msg->ancount = 1;
		msg->rrs->name = strdup(qr->qname);
		msg->rrs->type = qr->qtype;
		msg->rrs->cls = qr->qclass;
		msg->rrs->ttl = 600;
		msg->rrs->rdlength = family == AF_INET ? 4 : 16;
		msg->rrs->rdata = (char*)malloc(msg->rrs->rdlength);
		if (!msg->rrs->rdata) {
			loge("channel_build_msg() error: alloc \n");
			ns_msg_free(msg);
			return -1;
		}

		memcpy(msg->rrs->rdata, ip, msg->rrs->rdlength);
	}

	return 0;
}
