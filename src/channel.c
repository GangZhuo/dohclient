#include "channel.h"
#include "channel_cache.h"
#include "channel_os.h"
#include "channel_doh.h"
#include "channel_chndoh.h"
#include "channel_udp.h"
#include "channel_tcp.h"
#include "channel_hosts.h"
#include "mleak.h"

typedef struct channel_info_t{
	const char* name;
	channel_create_func create;
} channel_info_t;

static channel_info_t _infos[] = {
	{
		.name = "cache",
		.create = cache_create,
	},
	{
		.name = "hosts",
		.create = hosts_create,
	},
	{
		.name = "os",
		.create = channel_os_create,
	},
	{
		.name = "udp",
		.create = channel_udp_create,
	},
	{
		.name = "tcp",
		.create = channel_tcp_create,
	},
	{
		.name = "doh",
		.create = channel_doh_create,
	},
	{
		.name = "chinadns",
		.create = channel_chndoh_create,
	},
	NULL
};

int channel_create(
	channel_t** pctx,
	const char* name,
    const char* args,
	const config_t* conf,
	const proxy_t* proxies,
	const int proxy_num,
	const chnroute_ctx chnr,
	const chnroute_ctx blacklist,
	void* data)
{
	channel_info_t* info;
	char chname[20] = {0};
	char *dot;

	dot = strchr(name, '.');
	if (dot) {
		memcpy(chname, name, MIN(dot - name, sizeof(chname) - 1));
	}
	else {
		strncpy(chname, name, sizeof(chname) - 1);
	}

	info = _infos;
	while (info) {

		if (strcmp(info->name, chname) == 0) {
			return info->create(pctx,
				name, args, conf,
				proxies, proxy_num,
				chnr, blacklist,
				data);
		}

		info++;
	}
	return CHANNEL_NO_EXIST;
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

