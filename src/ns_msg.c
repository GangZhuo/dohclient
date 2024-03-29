#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef WINDOWS
#include "../windows/win.h"
#else
#include <arpa/inet.h>
#endif

#include "ns_msg.h"
#include "log.h"
#include "utils.h"
#include "mleak.h"

typedef struct opt_rdata_into {
	int count; /* number of option(s) */
	int size; /* total size of option data */
} opt_rdata_into;

typedef struct str_t {
	char *s;
	int len;
} str_t;

typedef struct label_t {
	str_t label;
	int offset;
	struct label_t *parent;
	struct label_t *childs;
	struct label_t *next;
} label_t;

typedef struct serialize_ctx {
	int compression;
	int startpos;
	label_t rlabel; /* root label */
} serialize_ctx;

static int indexof_char(char *p, int ch);

static void ns_msg_free_rdata(ns_rr_t* rr);

ns_flags_t ns_get_flags(ns_msg_t *msg)
{
	ns_flags_t f;
	int v = msg->flags;
	f.qr = (v >> 15) & 1;
	f.opcode = (v >> 11) & 0xf;
	f.aa = (v >> 10) & 1;
	f.tc = (v >> 9) & 1;
	f.rd = (v >> 8) & 1;
	f.ra = (v >> 7) & 1;
	f.z = (v >> 4) & 0x7;
	f.rcode = v & 0xf;
	return f;
}

uint16_t ns_set_flags(ns_msg_t *msg, const ns_flags_t *flags)
{
	int32_t rv = 0;
	rv |= ((int)flags->qr & 1) << 15;
	rv |= ((int)flags->opcode & 0xf) << 11;
	rv |= ((int)flags->aa & 1) << 10;
	rv |= ((int)flags->tc & 1) << 9;
	rv |= ((int)flags->rd & 1) << 8;
	rv |= ((int)flags->ra & 1) << 7;
	rv |= ((int)flags->z & 7) << 4;
	rv |= ((int)flags->rcode & 0xf);
	if (msg)
		msg->flags = (uint16_t)(rv & 0xffff);
	return (uint16_t)(rv & 0xffff);
}

int init_ns_msg(ns_msg_t *msg)
{
	memset(msg, 0, sizeof(ns_msg_t));

	return 0;
}

uint32_t ns_get_ttl(const ns_msg_t* msg)
{
	int i, rrcount;
	uint32_t ttl = 0;
	ns_rr_t* rr;

	rrcount = ns_rrcount(msg);
	for (i = 0; i < rrcount; i++) {
		rr = msg->rrs + i;
		if (rr->ttl > 0 && rr->type != NS_TYPE_OPT) {
			if (ttl == 0 || ttl > rr->ttl) ttl = rr->ttl;
		}
	}

	return ttl;
}

ns_qr_t* ns_qr_clone(const ns_qr_t* array, int num)
{
	ns_qr_t* copy, * dst;
	const ns_qr_t* src;
	int i;
	if (!array)
		return NULL;
	copy = (ns_qr_t*)malloc(sizeof(ns_qr_t) * num);
	if (!copy) {
		loge("alloc \n");
		return NULL;
	}
	memset(copy, 0, sizeof(ns_qr_t) * num);
	for (i = 0; i < num; i++) {
		src = array + i;
		dst = copy + i;
		dst->qname = src->qname ? strdup(src->qname) : NULL;
		dst->qtype = src->qtype;
		dst->qclass = src->qclass;
	}
	return copy;
}

static ns_hinfo_t* ns_rdata_clone_hinfo(const ns_rr_t* rr)
{
	ns_hinfo_t* old = rr->rdata;
	ns_hinfo_t* hinfo = (ns_hinfo_t*)malloc(sizeof(ns_hinfo_t));
	if (hinfo) {
		hinfo->cpu = old->cpu ? strdup(old->cpu) : NULL;
		hinfo->os = old->os ? strdup(old->os) : NULL;
	}
	return hinfo;
}

static ns_minfo_t* ns_rdata_clone_minfo(const ns_rr_t* rr)
{
	ns_minfo_t* old = rr->rdata;
	ns_minfo_t* minfo = (ns_minfo_t*)malloc(sizeof(ns_minfo_t));
	if (minfo) {
		minfo->rmailbx = old->rmailbx ? strdup(old->rmailbx) : NULL;
		minfo->emailbx = old->emailbx ? strdup(old->emailbx) : NULL;
	}
	return minfo;
}

static ns_mx_t* ns_rdata_clone_mx(const ns_rr_t* rr)
{
	ns_mx_t* old = rr->rdata;
	ns_mx_t* mx = (ns_mx_t*)malloc(sizeof(ns_mx_t));
	if (mx) {
		mx->preference = old->preference;
		mx->exchange = old->exchange ? strdup(old->exchange) : NULL;
	}
	return mx;
}

static void* ns_rdata_clone_any(const ns_rr_t* rr)
{
	char* data = (char*)malloc(rr->rdlength);
	if (data) {
		memcpy(data, rr->rdata, rr->rdlength);
	}
	return data;
}

static ns_soa_t* ns_rdata_clone_soa(const ns_rr_t* rr)
{
	ns_soa_t* old = rr->rdata;
	ns_soa_t* soa = (ns_soa_t*)malloc(sizeof(ns_soa_t));
	if (soa) {
		memcpy(soa, old, sizeof(ns_soa_t));
		soa->mname = old->mname ? strdup(old->mname) : NULL;
		soa->rname = old->rname ? strdup(old->rname) : NULL;
	}
	return soa;
}

static char* ns_rdata_clone_domainname(const ns_rr_t* rr)
{
	return rr->rdata ? strdup(rr->rdata) : NULL;
}

static ns_optlist_t* ns_rdata_clone_opts(const ns_rr_t* rr)
{
	ns_optlist_t* old = rr->rdata;
	ns_optlist_t* opts = (ns_optlist_t*)malloc(sizeof(ns_optlist_t));
	int i;
	if (opts) {
		opts->opts = (ns_opt_t*)malloc(sizeof(ns_opt_t) * old->optcount);
		if (!opts->opts) {
			free(opts);
			return NULL;
		}
		opts->optcount = old->optcount;
		for (i = 0; i < opts->optcount; i++) {
			opts->opts[i].code = old->opts[i].code;
			opts->opts[i].length = old->opts[i].length;
			opts->opts[i].data = malloc(opts->opts[i].length);
			if (!opts->opts[i].data) {
				for (; i >= 0; i--) {
					free(opts->opts[i].data);
				}
				free(opts->opts);
				free(opts);
				return NULL;
			}
			memcpy(opts->opts[i].data, old->opts[i].data, opts->opts[i].length);
		}
	}

	return opts;
}

static void* ns_msg_clone_rdata(const ns_rr_t* rr)
{
	switch (rr->type) {
	case NS_TYPE_HINFO:
		return ns_rdata_clone_hinfo(rr);
	case NS_TYPE_CNAME:
	case NS_TYPE_MB:
	case NS_TYPE_MD:
	case NS_TYPE_MF:
	case NS_TYPE_MG:
	case NS_TYPE_MR:
	case NS_TYPE_NS:
	case NS_TYPE_PTR:
		return ns_rdata_clone_domainname(rr);
	case NS_TYPE_MINFO:
		return ns_rdata_clone_minfo(rr);
		break;
	case NS_TYPE_MX:
		return ns_rdata_clone_mx(rr);
	case NS_TYPE_SOA:
		return ns_rdata_clone_soa(rr);
	case NS_TYPE_OPT:
		return ns_rdata_clone_opts(rr);
	case NS_TYPE_NULL:
	default:
		return ns_rdata_clone_any(rr);
	}
}

ns_rr_t* ns_rr_clone(const ns_rr_t* array, int num)
{
	ns_rr_t* copy, * dst;
	const ns_rr_t* src;
	int i;
	if (!array)
		return NULL;
	copy = (ns_rr_t*)malloc(sizeof(ns_rr_t) * num);
	if (!copy) {
		loge("alloc \n");
		return NULL;
	}
	memset(copy, 0, sizeof(ns_rr_t) * num);
	for (i = 0; i < num; i++) {
		src = array + i;
		dst = copy + i;

		dst->name = src->name ? strdup(src->name) : NULL;
		dst->type = src->type;
		dst->cls = src->cls;
		dst->ttl = src->ttl;
		dst->rdlength = src->rdlength;
		dst->rdata = NULL;

		if (src->rdata) {
			dst->rdata = ns_msg_clone_rdata(src);
			if (!dst->rdata) {
				loge("alloc \n");
				for (; i >= 0; i--) {
					dst = copy + i;
					ns_msg_free_rdata(dst);
					free(dst->name);
				}
				free(copy);
				return NULL;
			}
		}
	}
	return copy;
}

ns_msg_t* ns_msg_clone(const ns_msg_t *msg)
{
	ns_msg_t* copy;
	copy = (ns_msg_t*)malloc(sizeof(ns_msg_t));
	if (!copy) {
		loge("alloc \n");
		return NULL;
	}

	memset(copy, 0, sizeof(ns_msg_t));
	
	copy->id = msg->id;
	copy->flags = msg->flags;
	if (msg->qrs) {
		copy->qrs = ns_qr_clone(msg->qrs, msg->qdcount);
		if (!copy->qrs) {
			loge("ns_qr_clone() error\n");
			free(copy);
			return NULL;
		}
	}
	copy->qdcount = msg->qdcount;

	if (msg->rrs) {
		copy->rrs = ns_rr_clone(msg->rrs, ns_rrcount(msg));
		if (!copy->rrs) {
			loge("ns_rr_clone() error\n");
			ns_msg_free(copy);
			return NULL;
		}
	}

	copy->ancount = msg->ancount;
	copy->nscount = msg->nscount;
	copy->arcount = msg->arcount;

	return copy;
}

const char* qr_key(const ns_qr_t* qr)
{
	static char key[REQ_KEY_SIZE];
	int n;

	if (!qr)
		return NULL;

	n = snprintf(key, sizeof(key), "%s %s %s",
		ns_typename(qr->qtype),
		ns_classname(qr->qclass),
		qr->qname ? qr->qname : "");

	if (n <= 0 || n >= sizeof(key)) {
		loge("snprintf() error\n");
		return NULL;
	}

	return key;
}

static const char* get_answers(stream_t *s, const ns_msg_t* msg)
{
	static char answers[NS_PAYLOAD_SIZE];
	int i, rrcount, r, len = 0;
	const ns_rr_t* rr;

	for (i = 0, rrcount = ns_rrcount(msg); i < rrcount; i++) {
		rr = msg->rrs + i;
		if (rr->type == NS_QTYPE_A) {
			char ipname[INET6_ADDRSTRLEN];
			struct in_addr* addr = (struct in_addr*)rr->rdata;
			inet_ntop(AF_INET, addr, ipname, INET6_ADDRSTRLEN);
			r = stream_writef(s, len > 0 ? ", %s %d %s %s %s" : "%s %d %s %s %s",
					rr->name,
					rr->ttl,
					ns_classname(rr->cls),
					ns_typename(rr->type),
					ipname);
			if (r < 0)
				return NULL;
			len += r;
		}
		else if (rr->type == NS_QTYPE_AAAA) {
			struct in6_addr* addr = (struct in6_addr*)rr->rdata;
			static char ipname[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, addr, ipname, INET6_ADDRSTRLEN);
			r = stream_writef(s, len > 0 ? ", %s %d %s %s %s" : "%s %d %s %s %s",
					rr->name,
					rr->ttl,
					ns_classname(rr->cls),
					ns_typename(rr->type),
					ipname);
			if (r < 0)
				return NULL;
			len += r;
		}
		else if (rr->type == NS_QTYPE_PTR) {
			r = stream_writef(s, len > 0 ? ", %s %d %s %s %s" : "%s %d %s %s %s",
					rr->name,
					rr->ttl,
					ns_classname(rr->cls),
					ns_typename(rr->type),
					rr->rdata);
			if (r < 0)
				return NULL;
			len += r;
		}
		else if (rr->type == NS_QTYPE_CNAME) {
			r = stream_writef(s, len > 0 ? ", %s %d %s %s %s" : "%s %d %s %s %s",
					rr->name,
					rr->ttl,
					ns_classname(rr->cls),
					ns_typename(rr->type),
					rr->rdata);
			if (r < 0)
				return NULL;
			len += r;
		}
		else if (rr->type == NS_QTYPE_SOA) {
			ns_soa_t* soa = rr->rdata;
			r = stream_writef(s, len > 0 ? ", %s %d %s %s %s,%s" : " %s %d %s %s %s,%s",
					rr->name,
					rr->ttl,
					ns_classname(rr->cls),
					ns_typename(rr->type),
					soa->mname,
					soa->rname);
			if (r < 0)
				return NULL;
			len += r;
		}
		else {
			r = stream_writef(s, len > 0 ? ", %s %d %s %s [%d bytes]" : "%s %d %s %s [%d bytes]",
					rr->name,
					rr->ttl,
					ns_classname(rr->cls),
					ns_typename(rr->type),
					(int)rr->rdlength);
			if (r < 0)
				return NULL;
			len += r;
		}
	}

	len = MIN(len, sizeof(answers) - 1);
	if (len > 0)
		strncpy(answers, s->array, len);
	answers[len] = '\0';

	return answers;
}

const char* msg_answers(const ns_msg_t* msg)
{
	stream_t s = STREAM_INIT();
	const char* answers = get_answers(&s, msg);
	stream_free(&s);
	return answers;
}

static void ns_msg_free_qr(ns_qr_t *qr)
{
	free(qr->qname);
}

static void ns_rdata_free_hinfo(ns_rr_t *rr)
{
    ns_hinfo_t *hinfo = rr->rdata;
    if (hinfo) {
        free(hinfo->cpu);
        free(hinfo->os);
    }
}

static void ns_rdata_free_minfo(ns_rr_t *rr)
{
    ns_minfo_t *minfo = rr->rdata;
    if (minfo) {
        free(minfo->rmailbx);
        free(minfo->emailbx);
    }
}

static void ns_rdata_free_mx(ns_rr_t *rr)
{
    ns_mx_t *mx = rr->rdata;
    if (mx) {
        free(mx->exchange);
    }
}

static void ns_rdata_free_any(ns_rr_t *rr)
{
}

static void ns_rdata_free_soa(ns_rr_t *rr)
{
    ns_soa_t *soa = rr->rdata;
    if (soa) {
        free(soa->mname);
        free(soa->rname);
    }
}

static void ns_rdata_free_domainname(ns_rr_t *rr)
{
}

static void ns_free_opt(ns_opt_t *opt)
{
    if (opt) {
        free(opt->data);
    }
}

static void ns_rdata_free_opts(ns_rr_t *rr)
{
	ns_optlist_t *opts = rr->rdata;
    ns_opt_t *opt;
    
	if (opts != NULL && opts->opts != NULL) {
        int i;
        for (i = 0; i < opts->optcount; i++) {
            opt = opts->opts + i;
            ns_free_opt(opt);
        }
        free(opts->opts);
    }
}

static void ns_msg_free_rdata(ns_rr_t *rr)
{
    switch (rr->type) {
        case NS_TYPE_HINFO:
            ns_rdata_free_hinfo(rr);
            break;
        case NS_TYPE_CNAME:
        case NS_TYPE_MB:
        case NS_TYPE_MD:
        case NS_TYPE_MF:
        case NS_TYPE_MG:
        case NS_TYPE_MR:
        case NS_TYPE_NS:
        case NS_TYPE_PTR:
            ns_rdata_free_domainname(rr);
            break;
        case NS_TYPE_MINFO:
            ns_rdata_free_minfo(rr);
            break;
        case NS_TYPE_MX:
            ns_rdata_free_mx(rr);
            break;
        case NS_TYPE_SOA:
            ns_rdata_free_soa(rr);
            break;
        case NS_TYPE_OPT:
            ns_rdata_free_opts(rr);
            break;
        case NS_TYPE_NULL:
        default:
            ns_rdata_free_any(rr);
            break;
    }
}

static void ns_msg_free_rr(ns_rr_t *rr)
{
	free(rr->name);
    ns_msg_free_rdata(rr);
    free(rr->rdata);
}

void ns_msg_free(ns_msg_t *msg)
{
	int i, rrcount;
	if (msg) {
        if (msg->qrs) {
            for (i = 0; i < msg->qdcount; i++) {
                ns_msg_free_qr(msg->qrs + i);
            }
            free(msg->qrs);
        }

        if (msg->rrs) {
            for (i = 0, rrcount = ns_rrcount(msg);
                    i < rrcount; i++) {
                ns_msg_free_rr(msg->rrs + i);
            }
            free(msg->rrs);
        }
	}
}

static int ns_read_cstring(stream_t *dst, stream_t *s)
{
	int spos = s->pos, dpos = dst->pos, len;

#define do_return(r) \
	s->pos = spos; \
	dst->pos = dpos; \
	return (r);

#define check_len(n) \
	if (stream_rsize(s) < (n)) { \
		loge("truncated stream\n"); \
		do_return(-1); \
	}

	check_len(1);
	len = stream_readi8(s);

	check_len(len);
	if (stream_writess(dst, s, len) != len) {
		loge("write stream\n");
		do_return(-1);
	}

	if (stream_writei8(dst, 0) != 1) {
		loge("write stream\n");
		do_return(-1);
	}

	stream_seek(dst, -1, SEEK_CUR);


#undef check_len
#undef do_return

	return dst->pos - dpos;
}

static int ns_read_domainname(stream_t *dst, stream_t *s)
{
	int spos = s->pos, dpos = dst->pos, len;

#define do_return(r) \
	s->pos = spos; \
	dst->pos = dpos; \
	return (r);

#define check_len(n) \
	if (stream_rsize(s) < (n)) { \
		loge("truncated stream\n"); \
		do_return(-1); \
	}

	check_len(1);
	len = stream_readi8(s);

	while (len > 0) {

		if ((len & 0xc0) == 0xc0) { /* compression pointer */
			int offset = (len & 0x3f);
			offset <<= 8;
			check_len(1);
			len = stream_readi8(s);
			offset |= len;
			if (offset >= s->size) {
				loge("invalid compression pointer\n");
				do_return(-1);
			}
			else {
				stream_t ns = *s;
				stream_seek(&ns, offset, SEEK_SET);
				return ns_read_domainname(dst, &ns);
			}
		}
		else if ((len & 0xc0)) {
			loge("invalid label len '0x%x'\n", len);
			do_return(-1);
		}
		else {

			check_len(len);

			if (stream_writess(dst, s, len) != len) {
				loge("write stream\n");
				do_return(-1);
			}

			if (stream_write(dst, ".", 2) != 2) {
				loge("write stream\n");
				do_return(-1);
			}

			stream_seek(dst, -1, SEEK_CUR);

			check_len(1);
			len = stream_readi8(s);
		}
	}

	if (dst->array == NULL) {

		if (stream_writei8(dst, 0) != 1) {
			loge("write stream\n");
			do_return(-1);
		}

		stream_seek(dst, -1, SEEK_CUR);
	}

#undef check_len
#undef do_return

	return dst->pos - dpos;
}

static int ns_rdata_read_domainname(ns_rr_t *rr, stream_t *s)
{
    stream_t name = STREAM_INIT();
    if (ns_read_domainname(&name, s) < 0) {
        return -1;
    }
    rr->rdata = name.array;
    return 0;
}

static int ns_rdata_read_hinfo(ns_rr_t *rr, stream_t *s)
{
    stream_t cpu = STREAM_INIT();
    stream_t os = STREAM_INIT();
    int rc = -1;
    if (ns_read_cstring(&cpu, s) >= 0 &&
        ns_read_cstring(&os, s) >= 0) {
        ns_hinfo_t *hinfo = malloc(sizeof(ns_hinfo_t));
        if (hinfo) {
            hinfo->cpu = cpu.array;
            hinfo->os = os.array;
            rr->rdata = hinfo;
            rc = 0;
        }
    }
    return rc;
}

static int ns_rdata_read_minfo(ns_rr_t *rr, stream_t *s)
{
    stream_t rmailbx = STREAM_INIT();
    stream_t emailbx = STREAM_INIT();
    int rc = -1;
    if (ns_read_domainname(&rmailbx, s) >= 0 &&
        ns_read_domainname(&emailbx, s) >= 0) {
        ns_minfo_t *minfo = malloc(sizeof(ns_minfo_t));
        if (minfo) {
            minfo->rmailbx = rmailbx.array;
            minfo->emailbx = emailbx.array;
            rr->rdata = minfo;
            rc = 0;
        }
    }
    return rc;
}

static int ns_rdata_read_mx(ns_rr_t *rr, stream_t *s)
{
    stream_t exchange = STREAM_INIT();
    int preference, rc = -1;
    if (stream_rsize(s) < 2)
        return -1;
    preference = stream_readi16(s);
    if (ns_read_domainname(&exchange, s) >= 0) {
        ns_mx_t *mx = malloc(sizeof(ns_mx_t));
        if (mx) {
            mx->exchange = exchange.array;
            mx->preference = (uint16_t)preference;
            rr->rdata = mx;
            rc = 0;
        }
    }
    return rc;
}

static int ns_rdata_read_any(ns_rr_t *rr, stream_t *s)
{
    char *any;
    if (stream_rsize(s) < rr->rdlength)
        return -1;
	any = malloc(rr->rdlength);
    if (any) {
		if (stream_read(s, any, rr->rdlength) == rr->rdlength) {
			rr->rdata = any;
			return 0;
		}
		else {
			free(any);
		}
    }
    return -1;
}

static int ns_rdata_read_soa(ns_rr_t *rr, stream_t *s)
{
    stream_t mname = STREAM_INIT();
    stream_t rname = STREAM_INIT();
    int rc = -1;
    if (ns_read_domainname(&mname, s) >= 0 &&
        ns_read_domainname(&rname, s) >= 0) {
        if (stream_rsize(s) >= 20) {
            ns_soa_t *soa = malloc(sizeof(ns_soa_t));
            if (soa) {
                soa->mname = mname.array;
                soa->rname = rname.array;
                soa->serial = (uint32_t)stream_readi32(s);
                soa->refresh = (uint32_t)stream_readi32(s);
                soa->retry = (uint32_t)stream_readi32(s);
                soa->expire = (uint32_t)stream_readi32(s);
                soa->minimum = (uint32_t)stream_readi32(s);
                rr->rdata = soa;
                rc = 0;
            }
        }

    }
    return rc;
}

static opt_rdata_into ns_rdata_read_edns_optinfo(ns_rr_t *rr, stream_t *s)
{
    opt_rdata_into info = { 0 };
    int count = 0, size = 0;
    stream_t ns = STREAM_INIT();
    ns.array = s->array + s->pos;
    ns.cap = stream_rsize(s);
    ns.size = rr->rdlength;
    ns.pos = 0;
    while(stream_rsize(&ns) > 0) {
        int code, length;
        if (stream_rsize(&ns) < 4) {
            count = -1;
            break;
        }
        code = stream_readi16(&ns);
        length = stream_readi16(&ns);
        if (stream_rsize(&ns) < length) {
            count = -1;
            break;
        }
        stream_seek(&ns, length, SEEK_CUR);
        count++;
        size += length;
    }
    info.count = count;
    info.size = size;
    return info;
}

static int ns_rdata_read_opts(ns_rr_t *rr, stream_t *s)
{
    opt_rdata_into info;
	ns_optlist_t *opts;
    ns_opt_t *opt;
    info = ns_rdata_read_edns_optinfo(rr, s);
    if (info.count < 0)
        return -1;
	opts = malloc(sizeof(ns_optlist_t));
    if (opts) {
        int i = 0;
        stream_t ns = *s;
        ns.size = s->pos + rr->rdlength;
		opts->optcount = info.count;
		opts->opts = malloc(opts->optcount * sizeof(ns_opt_t));
        if (opts->opts == NULL) {
            free(opts);
            return -1;
        }
        memset(opts->opts, 0, opts->optcount * sizeof(ns_opt_t));
#define do_return(n) \
        for (i = 0; i < opts->optcount; i++) { \
            opt = opts->opts + i; \
            free(opt->data); \
        } \
        free(opts); \
        return (n);

#define check_size(n) \
        if (stream_rsize(&ns) < (n)) { \
            do_return(-1); \
        }

        while(stream_rsize(&ns) > 0) {
            opt = opts->opts + i;
            check_size(4);
            opt->code = (uint16_t)stream_readi16(&ns);
            opt->length = (uint16_t)stream_readi16(&ns);
            opt->data = malloc(opt->length);
            if (opt->data == NULL) {
                do_return(-1);
            }
            check_size(opt->length);
            memcpy(opt->data, ns.array + ns.pos, opt->length);
            stream_seek(&ns, opt->length, SEEK_CUR);
            i++;
        }
        rr->rdata = opts;
        return 0;
#undef check_size
#undef do_return
    }
    else
        return -1;
}

static int ns_read_rdata(ns_rr_t *rr, stream_t *s)
{

    switch (rr->type) {
        case NS_TYPE_HINFO:
            return ns_rdata_read_hinfo(rr, s);
        case NS_TYPE_CNAME:
        case NS_TYPE_MB:
        case NS_TYPE_MD:
        case NS_TYPE_MF:
        case NS_TYPE_MG:
        case NS_TYPE_MR:
        case NS_TYPE_NS:
        case NS_TYPE_PTR:
            return ns_rdata_read_domainname(rr, s);
        case NS_TYPE_MINFO:
            return ns_rdata_read_minfo(rr, s);
        case NS_TYPE_MX:
            return ns_rdata_read_mx(rr, s);
       case NS_TYPE_SOA:
            return ns_rdata_read_soa(rr, s);
       case NS_TYPE_OPT:
            return ns_rdata_read_opts(rr, s);
        case NS_TYPE_NULL:
        default:
            return ns_rdata_read_any(rr, s);
     }
}

int ns_parse(ns_msg_t *msg, const uint8_t *bytes, int nbytes)
{
	int i, rrcount;
	stream_t s = STREAM_INIT();
	ns_qr_t *qr;
	ns_rr_t *rr;

	s.array = (char *)bytes;
	s.cap = nbytes;
	s.size = nbytes;
	s.pos = 0;

#define check_len(n) \
	if (stream_rsize(&s) < (n)) { \
		loge("truncated stream\n"); \
		return -1; \
	}

	check_len(12);

	msg->id = (uint16_t)stream_readi16(&s);
	msg->flags = (uint16_t)stream_readi16(&s);
	msg->qdcount = (uint16_t)stream_readi16(&s);
	msg->ancount = (uint16_t)stream_readi16(&s);
	msg->nscount = (uint16_t)stream_readi16(&s);
	msg->arcount = (uint16_t)stream_readi16(&s);

	if (msg->qdcount > 0) {
		msg->qrs = calloc(msg->qdcount, sizeof(ns_qr_t));
		if (msg->qrs == NULL) {
			loge("alloc\n");
			return -1;
		}

		for (i = 0; i < msg->qdcount; i++) {
			stream_t name = STREAM_INIT();
			qr = msg->qrs + i;
			if (ns_read_domainname(&name, &s) < 0) {
				loge("read domain name\n");
				return -1;
			}
			qr->qname = name.array;
			check_len(4);
			qr->qtype = (uint16_t)stream_readi16(&s);
			qr->qclass = (uint16_t)stream_readi16(&s);
            if (qr->qtype == 0) {
                loge("wrong qtype, maybe pollution result\n");
                return -1;
            }
		}

	}

	rrcount = ns_rrcount(msg);
	if (rrcount > 0) {
		msg->rrs = calloc(rrcount, sizeof(ns_rr_t));
		if (msg->rrs == NULL) {
			loge("alloc\n");
			return -1;
		}

		for (i = 0; i < rrcount; i++) {
			stream_t name = STREAM_INIT();
			rr = msg->rrs + i;
			if (ns_read_domainname(&name, &s) < 0) {
				loge("read domain name\n");
				return -1;
			}
			rr->name = name.array;
			check_len(10);
			rr->type = (uint16_t)stream_readi16(&s);
			rr->cls = (uint16_t)stream_readi16(&s);
			rr->ttl = (uint32_t)stream_readi32(&s);
			rr->rdlength = (uint16_t)stream_readi16(&s);

			check_len(rr->rdlength);
			if (ns_read_rdata(rr, &s) < 0) {
				loge("read rdata\n");
				return -1;
			}
		}

	}

#undef check_len

	return 0;
}

ns_rr_t *ns_find_rr(ns_msg_t *msg, int type)
{
	int i, rrcount;
	ns_rr_t *rr;

	rrcount = ns_rrcount(msg);
	for (i = rrcount - 1; i >= 0; i--) {
		rr = msg->rrs + i;
		if (rr->type == type) {
			return rr;
		}
	}

	return NULL;
}

int ns_remove_rr(ns_msg_t* msg, ns_rr_t *rr)
{
	int i, rrcount;
	ns_rr_t* p;

	rrcount = ns_rrcount(msg);
	for (i = rrcount - 1; i >= 0; i--) {
		p = msg->rrs + i;
		if (p == rr) {
			ns_rdata_free_opts(rr);
			free(rr->rdata);
			memmove(msg->rrs + i, msg->rrs + i + 1,
				(rrcount - i - 1) * sizeof(ns_rr_t));
			msg->arcount--;
			return 0;
		}
	}

	return -1;
}

ns_rr_t *ns_add_optrr(ns_msg_t *msg)
{
    ns_rr_t *rr, *rrs;

    rrs = realloc(msg->rrs, ((int)ns_rrcount(msg) + 1) * sizeof(ns_rr_t));
    if (rrs == NULL) {
        loge("alloc\n");
        return NULL;
    }
    msg->rrs = rrs;
    rr = msg->rrs + ns_rrcount(msg);
    msg->arcount++;
    memset(rr, 0, sizeof(ns_rr_t));
    rr->type = NS_TYPE_OPT;
    rr->cls = NS_PAYLOAD_SIZE;
    rr->ttl = (NS_EDNS_VERSION << 16) & 0xFF0000;
    return rr;
}

int ns_remove_optrr(ns_msg_t *msg)
{
    int i, rrcount;
    ns_rr_t *rr;

    rrcount = ns_rrcount(msg);
    for (i = rrcount - 1; i >= 0; i--) {
        rr = msg->rrs + i;
        if (rr->type == NS_TYPE_OPT) {
            break;
        }
    }
    if (i >= 0) {
        ns_rdata_free_opts(rr);
        free(rr->rdata);
        memmove(msg->rrs + i, msg->rrs + i + 1,
                (rrcount - i - 1) * sizeof(ns_rr_t));
        msg->arcount--;
        return 0;
    }
    return -1;
}

ns_opt_t *ns_optrr_find_opt(ns_rr_t *rr, uint16_t code)
{
	ns_optlist_t *opts = rr->rdata;
    ns_opt_t *opt;
    int i;
    if (opts != NULL) {
        for (i = 0; i < opts->optcount; i++) {
            opt = opts->opts + i;
            if (opt->code == code) {
                return opt;
            }
        }
    }
    return NULL;
}

int ns_optrr_remove_opt(ns_rr_t *rr, uint16_t code)
{
	ns_optlist_t *opts = rr->rdata;
    ns_opt_t *opt;
    int i;
    if (opts != NULL) {
        for (i = 0; i < opts->optcount; i++) {
            opt = opts->opts + i;
			if (opt->code != code)
				continue;
			ns_free_opt(opt);
			memmove(opts->opts + i, opts->opts + i + 1,
				(opts->optcount - i - 1) * sizeof(ns_opt_t));
			opts->optcount--;
			return 0;
		}
    }
    return -1;
}

ns_opt_t *ns_optrr_new_opt(ns_optlist_t *opts, int optcode)
{
	ns_opt_t *newlist, * opt;

	newlist = realloc(opts->opts, (opts->optcount + 1) * sizeof(ns_opt_t));
	if (newlist == NULL)
		return NULL;
	opts->opts = newlist;
	opt = newlist + opts->optcount;
	opts->optcount++;
	memset(opt, 0, sizeof(ns_opt_t));
	opt->code = optcode;

	return opt;
}

ns_opt_t* ns_optrr_set_opt(ns_rr_t* rr, uint16_t code, uint16_t len, const char *data)
{
	ns_optlist_t* opts = rr->rdata;
	ns_opt_t* opt;

	if (opts == NULL) {
		opts = malloc(sizeof(ns_optlist_t));
		if (opts == NULL)
			return NULL;
		memset(opts, 0, sizeof(ns_optlist_t));
		rr->rdata = opts;
	}

	opt = ns_optrr_find_opt(rr, code);

	if (opt == NULL) {
		opt = ns_optrr_new_opt(opts, code);
		if (opt == NULL)
			return NULL;
	}

	ns_free_opt(opt);

	opt->code = code;
	opt->length = len;
	opt->data = malloc(len);

	if (opt->data == NULL)
		return NULL;

	memcpy(opt->data, data, opt->length);

	return opt;
}

int ns_ecs_parse_subnet(struct sockaddr *addr /*out*/, int *pmask /*out*/, const char *str /*in*/)
{
	char buf[INET6_ADDRSTRLEN], *sp_pos;
	int mask = -1;
	int is_ipv6;

	strncpy(buf, str, INET6_ADDRSTRLEN);
	buf[INET6_ADDRSTRLEN - 1] = '\0';

	sp_pos = strrchr(buf, '/');
	if (sp_pos) {
		*sp_pos = 0;
		mask = atoi(sp_pos + 1);
	}

	is_ipv6 = buf[0] =='[' || strchr(buf, ':');

	if (is_ipv6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
		struct in6_addr *ip = &(addr6->sin6_addr);
		if (inet_pton(AF_INET6, buf, ip) != 1) {
			loge("invalid addr %s: errno=%d, %s\n",
				str, errno, strerror(errno));
			return -1;
		}
		addr6->sin6_family = AF_INET6;
		if (mask == -1) mask = 128;
	}
	else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
		struct in_addr *ip = &(addr4->sin_addr);
		if (inet_pton(AF_INET, buf, ip) != 1) {
			loge("invalid addr %s: errno=%d, %s\n",
				str, errno, strerror(errno));
			return -1;
		}
		addr4->sin_family = AF_INET;
		if (mask == -1) mask = 32;
	}

	*pmask = mask;

	return 0;
}

/* IPv4 */
static int ns_set_ecs4(ns_opt_t* opt, struct sockaddr_in* addr, int srcprefix, int scopeprefix)
{
	stream_t s = STREAM_INIT();
	uint8_t* optdata;
	int addrlen;
	uint8_t saddr[4];
	uint8_t mask = 0xff;

	memcpy(saddr, (uint8_t*)(&addr->sin_addr), 4);

	addrlen = srcprefix / 8;
	if (srcprefix % 8)
		addrlen++;

	if (addrlen > 4)
		addrlen = 4;

	optdata = realloc(opt->data, 4 + addrlen);
	if (optdata == NULL) {
		return -1;
	}
	
	if (srcprefix % 8) {
		mask <<= (8 - (srcprefix % 8));
		saddr[addrlen - 1] &= mask;
	}

	opt->length = 4 + addrlen;
	opt->data = optdata;
	s.array = opt->data;
	s.cap = opt->length;
	if (stream_writei16(&s, ADDR_FAMILY_NUM_IP) != 2)
		return -1;
	if (stream_writei8(&s, srcprefix) != 1)
		return -1;
	if (stream_writei8(&s, scopeprefix) != 1)
		return -1;
	if (stream_write(&s, (const char*)saddr, addrlen) != addrlen)
		return -1;

	return 0;
}

/* IPv6 */
static int ns_set_ecs6(ns_opt_t* opt, struct sockaddr_in6* addr, int srcprefix, int scopeprefix)
{
	stream_t s = STREAM_INIT();
	uint8_t* optdata;
	int addrlen;
	uint8_t saddr[16];
	uint8_t mask = 0xff;

	addrlen = srcprefix / 8;
	if (srcprefix % 8)
		addrlen++;

	if (addrlen > 16)
		addrlen = 16;

	optdata = realloc(opt->data, 4 + addrlen);
	if (optdata == NULL) {
		return -1;
	}

	memcpy(saddr, addr->sin6_addr.s6_addr, 16);

	if (srcprefix % 8) {
		mask <<= (8 - (srcprefix % 8));
		saddr[addrlen - 1] &= mask;
	}

	opt->length = 4 + addrlen;
	opt->data = optdata;
	s.array = opt->data;
	s.cap = opt->length;
	if (stream_writei16(&s, ADDR_FAMILY_NUM_IP6) != 2)
		return -1;
	if (stream_writei8(&s, srcprefix) != 1)
		return -1;
	if (stream_writei8(&s, scopeprefix) != 1)
		return -1;
	if (stream_write(&s, (const char*)saddr, addrlen) != addrlen)
		return -1;

	return 0;
}

int ns_set_ecs(ns_opt_t *opt, struct sockaddr *addr, int srcprefix, int scopeprefix)
{
	if (addr->sa_family == AF_INET) {
		return ns_set_ecs4(opt, (struct sockaddr_in*)addr, srcprefix, scopeprefix);
	}
	else if (addr->sa_family == AF_INET6) {
		return ns_set_ecs6(opt, (struct sockaddr_in6*)addr, srcprefix, scopeprefix);
	}
	else {
		loge("No support family %d\n", addr->sa_family);
		return -1;
	}
}

int ns_optrr_set_ecs(ns_rr_t *rr, struct sockaddr *addr, int srcprefix, int scopeprefix)
{
	ns_optlist_t *opts = rr->rdata;
	ns_opt_t *opt;

	if (opts == NULL) {
		opts = malloc(sizeof(ns_optlist_t));
        if (opts == NULL)
            return -1;
		memset(opts, 0, sizeof(ns_optlist_t));
		rr->rdata = opts;
    }

	opt = ns_optrr_find_ecs(rr);

	if (opt == NULL) {
		opt = ns_optrr_new_opt(opts, NS_OPTCODE_ECS);
		if (opt == NULL)
			return -1;
	}
    
    return ns_set_ecs(opt, addr, srcprefix, scopeprefix);
}

static int serialize_init(serialize_ctx *ctx)
{
	memset(ctx, 0, sizeof(serialize_ctx));
	return 0;
}

static void free_label_childs(label_t *label)
{
	label_t *child = label->childs, *tmp;
	while (child) {
		tmp = child;
		child = child->next;
		free_label_childs(tmp);
		free(tmp);
	}
}

static void serialize_free(serialize_ctx *ctx)
{
	free_label_childs(&ctx->rlabel);
}

static label_t *find_childlabel(label_t *root, str_t *s)
{
	label_t *lbl = root->childs;
	while (lbl) {
		if (strcmp(s->s, lbl->label.s) == 0)
			break;
		lbl = lbl->next;
	}
	return lbl;
}

static label_t *new_child(label_t *root, str_t *s)
{
	label_t *lbl;
	lbl = malloc(sizeof(label_t));
	if (lbl == NULL) {
		return NULL;
	}
	memset(lbl, 0, sizeof(label_t));
	lbl->label = *s;
	lbl->parent = root;

	if (root->childs == NULL) {
		root->childs = lbl;
	}
	else {
		lbl->next = root->childs;
		root->childs = lbl;
	}
	return lbl;
}

static int name_split(str_t *labels, int size, char *name)
{
	int i, num = 0;
	i = indexof_char(name, '.');
	while (i > 0) {
		if (num >= size)
			return -1;
		labels[num].s = name;
		labels[num].len = i;
		num++;
		name += i;
		name++; /* skip '.' */
		i = indexof_char(name, '.');
	}
	return num;
}

static label_t *get_label_seq(serialize_ctx *ctx, char *name)
{
	str_t labels[NS_MAX_LABEL_COUNT];
	int label_num, i;
	label_t *root = &ctx->rlabel, *lbl = NULL;

	label_num = name_split(labels, NS_MAX_LABEL_COUNT, name);
	if (label_num == -1)
		return NULL;

	for (i = label_num - 1; i >= 0; i--) {
		lbl = find_childlabel(root, labels + i);
		if (lbl == NULL) {
			lbl = new_child(root, labels + i);
			if (lbl == NULL)
				return NULL;
		}

		root = lbl;
	}

	return lbl;
}

static int ns_write_domainname_comp(serialize_ctx *ctx, stream_t *s, char *name)
{
	int offset;
	label_t *seq;

	seq = get_label_seq(ctx, name);
	if (seq == NULL)
		return -1;

	while (seq) {
		if (seq->offset > 0) {
			offset = seq->offset | 0xc000;
			if (stream_writei16(s, offset) != 2)
				return -1;
			break;
		}
		else {
			seq->offset = s->pos - ctx->startpos;
			if (stream_writei8(s, seq->label.len) != 1)
				return -1;
			if (stream_write(s, seq->label.s, seq->label.len) != seq->label.len)
				return -1;
		}
		seq = seq->parent;
	}

	return 0;
}

static int ns_write_domainname_nocomp(serialize_ctx *ctx, stream_t *s, char *name)
{
	int i;

	i = indexof_char(name, '.');
	while (i > 0) {
		if (stream_writei8(s, i) != 1)
			return -1;
		if (stream_write(s, name, i) != i)
			return -1;
		name += i;
		name++; /* skip '.' */
		i = indexof_char(name, '.');
	}

	if (stream_writei8(s, 0) != 1)
		return -1;

	return 0;
}

static int ns_write_domainname(serialize_ctx *ctx, stream_t *s, char *name)
{
	if (name != NULL && strlen(name) > 0) {
		if (ctx && ctx->compression) {
			return ns_write_domainname_comp(ctx, s, name);
		}
		else {
			return ns_write_domainname_nocomp(ctx, s, name);
		}
	}
	else {

		if (stream_writei8(s, 0) != 1)
			return -1;

		return 0;
	}
}

static int ns_write_cstring(serialize_ctx *ctx, stream_t *s, char *str)
{
	int len;

	len = str != NULL ? (int)strlen(str) : 0;

	if (stream_writei8(s, len) != 1)
		return -1;

	if (stream_write(s, str, len) != len)
		return -1;

	return 0;
}

static int ns_rdata_write_hinfo(serialize_ctx *ctx, stream_t *s, ns_rr_t *rr)
{
	ns_hinfo_t *hinfo = rr->rdata;
	if (hinfo) {
		if (ns_write_cstring(ctx, s, hinfo->cpu) != 0)
			return -1;
		if (ns_write_cstring(ctx, s, hinfo->os) != 0)
			return -1;
	}
	return 0;
}

static int ns_rdata_write_domainname(serialize_ctx *ctx, stream_t *s, ns_rr_t *rr)
{
	if (ns_write_domainname(ctx, s, rr->rdata) < 0) {
		return -1;
	}
	return 0;
}

static int ns_rdata_write_minfo(serialize_ctx *ctx, stream_t *s, ns_rr_t *rr)
{
	ns_minfo_t *minfo = rr->rdata;

	if (minfo) {
		if (ns_write_domainname(ctx, s, minfo->rmailbx) != 0)
			return -1;
		if (ns_write_domainname(ctx, s, minfo->emailbx) != 0)
			return -1;
	}
	return 0;
}

static int ns_rdata_write_mx(serialize_ctx *ctx, stream_t *s, ns_rr_t *rr)
{
	ns_mx_t *mx = rr->rdata;

	if (mx) {
		if (stream_writei16(s, mx->preference) != 2)
			return -1;
		if (ns_write_domainname(ctx, s, mx->exchange) != 0)
			return -1;
	}
	return 0;
}

static int ns_rdata_write_soa(serialize_ctx *ctx, stream_t *s, ns_rr_t *rr)
{
	ns_soa_t *soa = rr->rdata;

	if (soa) {
		if (ns_write_domainname(ctx, s, soa->mname) != 0)
			return -1;
		if (ns_write_domainname(ctx, s, soa->rname) != 0)
			return -1;
		if (stream_writei32(s, soa->serial) != 4)
			return -1;
		if (stream_writei32(s, soa->refresh) != 4)
			return -1;
		if (stream_writei32(s, soa->retry) != 4)
			return -1;
		if (stream_writei32(s, soa->expire) != 4)
			return -1;
		if (stream_writei32(s, soa->minimum) != 4)
			return -1;
	}

	return 0;
}

static int ns_rdata_write_opts(serialize_ctx *ctx, stream_t *s, ns_rr_t *rr)
{
	ns_optlist_t *opts = rr->rdata;
	ns_opt_t *opt;
	int i;

	if (opts != NULL) {
		for (i = 0; i < opts->optcount; i++) {
			opt = opts->opts + i;

			if (stream_writei16(s, opt->code) != 2)
				return -1;
			if (stream_writei16(s, opt->length) != 2)
				return -1;
			if (stream_write(s, opt->data, opt->length) != opt->length)
				return -1;
		}
	}

	return 0;
}

static int ns_rdata_write_any(serialize_ctx *ctx, stream_t *s, ns_rr_t *rr)
{
	if (rr->rdata != NULL) {
		if (stream_write(s, rr->rdata, rr->rdlength) != rr->rdlength)
			return -1;
	}

	return 0;
}

static int ns_write_rdata(serialize_ctx *ctx, stream_t *s, ns_rr_t *rr)
{
	switch (rr->type) {
	case NS_TYPE_HINFO:
		return ns_rdata_write_hinfo(ctx, s, rr);
	case NS_TYPE_CNAME:
	case NS_TYPE_MB:
	case NS_TYPE_MD:
	case NS_TYPE_MF:
	case NS_TYPE_MG:
	case NS_TYPE_MR:
	case NS_TYPE_NS:
	case NS_TYPE_PTR:
		return ns_rdata_write_domainname(ctx, s, rr);
	case NS_TYPE_MINFO:
		return ns_rdata_write_minfo(ctx, s, rr);
	case NS_TYPE_MX:
		return ns_rdata_write_mx(ctx, s, rr);
	case NS_TYPE_SOA:
		return ns_rdata_write_soa(ctx, s, rr);
	case NS_TYPE_OPT:
		return ns_rdata_write_opts(ctx, s, rr);
	case NS_TYPE_NULL:
	default:
		return ns_rdata_write_any(ctx, s, rr);
	}
}

int ns_serialize(stream_t *s, ns_msg_t *msg, int compression)
{
	serialize_ctx ctx = { 0 };
	int i, rrcount, pos, rdlen, spos = s->pos;
	ns_qr_t *qr;
	ns_rr_t *rr;

#define check(n, c) \
	if ((c) != (n)) { \
		serialize_free(&ctx); \
		return -1; \
	}

	if (serialize_init(&ctx) != 0)
		return -1;

	ctx.compression = compression;
	ctx.startpos = spos;

	check(2, stream_writei16(s, msg->id));
	check(2, stream_writei16(s, msg->flags));
	check(2, stream_writei16(s, msg->qdcount));
	check(2, stream_writei16(s, msg->ancount));
	check(2, stream_writei16(s, msg->nscount));
	check(2, stream_writei16(s, msg->arcount));

	if (ctx.compression) {
		/* find '\0' */
		for (i = s->pos - 1; i >= spos; i--) {
			if (s->array[i] == 0) {
				ctx.rlabel.offset = i - spos;
				break;
			}
		}
	}

	for (i = 0; i < msg->qdcount; i++) {
		qr = msg->qrs + i;
		check(0, ns_write_domainname(&ctx, s, qr->qname));
		check(2, stream_writei16(s, qr->qtype));
		check(2, stream_writei16(s, qr->qclass));
	}

	for (i = 0, rrcount = ns_rrcount(msg);
		i < rrcount; i++) {
		rr = msg->rrs + i;
		check(0, ns_write_domainname(&ctx, s, rr->name));
		check(2, stream_writei16(s, rr->type));
		check(2, stream_writei16(s, rr->cls));
		check(4, stream_writei32(s, rr->ttl));
        pos = s->pos;
		check(2, stream_writei16(s, rr->rdlength));
        check(0, ns_write_rdata(&ctx, s, rr));
        rdlen = s->pos - pos - 2;
        stream_seti16(s, pos, rdlen);
	}

	serialize_free(&ctx);

#undef check

	return (s->pos - spos);
}

static void ns_rdata_print_hinfo(ns_rr_t *rr)
{
	ns_hinfo_t *hinfo = rr->rdata;
	if (hinfo) {
		logv("CPU: %s, OS: %s\n",
			hinfo->cpu,
			hinfo->os);
	}
}

static void ns_rdata_print_minfo(ns_rr_t *rr)
{
	ns_minfo_t *minfo = rr->rdata;

	if (minfo) {
		logv("RMAILBX: %s, EMAILBX: %s\n",
			minfo->rmailbx,
			minfo->emailbx);
	}
}

static void ns_rdata_print_mx(ns_rr_t *rr)
{
	ns_mx_t *mx = rr->rdata;

	if (mx) {
		logv("PREFERENCE: 0x%x, EXCHANGE: %s\n",
			(int)(mx->preference & 0xffff),
			mx->exchange);
	}
}

static void ns_rdata_print_soa(ns_rr_t *rr)
{
	ns_soa_t *soa = rr->rdata;

	if (soa) {
		logv("MNAME: %s, RNAME: %s, SERIAL: 0x%x, REFRESH: 0x%x, RETRY: 0x%x, EXPIRE: 0x%x, MINIMUM: 0x%x\n",
			soa->mname,
			soa->rname,
			soa->serial,
			soa->refresh,
			soa->retry,
			soa->expire,
			soa->minimum);
	}
}

ns_ecs_t* ns_parse_ect(ns_ecs_t *ecs, char *data, int len)
{
	int addrlen, i;
	stream_t ns = STREAM_INIT();
	ns.array = data;
	ns.cap = len;
	ns.size = len;
	ns.pos = 0;

#define check_size(n) \
        if (stream_rsize(&ns) < (n)) { \
            return NULL; \
        }

	memset(ecs, 0, sizeof(ns_ecs_t));

	check_size(2);
	ecs->family = stream_readi16(&ns);
	check_size(2);
	ecs->src_prefix_len = stream_readi8(&ns);
	ecs->scope_prefix_len = stream_readi8(&ns);

	addrlen = ecs->src_prefix_len / 8;
	if (ecs->src_prefix_len % 8)
		addrlen++;

	if (ecs->family == ADDR_FAMILY_NUM_IP) {
		if (addrlen > 4) {
			/* invalid src_prefix_len */
			return NULL;
		}
	}
	else if (ecs->family == ADDR_FAMILY_NUM_IP6) {
		if (addrlen > 16) {
			/* invalid src_prefix_len */
			return NULL;
		}
	}
	else {
		/* invalid family */
		return NULL;
	}

	check_size(addrlen);

	for (i = 0; i < addrlen; i++) {
		((uint8_t *)(&ecs->subnet))[i] = stream_readi8(&ns);
	}

#undef check_size

	return ecs;
}

static void ns_rdata_print_edns(ns_rr_t *rr)
{
	ns_optlist_t *opts = rr->rdata;
	ns_opt_t *opt;
	int i;

	if (opts != NULL) {
		logv("OPTCOUNT: 0x%x\n", opts->optcount);
		for (i = 0; i < opts->optcount; i++) {
			opt = opts->opts + i;

			logv("OPT-CODE: 0x%x, OPT-LEN: 0x%x, OPT-DATA:\n",
				(int)(opt->code & 0xffff),
				(int)(opt->length & 0xffff));
			if (opt->data != NULL) {
				if (opt->code == NS_OPTCODE_ECS) {
					ns_ecs_t ecs;
					if (ns_parse_ect(&ecs, opt->data, opt->length)) {
						char ipname[INET6_ADDRSTRLEN] = { 0 };
						if (ecs.family == ADDR_FAMILY_NUM_IP) {
							inet_ntop(AF_INET, &ecs.subnet, ipname, INET6_ADDRSTRLEN);
						}
						else if (ecs.family == ADDR_FAMILY_NUM_IP6) {
							inet_ntop(AF_INET6, &ecs.subnet, ipname, INET6_ADDRSTRLEN);
						}
						else {
							/*invalid ecs*/
							ipname[0] = '\0';
						}
						logv("ECS %s/%d SCOPE %d\n",
							ipname,
							ecs.src_prefix_len,
							ecs.scope_prefix_len);
					}
					else {
						bprint(opt->data, opt->length);
					}
				}
				else {
					bprint(opt->data, opt->length);
				}
			}
		}
	}
}

static void ns_rdata_print_a(ns_rr_t *rr)
{
	char ipname[INET6_ADDRSTRLEN];
	logv("IPv4: %s\n", inet_ntop(AF_INET, rr->rdata, ipname, INET6_ADDRSTRLEN));
}

static void ns_rdata_print_aaaa(ns_rr_t *rr)
{
	static char ipname[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, rr->rdata, ipname, INET6_ADDRSTRLEN);
	logv("IPv6: %s\n", ipname);
}

static void ns_print_rdata(ns_rr_t *rr)
{
	switch (rr->type) {
	case NS_TYPE_HINFO:
		ns_rdata_print_hinfo(rr);
		break;
	case NS_TYPE_CNAME:
		logv("CNAME: %s\n", rr->rdata);
		break;
	case NS_TYPE_MB:
		logv("MADNAME: %s\n", rr->rdata);
		break;
	case NS_TYPE_MD:
		logv("MADNAME: %s\n", rr->rdata);
		break;
	case NS_TYPE_MF:
		logv("MADNAME: %s\n", rr->rdata);
		break;
	case NS_TYPE_MG:
		logv("MGMNAME: %s\n", rr->rdata);
		break;
	case NS_TYPE_MR:
		logv("NEWNAME: %s\n", rr->rdata);
		break;
	case NS_TYPE_NS:
		logv("NSDNAME: %s\n", rr->rdata);
		break;
	case NS_TYPE_PTR:
		logv("HOSTNAME: %s\n", rr->rdata);
		break;
	case NS_TYPE_MINFO:
		ns_rdata_print_minfo(rr);
		break;
	case NS_TYPE_MX:
		ns_rdata_print_mx(rr);
		break;
	case NS_TYPE_SOA:
		ns_rdata_print_soa(rr);
		break;
	case NS_TYPE_OPT:
		ns_rdata_print_edns(rr);
		break;
	case NS_TYPE_A:
		ns_rdata_print_a(rr);
		break;
	case NS_TYPE_AAAA:
		ns_rdata_print_aaaa(rr);
		break;
	case NS_TYPE_NULL:
	default:
		if (rr->rdata != NULL) {
			bprint(rr->rdata, rr->rdlength);
		}
		break;
	}
}

void ns_print(ns_msg_t *msg)
{
	int i, rrcount;
	ns_qr_t *qr;
	ns_rr_t *rr;
	ns_flags_t flags;

	logv("<<< MSG START >>>\n");
	logv("ID: 0x%x, FLAGS: 0x%x, QDCOUNT: 0x%x, ANCOUNT: 0x%x, NSCOUNT: 0x%x, ARCOUNT: 0x%x\n",
		(int)(msg->id & 0xffff),
		(int)(msg->flags & 0xffff),
		(int)(msg->qdcount & 0xffff),
		(int)(msg->ancount & 0xffff),
		(int)(msg->nscount & 0xffff),
		(int)(msg->arcount & 0xffff));
	flags = ns_get_flags(msg);
	logv("FLAGS:%s%s%s%s%s opcode=%d rcode=%d\n",
		flags.qr ? " qr" : "",
		flags.aa ? " aa" : "",
		flags.tc ? " tc" : "",
		flags.rd ? " rd" : "",
		flags.ra ? " ra" : "",
		flags.opcode,
		flags.rcode);

	for (i = 0; i < msg->qdcount; i++) {
		qr = msg->qrs + i;
		logv("QNAME: %s, QTYPE: 0x%x (%s), QCLASS: 0x%x (%s)\n",
			qr->qname,
			(int)(qr->qtype & 0xffff),
			ns_typename(qr->qtype),
			(int)(qr->qclass & 0xffff),
			ns_classname(qr->qclass));
	}

	for (i = 0, rrcount = ns_rrcount(msg);
		i < rrcount; i++) {
		rr = msg->rrs + i;
		if (rr->type == NS_QTYPE_OPT) {
			logv("NAME: %s, TYPE: 0x%x (%s), PAYLOAD: 0x%x, RCODE: 0x%x, VERSION: 0x%x, Z: 0x%x, RDLEN: 0x%x\n",
				rr->name,
				(int)(rr->type & 0xffff),
				ns_typename(rr->type),
				(int)(rr->cls & 0xffff),
				(int)((rr->ttl >> 24) & 0xff),
				(int)((rr->ttl >> 16) & 0xff),
				(int)(rr->ttl & 0xffff),
				(int)(rr->rdlength & 0xffff));
		}
		else {
			logv("NAME: %s, TYPE: 0x%x (%s), CLASS: 0x%x (%s), TTL: 0x%x, RDLEN: 0x%x\n",
				rr->name,
				(int)(rr->type & 0xffff),
				ns_typename(rr->type),
				(int)(rr->cls & 0xffff),
				ns_classname(rr->cls),
				rr->ttl,
				(int)(rr->rdlength & 0xffff));
		}
		ns_print_rdata(rr);
	}
	logv("<<< MSG END >>>\n");
}

const char *ns_typename(uint16_t type)
{
	static char num[20] = {0};
    switch (type) {
        case NS_QTYPE_A		: return "A";
        case NS_QTYPE_NS	: return "NS";
        case NS_QTYPE_MD	: return "MD";	
        case NS_QTYPE_MF	: return "MF";	
        case NS_QTYPE_CNAME	: return "CNAME";
        case NS_QTYPE_SOA	: return "SOA";
        case NS_QTYPE_MB	: return "MB";	
        case NS_QTYPE_MG	: return "MG";	
        case NS_QTYPE_MR	: return "MR";	
        case NS_QTYPE_NULL	: return "NULL";
        case NS_QTYPE_WKS	: return "WKS";
        case NS_QTYPE_PTR	: return "PTR";
        case NS_QTYPE_HINFO	: return "HINFO";
        case NS_QTYPE_MINFO	: return "MINFO";
        case NS_QTYPE_MX	: return "MX";	
        case NS_QTYPE_TXT	: return "TXT";
        case NS_QTYPE_AAAA	: return "AAAA";
        case NS_QTYPE_OPT	: return "OPT";
        case NS_QTYPE_AXFR	: return "AXFR";
        case NS_QTYPE_MAILB	: return "MAILB";
        case NS_QTYPE_MAILA	: return "MAILA";
        case NS_QTYPE_ANY	: return "ANY";
        default:
			snprintf(num, sizeof(num) - 1, "QTYPE(%d)", (int)type);
			return num;
    }

}

const char *ns_classname(uint16_t cls)
{
	static char num[20] = {0};
    switch (cls) {
        case NS_QCLASS_IN: return "IN";
        case NS_QCLASS_CS: return "CS";
        case NS_QCLASS_CH: return "CH";
        case NS_QCLASS_HS: return "HS";
        case NS_QCLASS_ANY:return "ANY";
        default:
			snprintf(num, sizeof(num) - 1, "QCLASS(%d)", (int)cls);
			return num;
    }
}

static int indexof_char(char *s, int ch)
{
    int i = 0;
    while (*s && (*s) != ch) {
        s++;
        i++;
    }
    if (*s)
        return i;
    else
        return -1;
}

