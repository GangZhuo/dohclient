#ifndef DOHCLIENT_NS_MSG_H_
#define DOHCLIENT_NS_MSG_H_

#include <stdint.h>
#ifdef WINDOWS
#include "../windows/win.h"
#else
#include <arpa/inet.h>
#endif

#include "stream.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NS_PAYLOAD_SIZE
#define NS_PAYLOAD_SIZE		1024
#endif
#define NS_LABEL_SIZE		63
#define NS_NAME_SIZE		255
#define NS_QNAME_SIZE		NS_NAME_SIZE
#define NS_EDNS_VERSION		0
#define NS_MAX_LABEL_COUNT	512
#define NS_QTYPE_NAME_SIZE	8
#define NS_QCLASS_NAME_SIZE	8
#define REQ_KEY_SIZE		(NS_QNAME_SIZE + NS_QTYPE_NAME_SIZE + NS_QCLASS_NAME_SIZE)

#define NS_QTYPE_A			1
#define NS_QTYPE_NS			2
#define NS_QTYPE_MD			3
#define NS_QTYPE_MF			4
#define NS_QTYPE_CNAME		5
#define NS_QTYPE_SOA		6
#define NS_QTYPE_MB			7
#define NS_QTYPE_MG			8
#define NS_QTYPE_MR			9
#define NS_QTYPE_NULL		10
#define NS_QTYPE_WKS		11
#define NS_QTYPE_PTR		12
#define NS_QTYPE_HINFO		13
#define NS_QTYPE_MINFO		14
#define NS_QTYPE_MX			15
#define NS_QTYPE_TXT		16
#define NS_QTYPE_AAAA		28	
#define NS_QTYPE_OPT		41
#define NS_QTYPE_AXFR		252
#define NS_QTYPE_MAILB		253
#define NS_QTYPE_MAILA		254
#define NS_QTYPE_ANY		255

#define NS_QCLASS_IN		1		
#define NS_QCLASS_CS		2		
#define NS_QCLASS_CH		3		
#define NS_QCLASS_HS		4		
#define NS_QCLASS_ANY		255

#define NS_TYPE_A			NS_QTYPE_A		
#define NS_TYPE_NS			NS_QTYPE_NS		
#define NS_TYPE_MD			NS_QTYPE_MD		
#define NS_TYPE_MF			NS_QTYPE_MF		
#define NS_TYPE_CNAME		NS_QTYPE_CNAME	
#define NS_TYPE_SOA			NS_QTYPE_SOA		
#define NS_TYPE_MB			NS_QTYPE_MB		
#define NS_TYPE_MG			NS_QTYPE_MG		
#define NS_TYPE_MR			NS_QTYPE_MR		
#define NS_TYPE_NULL		NS_QTYPE_NULL	
#define NS_TYPE_WKS			NS_QTYPE_WKS		
#define NS_TYPE_PTR			NS_QTYPE_PTR		
#define NS_TYPE_HINFO		NS_QTYPE_HINFO	
#define NS_TYPE_MINFO		NS_QTYPE_MINFO	
#define NS_TYPE_MX			NS_QTYPE_MX		
#define NS_TYPE_TXT			NS_QTYPE_TXT		
#define NS_TYPE_AAAA		NS_QTYPE_AAAA	
#define NS_TYPE_OPT			NS_QTYPE_OPT		

#define NS_CLASS_IN			NS_QCLASS_IN
#define NS_CLASS_CS			NS_QCLASS_CS
#define NS_CLASS_CH			NS_QCLASS_CH
#define NS_CLASS_HS			NS_QCLASS_HS

#define NS_OPTCODE_ECS      8 /* edns-client-subnet */
#define NS_OPTCODE_SVR		65530 /* customer code, which store the dns server name */

#define ADDR_FAMILY_NUM_IP  1 /*IPv4*/
#define ADDR_FAMILY_NUM_IP6 2 /*IPv6*/

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

typedef struct ns_hinfo_t {
	char *cpu;
	char *os;
} ns_hinfo_t;

typedef struct ns_minfo_t {
	char *rmailbx;
	char *emailbx;
} ns_minfo_t;

typedef struct ns_mx_t {
    uint16_t preference;
    char *exchange;
} ns_mx_t;

typedef struct ns_soa_t {
	char *mname;
	char *rname;
	uint32_t serial;
	uint32_t refresh;
	uint32_t retry;
	uint32_t expire;
	uint32_t minimum;
} ns_soa_t;

typedef struct ns_ecs_t {
	uint16_t family;
	uint8_t src_prefix_len;
	uint8_t scope_prefix_len;
	uint8_t subnet[16];
} ns_ecs_t;

typedef struct ns_opt_t {
	uint16_t code;
	uint16_t length;
	void *data;
} ns_opt_t;

typedef struct ns_optlist_t {
    ns_opt_t *opts;
    int optcount;
} ns_optlist_t;

typedef struct ns_rr_t {
	char *name;
	uint16_t type;
	uint16_t cls; /* class */
	uint32_t ttl; /* second */
	uint16_t rdlength;
	union {
		void* rdata;
		ns_optlist_t *opts;
	};
} ns_rr_t;

typedef struct ns_qr_t {
	char *qname;
	uint16_t qtype;
	uint16_t qclass;
} ns_qr_t;

typedef struct ns_flags_t {
	uint8_t qr : 1;
	uint8_t opcode : 4;
	uint8_t aa : 1;
	uint8_t tc : 1;
	uint8_t rd : 1;

	uint8_t ra : 1;
	uint8_t z : 3;
	uint8_t rcode : 4;
} ns_flags_t;

typedef struct ns_msg_t {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;

	ns_qr_t *qrs;
	ns_rr_t *rrs;
} ns_msg_t;

int init_ns_msg(ns_msg_t *msg);
void ns_msg_free(ns_msg_t *msg);

ns_flags_t ns_get_flags(ns_msg_t *msg);
uint16_t ns_set_flags(ns_msg_t *msg, const ns_flags_t *flags);

int ns_parse(ns_msg_t *msg, const uint8_t *bytes, int nbytes);

uint32_t ns_get_ttl(const ns_msg_t* msg);

ns_rr_t *ns_find_rr(ns_msg_t *msg, int type);

int ns_remove_rr(ns_msg_t* msg, ns_rr_t* rr);

#define ns_find_opt_rr(msg) \
	ns_find_rr((msg), NS_TYPE_OPT)

ns_rr_t *ns_add_optrr(ns_msg_t *msg);

/* remove first find optrr */
int ns_remove_optrr(ns_msg_t *msg);

#define ns_remove_all_optrr(msg) while (ns_remove_optrr(msg) == 0){}

ns_opt_t* ns_optrr_find_opt(ns_rr_t* rr, uint16_t code);

/* remove first find opt */
int ns_optrr_remove_opt(ns_rr_t* rr, uint16_t code);

#define ns_optrr_remove_all_opt(rr, code) while (ns_optrr_remove_opt((msg), (code)) == 0){}

#define ns_optrr_find_ecs(rr) ns_optrr_find_opt((rr), NS_OPTCODE_ECS)
#define ns_optrr_remove_ecs(rr) ns_optrr_remove_opt((rr), NS_OPTCODE_ECS)
#define ns_optrr_remove_all_ecs(rr) while (ns_optrr_remove_ecs(rr) == 0){}

/*create new ns_opt_t, then append to 'opts'. return new created ns_opt_t. */
ns_opt_t* ns_optrr_new_opt(ns_optlist_t* opts, int optcode);

ns_opt_t* ns_optrr_set_opt(ns_rr_t* rr, uint16_t code, uint16_t len, const char* data);

static inline ns_opt_t* ns_find_ecs(ns_msg_t* msg, ns_rr_t** prr)
{
	ns_rr_t* rr;
	ns_opt_t* opt;
	rr = ns_find_opt_rr(msg);
	if (rr == NULL)
		return NULL;
	opt = ns_optrr_find_ecs(rr);
	if (opt == NULL)
		return NULL;
	if (prr) (*prr) = rr;
	return opt;
}

int ns_optrr_set_ecs(ns_rr_t *rr, struct sockaddr *addr, int srcprefix, int scopeprefix);

int ns_serialize(stream_t *s, ns_msg_t *msg, int compression);

void ns_print(ns_msg_t *msg);

const char *ns_typename(uint16_t type);

const char *ns_classname(uint16_t cls);

/* parse subnet like "192.168.1.1/24" */
int ns_ecs_parse_subnet(struct sockaddr *addr /*out*/, int *pmask /*out*/, const char *subnet /*in*/);

static inline int ns_flag_rcode(ns_msg_t *msg)
{
	ns_flags_t flags = ns_get_flags(msg);
	int rcode = (flags.rcode) & 0xf;
	ns_rr_t *rr = ns_find_rr(msg, NS_TYPE_OPT);
	if (rr) {
		rcode |= (rr->ttl >> 20) & 0xff00;
	}
	return rcode;
}

#define ns_is_edns_rr(rr) ((rr)->type == NS_QTYPE_OPT)

#define ns_rrcount(msg) ((msg)->ancount + (msg)->nscount + (msg)->arcount)

ns_qr_t* ns_qr_clone(const ns_qr_t* array, int num);
ns_rr_t* ns_rr_clone(const ns_rr_t* array, int num);
ns_msg_t* ns_msg_clone(const ns_msg_t* msg);
const char* qr_key(const ns_qr_t* qr);
static inline const char* msg_key(const ns_msg_t* msg)
{
	if (!msg || msg->qdcount < 1 || !msg->qrs)
		return NULL;
	return qr_key(msg->qrs);
}
const char* msg_answers(const ns_msg_t* msg);

ns_ecs_t* ns_parse_ect(ns_ecs_t* ecs, char* data, int len);

#ifdef __cplusplus
}
#endif

#endif /*CLEANDNS_NS_MSG_H_*/
