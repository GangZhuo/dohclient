#include "channel_hosts.h"
#include "../rbtree/rbtree.h"
#include "utils.h"
#include "netutils.h"
#include "ns_msg.h"
#include "mleak.h"

#define _M

typedef struct hosts_t {
	CHANNEL_BASE(_M)
	struct rbtree_t dic;
} hosts_t;

typedef struct ipnode_t ipnode_t;

struct ipnode_t {
	int family;
	union {
		struct in_addr  ip4;
		struct in6_addr ip6;
	};
	ipnode_t *next;
};

typedef struct hosts_item_t {
	char *domain;
	ipnode_t *iplist;
	struct rbnode_t node;
} hosts_item_t;

static int rbkeycmp(const void *a, const void *b)
{
	const char *x = a;
	const char *y = b;
	return strcmp(x, y);
}

static ipnode_t *ipnode_new(const void *ip, int family)
{
	ipnode_t *ipnode;

	ipnode = (ipnode_t*)malloc(sizeof(ipnode_t));
	if (!ipnode) {
		loge("ipnode_new() error: alloc\n");
		return NULL;
	}

	memset(ipnode, 0, sizeof(ipnode_t));

	ipnode->family = family;

	if (family == AF_INET) {
		memcpy(&ipnode->ip4, ip, sizeof(struct in_addr));
	}
	else if (family == AF_INET6) {
		memcpy(&ipnode->ip6, ip, sizeof(struct in6_addr));
	}
	else if (family != 0) {
		loge("ipnode_new() error: unknown \"family\" %d\n", family);
		free(ipnode);
		return NULL;
	}

	return ipnode;
}

static hosts_item_t *hosts_item_new(const char *key, const void *ip, int family)
{
	hosts_item_t *item;

	item = (hosts_item_t*)malloc(sizeof(hosts_item_t));
	if (!item) {
		loge("hosts_item_new() error: alloc\n");
		return NULL;
	}

	memset(item, 0, sizeof(hosts_item_t));

	item->domain = strdup(key);
	item->node.key = item->domain;

	if (ip && family) {
		item->iplist = ipnode_new(ip, family);
		if (!item->iplist) {
			free(item->domain);
			free(item);
			return NULL;
		}
	}

	return item;
}

static void hosts_item_destroy(hosts_item_t *item)
{
	ipnode_t *curr, *next;

	if (item) {
		for (curr = item->iplist; curr; curr = next) {
			next = curr->next;
			free(curr);
		}
		free(item->domain);
		free(item);
	}
}

static void hosts_item_rbfree(rbnode_t *node, void *state)
{
	hosts_item_t *item = rbtree_container_of(node, hosts_item_t, node);
	hosts_item_destroy(item);
}

static void destroy(channel_t *ctx)
{
	hosts_t *c = (hosts_t*)ctx;
	rbtree_clear(&c->dic, hosts_item_rbfree, NULL);
	rbtree_init(&c->dic, rbkeycmp);
	free(ctx);
}

static sock_t fdset(channel_t *ctx,
	fd_set *readset, fd_set *writeset, fd_set *errorset)
{
	return 0;
}

static int step(channel_t *ctx,
	fd_set *readset, fd_set *writeset, fd_set *errorset)
{
	return 0;
}

static int query(channel_t *ctx,
	const ns_msg_t *msg,
	channel_query_cb callback, void *state)
{
	hosts_t *c = (hosts_t*)ctx;
	struct rbnode_t *rbn;
	hosts_item_t *item;
	char domain[NS_QNAME_SIZE];
	int family;
	ipnode_t *ip;
	ns_msg_t result = { 0 };
	ns_qr_t qr = { 0 };
	ns_rr_t an = { 0 };

	if (!msg->qrs || msg->qdcount < 1) {
		loge("hosts_query() error: invalid msg (qdcount=%d)\n",
			(int)msg->qdcount);
		return -1;
	}

	if (msg->qrs->qclass != NS_QCLASS_IN) {
		goto error;
	}

	if (msg->qrs->qtype == NS_QTYPE_A) {
		family = AF_INET;
	}
	else if (msg->qrs->qtype == NS_QTYPE_AAAA) {
		family = AF_INET6;
	}
	else {
		goto error;
	}

	strncpy(domain, msg->qrs->qname, sizeof(domain));
	domain[NS_QNAME_SIZE - 1] = '\0';
	domain[strlen(domain) - 1] = '\0'; /* Remove last point */

	rbn = rbtree_lookup(&c->dic, domain);
	if (!rbn) {
		goto error;
	}

	item = rbtree_container_of(rbn, hosts_item_t, node);

	ip = item->iplist;

	while(ip) {
		if (ip->family == family) {
			break;
		}
		ip = ip->next;
	}

	if (!ip) {
		goto error;
	}

	/* TODO: create result */

	result.id = msg->id;
	result.flags.bits.qr = 1;
	result.flags.bits.opcode = 0;
	result.flags.bits.aa = 0;
	result.flags.bits.tc = 0;
	result.flags.bits.ra = 1;
	result.flags.bits.z = 0;
	result.flags.bits.rcode = 0;

	result.qdcount = 1;
	result.qrs = &qr;

	result.ancount = 1;
	result.rrs = &an;

	qr.qname = msg->qrs->qname;
	qr.qclass = msg->qrs->qclass;
	qr.qtype = msg->qrs->qtype;

	an.name = qr.qname;
	an.type = qr.qtype;
	an.cls = qr.qclass;
	an.ttl = 60 * 60; /* 1 hour */
	an.rdlength = family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr);
	an.rdata = family == AF_INET ? (void*)&ip->ip4 : (void*)&ip->ip6;

	logv("hit hosts: %s - %s\n", domain, get_ipname(ip->family, &ip->ip4));

	if (callback)
		callback(ctx, 0, &result, TRUE, FALSE, state);

	return 0;

error:
	if (callback)
		callback(ctx, -1, NULL, TRUE, FALSE, state);

	return 0;
}

int hosts_add(channel_t *ctx, const char *domain, const void *ip, int family)
{
	hosts_t *c = (hosts_t*)ctx;
	hosts_item_t *item;
	struct rbnode_t *rbn;
	ipnode_t *ipnode;

	if (!domain || !ip || !family) {
		loge("hosts_add() error: invalid arguments\n");
		return -1;
	}

	rbn = rbtree_lookup(&c->dic, domain);
	if (!rbn) {
		item = hosts_item_new(domain, ip, family);
		if (!item) {
			loge("hosts_add() error: hosts_item_new() error\n");
			return -1;
		}

		rbtree_insert(&c->dic, &item->node);
		logv("hosts added: %s - %s\n", domain, get_ipname(family, ip));
	}
	else {
		item = rbtree_container_of(rbn, hosts_item_t, node);

		ipnode = ipnode_new(ip, family);
		if (!ipnode) {
			loge("hosts_add() error: ipnode_new() error\n");
			return -1;
		}

		ipnode->next = item->iplist;
		item->iplist = ipnode;

		logv("hosts added: %s - %s\n", domain, get_ipname(family, ip));
	}

	return 0;
}

static char *strspace(char *s)
{
	while (*s) {
		if (*s == ' ' || *s == '\t') {
			return s;
		}
		++s;
	}

	return NULL;
}

static int hosts_parse_file(channel_t *ctx, const char *filename)
{
	char buf[512];
	char *line;
	FILE *fp;
	int r, rownum = 0;
	sockaddr_t addr;
	void *ip;
	int family;

	fp = fopen(filename, "rb");
	if (fp == NULL) {
		loge("hosts_parse_file() error: Can't open hosts: %s\n", filename);
		return -1;
	}

	if (fseek(fp, 0, SEEK_SET) != 0) {
		loge("fseek\n");
		fclose(fp);
		return -1;
	}

	while ((line = fgets(buf, sizeof(buf), fp)) != NULL) {
		char *sp_pos;

		rownum++;

		line = ltrim(line);

		/* skip comments */
		if ((*line) == '#') continue;

		/* remove CRLF */
		sp_pos = strrchr(line, '\r');
		if (sp_pos)
			*sp_pos = 0;
		else if ((sp_pos = strrchr(line, '\n')) != NULL)
			*sp_pos = 0;

		/* skip empty line */
		if (!(*line)) continue;

		/* find end position of the ip address */
		sp_pos = strspace(line);

		if (!sp_pos) {
			logw("hosts_parse_file(): invalid line %d: %s\n", rownum, line);
			continue;
		}

		*sp_pos = '\0';

		memset(&addr, 0, sizeof(sockaddr_t));

		if (!try_parse_as_ip(&addr, line, "80")) {
			logw("hosts_parse_file(): invalid ip address (line %d): %s\n", rownum, line);
			continue;
		}

		/* string that follow the ip address are a domain names */
		line = ltrim(sp_pos + 1);

		if (!(*line)) {
			logw("hosts_parse_file(): no domain name (line %d): %s\n", rownum, ltrim(buf));
			continue;
		}

		/* get ip family and bytes */
		family = addr.addr.ss_family;
		if (family == AF_INET)
			ip = &(((struct sockaddr_in*)(&addr.addr))->sin_addr);
		else
			ip = &(((struct sockaddr_in6*)(&addr.addr))->sin6_addr);

		/* parse domains one by one, and add these to dictionary */
		while (*line) {
			sp_pos = strspace(line);
			if (sp_pos)
				*sp_pos = '\0';
			if (hosts_add(ctx, line, ip, family)) {
				loge("hosts_parse_file() error: hosts_add() error\n");
				fclose(fp);
				return -1;
			}
			if (!sp_pos)
				break;
			else {
				line = ltrim(sp_pos + 1);
			}
		}
	}

	fclose(fp);

	return 0;
}

static int hosts_parse_files(channel_t *ctx, const char *filenames)
{
	char *s, *p;
	int r;

	s = strdup(filenames);

	for (p = strtok(s, ",");
		p && *p;
		p = strtok(NULL, ",")) {

		if (hosts_parse_file(ctx, p)) {
			free(s);
			return -1;
		}
	}

	free(s);

	return r;
}

static int parse_args_callback(char *name, char *value, void *state)
{
	channel_t *ctx = state;

	if (strcmp(name, "hosts") == 0) {
		if (hosts_parse_files(ctx, value)) {
			return -1;
		}
	}

	return 0;
}

int hosts_create(
	channel_t **pctx,
	const char *name,
	const char *args,
	const config_t *conf,
	const proxy_t *proxies,
	const int proxy_num,
	const chnroute_ctx chnr,
	const chnroute_ctx blacklist,
	void *data)
{
	hosts_t *ctx;

	ctx = (hosts_t*)malloc(sizeof(hosts_t));
	if (!ctx) {
		loge("hosts_create() error: alloc\n");
		return CHANNEL_ALLOC;
	}

	memset(ctx, 0, sizeof(hosts_t));

	rbtree_init(&ctx->dic, rbkeycmp);

	ctx->name = name;
	ctx->conf = conf;
	ctx->proxies = proxies;
	ctx->proxy_num = proxy_num;
	ctx->chnr = chnr;
	ctx->blacklist = blacklist;
	ctx->data = data;

	ctx->fdset = fdset;
	ctx->step = step;
	ctx->query = query;
	ctx->destroy = destroy;

	if (args) {
		if (parse_querystring(args, parse_args_callback, ctx)) {
			loge("hosts_create() error: invalid args: %s\n", args);
			return CHANNEL_WRONG_ARG;
		}
	}

	*pctx = (channel_t*)ctx;

	return CHANNEL_OK;
}
