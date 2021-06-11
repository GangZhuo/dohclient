#include "chnroute.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef WINDOWS
#include "../windows/win.h"
#else
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#endif

#include "utils.h"
#include "log.h"
#include "dllist.h"
#include "mleak.h"

#ifndef FALSE
#define FALSE               0
#endif

#ifndef TRUE
#define TRUE                1
#endif

typedef struct net_mask_t {
	uint32_t net;
	uint32_t mask;
} net_mask_t;

typedef struct net_mask6_t {
	uint32_t net[4];
	uint32_t mask[4];
} net_mask6_t;

typedef struct net_list_t {
	int entries;
	net_mask_t* nets;
	int entries6;
	net_mask6_t* nets6;
} net_list_t;

typedef struct chnroute_item_t {
	dlitem_t entry;
	int is_ipv6;
	union {
		net_mask_t net;
		net_mask6_t net6;
	};
} chnroute_item_t;

typedef struct chnroute_list_t {
	dllist_t items;
	int net_num;
	int net6_num;
} chnroute_list_t;

static int is_ipv6(const char* ip)
{
	return !!strchr(ip, ':');
}

static int cmp_net_mask(const void* a, const void* b)
{
	uint32_t x, y;
	x = ((net_mask_t*)a)->net;
	y = ((net_mask_t*)b)->net;
	if (x < y) return -1;
	else if (x > y) return 1;
	else return 0;
}

static int cmp_net_mask6(const void* a, const void* b)
{
	const net_mask6_t* x = a;
	const net_mask6_t* y = b;
	int i;
	for (i = 0; i < 4; i++) {
		if (x->net[i] < y->net[i]) return -1;
		else if (x->net[i] > y->net[i]) return 1;
	}
	return 0;
}

int chnroute_test4(chnroute_ctx ctx, struct in_addr* ip)
{
	net_list_t* netlist = ctx;
	int l = 0, r;
	int m, cmp;
	net_mask_t ip_net;
	net_mask_t* find;

	if (netlist == NULL || ip == NULL || netlist->entries == 0)
		return FALSE;

	r = netlist->entries - 1;

	ip_net.net = ntohl(ip->s_addr);
	while (l != r) {
		m = (l + r) / 2;
		cmp = cmp_net_mask(&ip_net, &netlist->nets[m]);
		if (cmp < 0) {
			if (r != m)
				r = m;
			else
				break;
		}
		else {
			if (l != m)
				l = m;
			else
				break;
		}
	}
	find = &netlist->nets[l];
	if ((ip_net.net & find->mask) != find->net) {
		return FALSE;
	}
	return TRUE;
}

int chnroute_test6(chnroute_ctx ctx, struct in6_addr* ip)
{
	net_list_t* netlist = ctx;
	int l = 0, r;
	int m, cmp;
	int i;
	net_mask6_t ip_net;
	net_mask6_t* find;

	if (netlist == NULL || ip == NULL || netlist->entries6 == 0)
		return FALSE;

	r = netlist->entries6 - 1;

	memcpy(ip_net.net, ip->s6_addr, 16);
	for (i = 0; i < 4; i++) {
		ip_net.net[i] = ntohl(ip_net.net[i]);
	}
	while (l != r) {
		m = (l + r) / 2;
		cmp = cmp_net_mask6(&ip_net, &netlist->nets6[m]);
		if (cmp < 0) {
			if (r != m)
				r = m;
			else
				break;
		}
		else {
			if (l != m)
				l = m;
			else
				break;
		}
	}
	find = &netlist->nets6[l];
	for (i = 0; i < 4; i++) {
		if ((ip_net.net[i] & find->mask[i]) != find->net[i]) {
			return FALSE;
		}
	}
	return TRUE;
}

int chnroute_test(chnroute_ctx ctx, struct sockaddr* addr)
{
	if (ctx == NULL || addr == NULL) {
		return FALSE;
	}
	if (addr->sa_family == AF_INET) {
		return chnroute_test4(ctx, &((struct sockaddr_in*)addr)->sin_addr);
	}
	else if (addr->sa_family == AF_INET6) {
		return chnroute_test6(ctx, &((struct sockaddr_in6*)addr)->sin6_addr);
	}
	else {
		return FALSE;
	}
}

static int parse_netmask(net_mask_t* netmask, char* line)
{
	char* sp_pos;
	struct in_addr ip;
	sp_pos = strchr(line, '/');
	if (sp_pos) {
		*sp_pos = 0;
		netmask->mask = UINT32_MAX ^ (((uint32_t)1 << (32 - atoi(sp_pos + 1))) - 1);
	}
	else {
		netmask->mask = UINT32_MAX;
	}
	if (inet_pton(AF_INET, line, &ip) == 0) {
		if (sp_pos)* sp_pos = '/';
		loge("invalid addr: %s, errno=%d, %s\n",
			line, errno, strerror(errno));
		return -1;
	}
	netmask->net = ntohl(ip.s_addr);
	if (sp_pos)* sp_pos = '/';
	return 0;
}

static int parse_netmask6(net_mask6_t* netmask, char* line)
{
	char* sp_pos;
	struct in6_addr ip;
	int i, cidr;
	int quotient, remainder;
	sp_pos = strchr(line, '/');
	if (sp_pos) {
		*sp_pos = 0;
		cidr = atoi(sp_pos + 1);
	}
	else {
		cidr = 128;
	}
	if (inet_pton(AF_INET6, line, &ip) == 0) {
		if (sp_pos)* sp_pos = '/';
		loge("invalid addr %s, errno=%d, %s\n",
			line, errno, strerror(errno));
		return -1;
	}
	memcpy(netmask->net, ip.s6_addr, 16);
	for (i = 0; i < 4; i++) {
		netmask->net[i] = ntohl(netmask->net[i]);
	}
	memset(netmask->mask, 0, sizeof(netmask->mask));
	quotient = cidr / 32;
	remainder = cidr % 32;
	for (i = 0; i < quotient; i++)
		netmask->mask[i] = UINT32_MAX;
	if (remainder > 0) {
		netmask->mask[quotient] = (((uint32_t)1 << (32 - remainder)) - 1) ^ UINT32_MAX;
	}
	if (sp_pos)* sp_pos = '/';
	return 0;
}

static void free_chnroute_list(dllist_t* list)
{
	dlitem_t* curr, * next;
	chnroute_item_t* item;

	dllist_foreach(list, curr, next, chnroute_item_t, item, entry) {
		free(item);
	}
}

static int parse_chnroute_file(chnroute_list_t* list, const char* filename)
{
	char buf[512];
	char* line;
	FILE* fp;
	int r, rownum = 0;
	chnroute_item_t* item;

	fp = fopen(filename, "rb");
	if (fp == NULL) {
		loge("Can't open chnroute: %s\n", filename);
		return -1;
	}

	if (fseek(fp, 0, SEEK_SET) != 0) {
		loge("fseek\n");
		fclose(fp);
		return -1;
	}

	while ((line = fgets(buf, sizeof(buf), fp)) != NULL) {
		char* sp_pos;

		rownum++;

		if ((*line) == '#') continue;

		sp_pos = strchr(line, '\r');
		if (sp_pos)* sp_pos = 0;

		sp_pos = strchr(line, '\n');
		if (sp_pos)* sp_pos = 0;

		if (!(*line)) continue;

		item = (chnroute_item_t*)malloc(sizeof(chnroute_item_t));
		if (!item) {
			loge("calloc\n");
			fclose(fp);
			return -1;
		}

		memset(item, 0, sizeof(chnroute_item_t));

		if (is_ipv6(line)) {
			r = parse_netmask6(&item->net6, line);
			item->is_ipv6 = 1;
		}
		else {
			r = parse_netmask(&item->net, line);
		}

		if (r != 0) {
			loge("invalid addr %s in %s:%d\n", line, filename, rownum);
			free(item);
			fclose(fp);
			return -1;
		}
		else {
			dllist_add(&list->items, &item->entry);
			if (item->is_ipv6)
				list->net6_num++;
			else
				list->net_num++;
		}
	}

	fclose(fp);

	return 0;
}

static int feedback_net_list(chnroute_ctx ctx, chnroute_list_t* list)
{
	net_list_t* netlist = ctx;

	netlist->entries = 0;
	netlist->entries6 = 0;

	netlist->nets = calloc(list->net_num, sizeof(net_mask_t));
	if (netlist->nets == NULL) {
		loge("calloc\n");
		return -1;
	}

	netlist->nets6 = calloc(list->net6_num, sizeof(net_mask6_t));
	if (netlist->nets6 == NULL) {
		loge("calloc\n");
		free(netlist->nets);
		return -1;
	}

	{
		dlitem_t* curr, * next;
		chnroute_item_t* item;

		dllist_foreach(&list->items, curr, next, chnroute_item_t, item, entry) {
			if (item->is_ipv6) {
				netlist->nets6[netlist->entries6++] = item->net6;
			}
			else {
				netlist->nets[netlist->entries++] = item->net;
			}
		}
	}

	qsort(netlist->nets, netlist->entries, sizeof(net_mask_t), cmp_net_mask);

	qsort(netlist->nets6, netlist->entries6, sizeof(net_mask6_t), cmp_net_mask6);

	return 0;
}

int chnroute_parse(chnroute_ctx ctx, const char* filename)
{
	char* s, * p, *saveptr = NULL;
	int r;
	chnroute_list_t list;

	memset(&list, 0, sizeof(chnroute_list_t));

	dllist_init(&list.items);

	s = strdup(filename);

	for (p = strtok_r(s, ",", &saveptr);
		p && *p;
		p = strtok_r(NULL, ",", &saveptr)) {

		if (parse_chnroute_file(&list, p)) {
			free_chnroute_list(&list.items);
			free(s);
			return -1;
		}
	}

	free(s);

	r = feedback_net_list(ctx, &list);

	free_chnroute_list(&list.items);

	return r;
}

chnroute_ctx chnroute_create()
{
	net_list_t* netlist = (net_list_t*)malloc(sizeof(net_list_t));
	if (!netlist)
		return NULL;
	memset(netlist, 0, sizeof(net_list_t));
	return netlist;
}

void chnroute_free(chnroute_ctx ctx)
{
	if (ctx) {
		net_list_t* netlist = ctx;
		free(netlist->nets);
		free(netlist->nets6);
		free(netlist);
	}
}
