#ifndef DOHCLIENT_DNS_REQUEST_H_
#define DOHCLIENT_DNS_REQUEST_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "ns_msg.h"
#include "netutils.h"

#ifdef __cplusplus
extern "C" {
#endif

/* dns request */
typedef struct req_t req_t;
struct req_t {
	int id;
	ns_msg_t* msg;
	void* from;
	int fromlen;
	int fromtcp;
	time_t expire;
	dlitem_t entry;
	void* data;
};

req_t* new_req(const char* data, int datalen, void* from, int fromlen, int fromtcp);

void destroy_req(req_t* req);

void _print_req(req_t* req);

#define print_req(req) \
	do { \
		if (loglevel >= LOG_DEBUG) { \
			_print_req((req)); \
		} \
	} while(0)

int get_req_questions(stream_t* s, req_t* req);

void print_req_questions(req_t* req);

#ifdef __cplusplus
}
#endif

#endif
