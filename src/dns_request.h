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
	dlitem_t entry1;
	void* data;
};

req_t* req_new(const char* data, int datalen, void* from, int fromlen, int fromtcp);

void req_destroy(req_t* req);

void _req_print(req_t* req);

#define req_print(req) \
	do { \
		if (loglevel >= LOG_DEBUG) { \
			_req_print((req)); \
		} \
	} while(0)

int req_get_questions(stream_t* s, req_t* req);

void req_print_questions(req_t* req);

#ifdef __cplusplus
}
#endif

#endif
