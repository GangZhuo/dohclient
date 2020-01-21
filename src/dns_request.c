#include "dns_request.h"
#include "log.h"

static int _req_id = 0;

req_t* req_new(const char* data, int datalen, void* from, int fromlen, int fromtcp)
{
	req_t* req;
	ns_msg_t *msg;

	req = (req_t*)malloc(sizeof(req_t));
	if (!req) {
		loge("req_new() error: alloc");
		return NULL;
	}

	memset(req, 0, sizeof(req_t));

	msg = (ns_msg_t*)malloc(sizeof(ns_msg_t));
	if (!msg) {
		loge("req_new() error: alloc");
		free(req);
		return NULL;
	}

	if (init_ns_msg(msg)) {
		loge("req_new() error: init_ns_msg() error");
		free(msg);
		free(req);
		return NULL;
	}

	if (ns_parse(msg, data, datalen)) {
		loge("req_new() error: ns_parse() error");
		ns_msg_free(msg);
		free(msg);
		free(req);
		return NULL;
	}

	req->msg = msg;
	req->from = from;
	req->fromlen = fromlen;
	req->fromtcp = fromtcp;
	req->id = ++_req_id;


	return req;
}

void req_destroy(req_t* req)
{
	if (req) {
		if (req->msg) {
			ns_msg_free(req->msg);
			free(req->msg);
		}
	}
}

void _req_print(req_t* req)
{
	ns_msg_t* msg = req->msg;
	ns_print(msg);
}

