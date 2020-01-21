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

int req_get_questions(stream_t* s, req_t* req)
{
	ns_msg_t* msg = req->msg;
	int i, r, len = 0;
	for (i = 0; i < msg->qdcount; i++) {
		r = stream_writef(s, i > 0 ? ", %s" : "%s", msg->qrs[i].qname);
		if (r < 0)
			return -1;
		len += r;
	}
	return len;
}

void req_print_questions(req_t* req)
{
	stream_t questions = STREAM_INIT();
	if (req_get_questions(&questions, req) > 0) {
		logi("recv dns request from %s by %s: %s\n",
			req->fromtcp
			? get_sockname(((peer_t*)req->from)->conn.sock)
			: get_addrname((struct sockaddr*)req->from),
			req->fromtcp
				? "tcp"
				: "udp",
			questions);
	}
	stream_free(&questions);
}

