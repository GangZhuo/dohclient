#include "dns_request.h"
#include "log.h"

static int _id = 0;

req_t* new_req(const char* data, int datalen, void* from, int fromlen, int fromtcp)
{
	req_t* req;
	ns_msg_t *msg;

	req = (req_t*)malloc(sizeof(req_t));
	if (!req) {
		loge("new_req() error: alloc");
		return NULL;
	}

	memset(req, 0, sizeof(req_t));

	msg = (ns_msg_t*)malloc(sizeof(ns_msg_t));
	if (!msg) {
		loge("new_req() error: alloc");
		free(req);
		return NULL;
	}

	if (init_ns_msg(msg)) {
		loge("new_req() error: init_ns_msg() error");
		free(msg);
		free(req);
		return NULL;
	}

	if (ns_parse(msg, data, datalen)) {
		loge("new_req() error: ns_parse() error");
		ns_msg_free(msg);
		free(msg);
		free(req);
		return NULL;
	}

	req->msg = msg;
	req->from = from;
	req->fromlen = fromlen;
	req->fromtcp = fromtcp;
	req->id = ++_id;


	return req;
}

void destroy_req(req_t* req)
{
	if (req) {
		if (req->msg) {
			ns_msg_free(req->msg);
			free(req->msg);
		}
	}
}

void _print_req(req_t* req)
{
	ns_msg_t* msg = req->msg;
	ns_print(msg);
}

int get_req_questions(stream_t* s, req_t* req)
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

void print_req_questions(req_t* req)
{
	stream_t questions = STREAM_INIT();
	if (get_req_questions(&questions, req) > 0) {
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

