#if DOHCLIENT_CACHE_API
#include "ws.h"
#include "dllist.h"
#include "netutils.h"
#include "log.h"
#include "stream.h"
#include "../http-parser/http_parser.h"
#include "sha1.h"
#include "base64url.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mleak.h"

#define HP_STATE_NONE  0
#define HP_STATE_NAME  1
#define HP_STATE_VALUE 2

#define WS_SALT "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

typedef struct handshake_t {
	char         url[512];
	char         upgrade[50];
	char         connection[50];
	char         ws_key[50];
	char         ws_protocol[50];
	char         ws_version[50];
	http_parser  hp[1];
	char         hp_name[24];
	char         hp_value[24];
	int          hp_state;
} handshake_t;

typedef struct wsctx_t {
	int            is_handshake;
	handshake_t   *hs;
} wsctx_t;

static int on_message_begin(http_parser *parser);
static int on_url(http_parser *parser, const char *at, size_t length);
static int on_header_field(http_parser *parser, const char *at, size_t length);
static int on_header_value(http_parser *parser, const char *at, size_t length);
static int on_headers_complete(http_parser *parser);
static int on_message_complete(http_parser *parser);

static http_parser_settings hp_settings[1] = {{
	.on_message_begin = on_message_begin,
	.on_url = on_url,
	.on_status = NULL,
	.on_header_field = on_header_field,
	.on_header_value = on_header_value,
	.on_headers_complete = on_headers_complete,
	.on_body = NULL,
	.on_message_complete = on_message_complete,
	.on_chunk_header = NULL,
	.on_chunk_complete = NULL,
}};

void wsctx_free(wsctx_t *ctx)
{
	free(ctx);
}

int ws_onrecv(peer_t *peer)
{
	stream_t *s = &peer->conn.rs;
	wsctx_t *c = peer->wsctx;

	logd("ws_onrecv():\n%s\n", s->array + s->pos);

	if (!c) {
		c = (wsctx_t *)malloc(sizeof(wsctx_t));
		if (!c) {
			loge("ws_onrecv() error: alloc\n");
			return -1;
		}
		memset(c, 0, sizeof(wsctx_t));
		peer->wsctx = c;
		peer->is_ws = TRUE;
	}

	if (c->is_handshake) {
		/* TODO: */
	}
	else {
		size_t nparsed;
		handshake_t *hs = c->hs;
		hs = (handshake_t *)malloc(sizeof(handshake_t));
		if (!hs) {
			loge("ws_onrecv() error: alloc\n");
			return -1;
		}
		memset(hs, 0, sizeof(handshake_t));
		http_parser_init(hs->hp, HTTP_REQUEST);
		hs->hp->data = peer;
		c->hs = hs;

		nparsed = http_parser_execute(hs->hp, hp_settings,
				s->array + s->pos, s->size - s->pos);

		if (nparsed <= 0) {
			loge("ws_onrecv() error: %s\n", http_errno_name(hs->hp->http_errno));
			return -1;
		}

		s->pos += nparsed;
	}

	if (s->pos > 0) {
		if (stream_quake(s)) {
			loge("ws_onrecv() error: stream_quake() failed\n");
			return -1;
		}
	}

	return 0;
}

#define safe_free(p) do { if (p) { free(p); p = NULL; } } while(0)

static int strappend(char *to, size_t tosize, const char *at, size_t atlen)
{
	size_t tolen = strlen(to);
	if (tolen < tosize) {
		if (atlen + 1 > tosize - tolen)
			atlen = tosize - tolen - 1;
		memcpy(to + tolen, at, atlen);
		to[tolen + atlen] = '\0';
		return 0;
	}
	return -1;
}

static int on_message_begin(http_parser* parser)
{
	peer_t *peer = parser->data;
	handshake_t *c = peer->wsctx->hs;

	c->url[0] = '\0';
	c->upgrade[0] = '\0';
	c->connection[0] = '\0';
	c->ws_key[0] = '\0';
	c->ws_protocol[0] = '\0';
	c->ws_version[0] = '\0';
	c->hp_name[0] = '\0';
	c->hp_value[0] = '\0';
	c->hp_state = HP_STATE_NONE;
	return 0;
}

static int on_url(http_parser *parser, const char *at, size_t length)
{
	peer_t* peer = parser->data;
	handshake_t* c = peer->wsctx->hs;
	strappend(c->url, sizeof(c->url), at, length);
	return 0;
}

static int on_header_field_complete(http_parser *parser)
{
	peer_t *peer = parser->data;
	handshake_t *c = peer->wsctx->hs;

	/*
	 * GET / HTTP/1.1
	 * Host: 127.0.0.1:5354
	 * Upgrade: websocket
	 * Connection: Upgrade
	 * Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==
	 * Sec-WebSocket-Protocol: chat, superchat
	 * Sec-WebSocket-Version: 13
	 * */
	if (strcasecmp(c->hp_name, "Upgrade") == 0) {
		strncpy(c->upgrade, c->hp_value, sizeof(c->upgrade) - 1);
		logd("Upgrade: %s\n", c->upgrade);
	}
	else if (strcasecmp(c->hp_name, "Connection") == 0) {
		strncpy(c->connection, c->hp_value, sizeof(c->connection) - 1);
		logd("Connection: %s\n", c->connection);
	}
	else if (strcasecmp(c->hp_name, "Sec-WebSocket-Key") == 0) {
		strncpy(c->ws_key, c->hp_value, sizeof(c->ws_key) - 1);
		logd("Sec-WebSocket-Key: %s\n", c->ws_key);
	}
	else if (strcasecmp(c->hp_name, "Sec-WebSocket-Protocol") == 0) {
		strncpy(c->ws_protocol, c->hp_value, sizeof(c->ws_protocol) - 1);
		logd("Sec-WebSocket-Protocol: %s\n", c->ws_protocol);
	}
	else if (strcasecmp(c->hp_name, "Sec-WebSocket-Version") == 0) {
		strncpy(c->ws_version, c->hp_value, sizeof(c->ws_version) - 1);
		logd("Sec-WebSocket-Version: %s\n", c->ws_version);
	}
	else {
		logd("%s: %s\n", c->hp_name, c->hp_value);
	}

	c->hp_name[0] = '\0';
	c->hp_value[0] = '\0';
	c->hp_state = HP_STATE_NONE;

	return 0;
}

static int on_header_field(http_parser *parser, const char *at, size_t length)
{
	peer_t *peer = parser->data;
	handshake_t *c = peer->wsctx->hs;

	if (c->hp_state == HP_STATE_VALUE) {
		if (on_header_field_complete(parser))
			return -1;
	}

	c->hp_state = HP_STATE_NAME;
	strappend(c->hp_name, sizeof(c->hp_name), at, length);
	return 0;
}

static int on_header_value(http_parser *parser, const char *at, size_t length)
{
	peer_t *peer = parser->data;
	handshake_t *c = peer->wsctx->hs;

	c->hp_state = HP_STATE_VALUE;
	strappend(c->hp_value, sizeof(c->hp_value), at, length);

	return 0;
}

static int on_headers_complete(http_parser *parser)
{
	peer_t *peer = parser->data;
	handshake_t *c = peer->wsctx->hs;

	if (c->hp_state != HP_STATE_NONE) {
		if (on_header_field_complete(parser))
			return -1;
	}

	return 0;
}

static char *gen_ws_accept_key(const char *key)
{
	char tmp[512] = {0};
	uint8_t *hash;
	int n = 0;
	sha1nfo s;
	snprintf(tmp, sizeof(tmp) - 1, "%s%s", key, WS_SALT);
	sha1_init(&s);
	sha1_write(&s, tmp, strlen(tmp));
	hash = sha1_result(&s);
	return base64url_encode(hash, 20, &n, TRUE, FALSE);
}

static int on_message_complete(http_parser *parser)
{
	peer_t *peer = parser->data;
	handshake_t *c = peer->wsctx->hs;
	stream_t *s = &peer->conn.ws;
	char *key;
	int is_ws = FALSE;
	int r;

	logd("Http Request: url=%s\n", c->url);

	if (strcasecmp(c->upgrade, "websocket") == 0) {
		if (strlen(c->ws_key) == 0) {
			r = stream_writef(s,
				"HTTP/1.1 400 Bad Request\r\n"
				"Content-Type: text/plain\r\n"
				"Content-Length: 11\r\n"
				"\r\n"
				"Bad Request");
		}
		else {
			key = gen_ws_accept_key(c->ws_key);
			s->pos = 0;
			r = stream_writef(s,
				"HTTP/1.1 101 Switching Protocols\r\n"
				"Connection: Upgrade\r\n"
				"Sec-WebSocket-Accept: %s\r\n"
				"Sec-WebSocket-Protocol: %s\r\n"
				"Upgrade: websocket\r\n"
				"\r\n",
				key,
				strlen(c->ws_protocol) == 0 ? "chat" : c->ws_protocol);
			free(key);
			is_ws = TRUE;
		}
	}
	else if (strlen(c->upgrade) > 0) {
		r = stream_writef(s,
			"HTTP/1.1 400 Bad Request\r\n"
			"Content-Type: text/plain\r\n"
			"Content-Length: 11\r\n"
			"\r\n"
			"Bad Request");
	}
	else if (strcasecmp(c->url, "/") == 0) {
		r = stream_writef(s,
			"HTTP/1.1 200 Ok\r\n"
			"Content-Type: text/plain\r\n"
			"Content-Length: 7\r\n"
			"\r\n"
			"Working");
	}
	else if (strcasecmp(c->url, "/api") == 0) {
		r = stream_writef(s,
			"HTTP/1.1 403 Forbidden\r\n"
			"Content-Type: text/plain\r\n"
			"Content-Length: 9\r\n"
			"\r\n"
			"Forbidden");
	}
	else {
		r = stream_writef(s,
			"HTTP/1.1 404 Not Found\r\n"
			"Content-Type: text/plain\r\n"
			"Content-Length: 9\r\n"
			"\r\n"
			"Not Found");
	}
	
	if (r == -1) {
		loge("Create Response Error: alloc\n");
		return -1;
	}

	logd("Http Response: \n%s\n", s->array);

	s->pos = 0;

	r = tcp_send(peer->conn.sock, s);
	if (r == -1) {
		loge("Send Response Error: %d, %s\n", errno, strerror(errno));
		return -1;
	}

	if (is_ws) {
		peer->wsctx->is_handshake = TRUE;
	}

	return 0;
}
#endif
