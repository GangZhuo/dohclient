#if DOHCLIENT_CACHE_API
#include "httpserver.h"
#include "dllist.h"
#include "netutils.h"
#include "log.h"
#include "stream.h"
#include "../http-parser/http_parser.h"
#include "sha1.h"
#include "base64url.h"
#include "cache_api.h"
#include "utils.h"
#include "channel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mleak.h"

#define HP_STATE_NONE  0
#define HP_STATE_NAME  1
#define HP_STATE_VALUE 2

#define WS_SALT "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define CONTENT_TYPE_URLENCODED "application/x-www-form-urlencoded"

#define URL_MAX        512
#define HNAME_MAX      50       /* Max length of HTTP Header Name  */
#define HVALUE_MAX     50       /* Max length of HTTP Header Value */
#define HREQBODY_MAX   1024     /* Max length of HTTP Request Body */

typedef struct request_t {
	char         url[URL_MAX];
	char         path[URL_MAX];
	char         querystring[URL_MAX];
	char         upgrade[HVALUE_MAX];
	char         connection[HVALUE_MAX];
	char         content_type[HVALUE_MAX];
	char         body[HREQBODY_MAX];
	char         ws_key[HVALUE_MAX];
	char         ws_protocol[HVALUE_MAX];
	char         ws_version[HVALUE_MAX];
	http_parser  hp[1];
	char         hp_name[HNAME_MAX];
	char         hp_value[HVALUE_MAX];
	int          hp_state;
} request_t;

typedef struct hsctx_t {
	int        is_handshake;
	request_t *hs;
} hsctx_t;

static mime_t mimes[] = {
	{ "",       "application/octet-stream" },
	{ "aac",    "audio/aac" },
	{ "abw",    "application/x-abiword" },
	{ "arc",    "application/x-freearc" },
	{ "avi",    "video/x-msvideo" },
	{ "azw",    "application/vnd.amazon.ebook" },
	{ "bin",    "application/octet-stream" },
	{ "bmp",    "image/bmp" },
	{ "bz",     "application/x-bzip" },
	{ "bz2",    "application/x-bzip2" },
	{ "csh",    "application/x-csh" },
	{ "css",    "text/css" },
	{ "csv",    "text/csv" },
	{ "doc",    "application/msword" },
	{ "docx",   "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
	{ "eot",    "application/vnd.ms-fontobject" },
	{ "epub",   "application/epub+zip" },
	{ "gif",    "image/gif" },
	{ "htm",    "text/html" },
	{ "html",   "text/html" },
	{ "ico",    "image/vnd.microsoft.icon" },
	{ "ics",    "text/calendar" },
	{ "jar",    "application/java-archive" },
	{ "jpeg",   "image/jpeg" },
	{ "jpg",    "image/jpeg" },
	{ "js",     "text/javascript" },
	{ "json",   "application/json" },
	{ "jsonld", "application/ld+json" },
	{ "mid",    "audio/midi audio/x-midi" },
	{ "midi",   "audio/midi audio/x-midi" },
	{ "mjs",    "text/javascript" },
	{ "mp3",    "audio/mpeg" },
	{ "mpeg",   "video/mpeg" },
	{ "mpkg",   "application/vnd.apple.installer+xml" },
	{ "odp",    "application/vnd.oasis.opendocument.presentation" },
	{ "ods",    "application/vnd.oasis.opendocument.spreadsheet" },
	{ "odt",    "application/vnd.oasis.opendocument.text" },
	{ "oga",    "audio/ogg" },
	{ "ogv",    "video/ogg" },
	{ "ogx",    "application/ogg" },
	{ "otf",    "font/otf" },
	{ "png",    "image/png" },
	{ "pdf",    "application/pdf" },
	{ "ppt",    "application/vnd.ms-powerpoint" },
	{ "pptx",   "application/vnd.openxmlformats-officedocument.presentationml.presentation" },
	{ "rar",    "application/x-rar-compressed" },
	{ "rtf",    "application/rtf" },
	{ "sh",     "application/x-sh" },
	{ "svg",    "image/svg+xml" },
	{ "swf",    "application/x-shockwave-flash" },
	{ "tar",    "application/x-tar" },
	{ "tif",    "image/tiff" },
	{ "tiff",   "image/tiff" },
	{ "ttf",    "font/ttf" },
	{ "txt",    "text/plain" },
	{ "vsd",    "application/vnd.visio" },
	{ "wav",    "audio/wav" },
	{ "weba",   "audio/webm" },
	{ "webm",   "video/webm" },
	{ "webp",   "image/webp" },
	{ "woff",   "font/woff" },
	{ "woff2",  "font/woff2" },
	{ "xhtml",  "application/xhtml+xml" },
	{ "xls",    "application/vnd.ms-excel" },
	{ "xlsx",   "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" },
	{ "xml",    "text/xml" },
	{ "xul",    "application/vnd.mozilla.xul+xml" },
	{ "zip",    "application/zip" },
	{ "3gp",    "video/3gpp" },
	{ "3g2",    "video/3gpp2" },
	{ "7z",     "application/x-7z-compressed" },
};

static const char *methods[] = {
	"GET", "POST", "HEAD", "PUT", "DELETE",
	"CONNECT", "OPTIONS", "TRACE", "PATCH",
};

static int on_message_begin(http_parser *parser);
static int on_url(http_parser *parser, const char *at, size_t length);
static int on_header_field(http_parser *parser, const char *at, size_t length);
static int on_header_value(http_parser *parser, const char *at, size_t length);
static int on_headers_complete(http_parser *parser);
static int on_body(http_parser *parser, const char *at, size_t length);
static int on_message_complete(http_parser *parser);

static http_parser_settings hp_settings[1] = {{
	.on_message_begin = on_message_begin,
	.on_url = on_url,
	.on_status = NULL,
	.on_header_field = on_header_field,
	.on_header_value = on_header_value,
	.on_headers_complete = on_headers_complete,
	.on_body = on_body,
	.on_message_complete = on_message_complete,
	.on_chunk_header = NULL,
	.on_chunk_complete = NULL,
}};

hsconfig_t hsconf[1] = {{
	.wwwroot = "asset/wwwroot/",
}};

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

int hs_can_parse(char *buf)
{
	int i;
	for (i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
		if (strncmp(buf, methods[i], strlen(methods[i])) == 0)
			return TRUE;
	}
	return FALSE;
}

void hsctx_free(hsctx_t *ctx)
{
	if (ctx->hs)
		free(ctx->hs);
	free(ctx);
}

int hs_onrecv(peer_t *peer)
{
	stream_t *s = &peer->conn.rs;
	hsctx_t *c = peer->hsctx;

	logd("ws_onrecv():\n%s\n", s->array + s->pos);

	if (!c) {
		c = (hsctx_t *)malloc(sizeof(hsctx_t));
		if (!c) {
			loge("ws_onrecv() error: alloc\n");
			return -1;
		}
		memset(c, 0, sizeof(hsctx_t));
		peer->hsctx = c;
		peer->is_hs = TRUE;
	}

	if (c->is_handshake) {
		/* TODO: */
	}
	else {
		size_t nparsed;
		request_t *hs = c->hs;
		hs = (request_t *)malloc(sizeof(request_t));
		if (!hs) {
			loge("ws_onrecv() error: alloc\n");
			return -1;
		}
		memset(hs, 0, sizeof(request_t));
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

static const char *get_mime(const char *filename)
{
	const char *name;
	const char *ext;
	const char *p;
	int         i;

	p = strrchr(filename, '/');
	if ((p = strrchr(filename, '/')) != NULL)
		name = p + 1;
	else if ((p = strrchr(filename, '\\')) != NULL)
		name = p + 1;
	else
		name = filename;

	ext = strrchr(name, '.');
	if ((ext = strrchr(name, '.')) != NULL)
		ext++;
	else
		return mimes[0].mime;

	for (i = 1; i < sizeof(mimes) / sizeof(mimes[0]); i++) {
		if (strcasecmp(ext, mimes[i].ext) == 0) {
			return mimes[i].mime;
		}
	}

	return mimes[0].mime;
}

static int readfile(stream_t *s, const char *filename)
{
	FILE *pf;
	char  buf[4096];
	int   n;

	pf = fopen(filename, "rb");
	if (!pf) {
		loge("readfile() error: Failed to open file %s\n", filename);
		return -1;
	}

	while ((n = fread(buf, 1, sizeof(buf), pf)) > 0) {
		if (stream_appends(s, buf, n) == -1) {
			loge("readfile() error: alloc\n");
			fclose(pf);
			return -1;
		}
	}

	fclose(pf);

	return 0;
}

static int parse_url(peer_t *peer)
{
	request_t *c = peer->hsctx->hs;
	char *p;

	p = strchr(c->url, '?');
	if (p) {
		strappend(c->path, sizeof(c->path), c->url, p - c->url);
		strncpy(c->querystring, p + 1, sizeof(c->querystring));
		p = strchr(c->querystring, '#');
		if (p) {
			*p = '\0';
		}
	}
	else {
		strncpy(c->path, c->url, sizeof(c->path));
	}

	if (strcmp(c->path, "/") == 0) {
		strncpy(c->path, "/index.html", sizeof(c->path));
	}

	return 0;
}

static int get_physical_path(char *buf, int bufsize, const char *path)
{
	int len1 = hsconf->wwwroot ? strlen(hsconf->wwwroot) : 0;
	int len2 = strlen(path);

	if (len1 + len2 + 1 > bufsize) {
		loge("get_physical_path() error: Too small buffer\n");
		return -1;
	}

	if (len1 > 0) {
		memcpy(buf, hsconf->wwwroot, len1);
		if (buf[len1 - 1] != '/' && buf[len1 - 1] != '\\') {
			buf[len1 - 1] = '/';
			len1++;
		}
	}

	/* Skip first slash */
	path++;
	len2--;

	if (len2 > 0) {
		memcpy(buf + len1, path, len2);
	}

	buf[len1 + len2] = '\0';

	return 0;
}

static int run_get(peer_t *peer)
{
	request_t *c = peer->hsctx->hs;
	stream_t *s = &peer->conn.ws;
	char filename[1024];
	stream_t fs[1] = {0};
	int r;

	r = get_physical_path(filename, sizeof(filename), c->path);

	if (r == -1) {
		r = stream_writef(s,
			"HTTP/1.1 400 Bad Request\r\n"
			"Content-Type: text/plain; charset=utf-8\r\n"
			"Cache-Control: no-cache, no-store\r\n"
			"Pragma: no-cache\r\n"
			"Connection: close\r\n"
			"Content-Length: 11\r\n"
			"\r\n"
			"Bad Request");
	}
	else if ((r = readfile(fs, filename)) == -1) {
		r = stream_writef(s,
			"HTTP/1.1 404 Not Found\r\n"
			"Content-Type: text/plain; charset=utf-8\r\n"
			"Cache-Control: no-cache, no-store\r\n"
			"Pragma: no-cache\r\n"
			"Connection: close\r\n"
			"Content-Length: 9\r\n"
			"\r\n"
			"Not Found");
	}
	else {
		r = stream_writef(s,
			"HTTP/1.1 200 Ok\r\n"
			"Content-Type: %s; charset=utf-8\r\n"
			"Cache-Control: no-cache, no-store\r\n"
			"Pragma: no-cache\r\n"
			"Connection: %s\r\n"
			"Content-Length: %d\r\n"
			"\r\n",
			get_mime(filename),
			http_should_keep_alive(c->hp) ? "keep-alive" : "close",
			(int)fs->size);
		if (r == -1 || (r = stream_write(s, fs->array, fs->size)) == -1) {
			loge("run_http_server() error: alloc\n");
			stream_reset(s);
			r = stream_writef(s,
				"HTTP/1.1 500 Internal Server Error\r\n"
				"Content-Type: text/plain; charset=utf-8\r\n"
				"Cache-Control: no-cache, no-store\r\n"
				"Pragma: no-cache\r\n"
				"Connection: close\r\n"
				"Content-Length: 21\r\n"
				"\r\n"
				"Internal Server Error");
		}
		else {
			peer->keep_alive = http_should_keep_alive(c->hp);
		}
	}

	stream_free(fs);

	return r;
}

typedef struct qitem_t {
	const char  *name;
	char        *pvalue;
	size_t       vsize;
} qitem_t;

typedef struct parse_querystring_state_t {
	qitem_t items[4];
	int     num;
} parse_querystring_state_t;

static int cb_parse_querystring(char *name, char *value, void *state)
{
	parse_querystring_state_t *st = state;
	int i;
	int num = st->num;
	for (i = 0; i < num; i++) {
		if (strcasecmp(name, st->items[i].name) == 0) {
			strncpy(st->items[i].pvalue, value, st->items[i].vsize - 1);
			return 0;
		}
	}
	return 0;
}

static int run_post(peer_t *peer)
{
	request_t *c = peer->hsctx->hs;
	stream_t *s = &peer->conn.ws;
	char *json = NULL;
	int r = 0;

	if (strncasecmp(c->content_type, CONTENT_TYPE_URLENCODED,
				sizeof(CONTENT_TYPE_URLENCODED) - 1)) {
		r = -1;
	}
	else if (strcasecmp(c->path, "/api/v1/list") == 0) {
		char offset[10] = {0}, limit[10] = {0};
		char keyword[NS_NAME_SIZE] = {0};
		int off = 0, lim = 0;
		parse_querystring_state_t st[1] = {{
			{
				{ "offset", offset, sizeof (offset) },
				{ "limit",  limit,  sizeof (limit) },
				{ "keyword",keyword,sizeof (keyword) },
			},
			3,
		}};
		parse_querystring(c->body, cb_parse_querystring, st);
		if (*offset)
			off = atoi(offset);
		if (*limit)
			lim = atoi(limit);
		json = cache_api_list(hsconf->cache, keyword, off, lim);
	}
	else if (strcasecmp(c->path, "/api/v1/get") == 0 ||
			strcasecmp(c->path, "/api/v1/delete") == 0) {
		char qtype[10] = {0}, qclass[10] = {0}, qname[NS_NAME_SIZE] = {0};
		char key[NS_NAME_SIZE] = {0};
		parse_querystring_state_t st[1] = {{
			{
				{ "type",  qtype,  sizeof(qtype) }, /* A|AAAA */
				{ "class", qclass, sizeof(qclass) }, /* IN|CS|CH|HS */
				{ "name",  qname,  sizeof(qname) - 1 },
				{ "key",   key,    sizeof(key) - 1 },
			},
			4,
		}};
		parse_querystring(c->body, cb_parse_querystring, st);
		if (!*key) {
			int qnamelen = strlen(qname);
			if (qname[qnamelen - 1] != '.') {
				strncat(qname, ".", sizeof(qname) - 1);
			}
			snprintf(key, sizeof(key) - 1, "%s %s %s", qtype, qclass, qname);
		}
		if (strcasecmp(c->path, "/api/v1/delete") == 0)
			json = cache_api_delete(hsconf->cache, key);
		else
			json = cache_api_get(hsconf->cache, key);
	}
	else if (strcasecmp(c->path, "/api/v1/put") == 0) {
		char qtype[10] = {0}, ip[INET6_ADDRSTRLEN + 1] = {0},
			 qname[NS_NAME_SIZE] = {0}, ttl[10] = {0};
		parse_querystring_state_t st[1] = {{
			{
				{ "type",  qtype,  sizeof(qtype) }, /* A|AAAA */
				{ "ip",    ip,     sizeof(ip) },
				{ "name",  qname,  sizeof(qname) },
				{ "ttl",   ttl,    sizeof(ttl) },
			},
			4,
		}};
		parse_querystring(c->body, cb_parse_querystring, st);
		json = cache_api_put(hsconf->cache, qname, qtype, ip, ttl);
	}
	else {
		r = -1;
	}

	if (!json)
		r = -1;
	else {
		int len = strlen(json);
		r = stream_writef(s,
			"HTTP/1.1 200 Ok\r\n"
			"Content-Type: %s; charset=utf-8\r\n"
			"Cache-Control: no-cache, no-store\r\n"
			"Pragma: no-cache\r\n"
			"Connection: %s\r\n"
			"Content-Length: %d\r\n"
			"\r\n",
			get_mime("json"),
			http_should_keep_alive(c->hp) ? "keep-alive" : "close",
			len);
		if (r == -1 || (r = stream_writes(s, json, len)) == -1) {
			loge("run_http_server() error: alloc\n");
			stream_reset(s);
			r = stream_writef(s,
				"HTTP/1.1 500 Internal Server Error\r\n"
				"Content-Type: text/plain; charset=utf-8\r\n"
				"Cache-Control: no-cache, no-store\r\n"
				"Pragma: no-cache\r\n"
				"Connection: close\r\n"
				"Content-Length: 21\r\n"
				"\r\n"
				"Internal Server Error");
		}
		else {
			peer->keep_alive = http_should_keep_alive(c->hp);
		}
		safe_free(json);
	}

	if (r == -1) {
		r = stream_writef(s,
			"HTTP/1.1 400 Bad Request\r\n"
			"Content-Type: text/plain; charset=utf-8\r\n"
			"Cache-Control: no-cache, no-store\r\n"
			"Pragma: no-cache\r\n"
			"Connection: close\r\n"
			"Content-Length: 11\r\n"
			"\r\n"
			"Bad Request");
	}

	return r;
}

static int run_http_server(peer_t *peer)
{
	request_t *c = peer->hsctx->hs;
	stream_t *s = &peer->conn.ws;
	int r;

	logd("Http Request: url=%s\n", c->url);

	parse_url(peer);

	switch (c->hp->method) {
		case HTTP_GET:
			r = run_get(peer);
			break;
		case HTTP_POST:
			r = run_post(peer);
			break;
		default:
			r = stream_writef(s,
				"HTTP/1.1 400 Bad Request\r\n"
				"Content-Type: text/plain; charset=utf-8\r\n"
				"Cache-Control: no-cache, no-store\r\n"
				"Pragma: no-cache\r\n"
				"Connection: close\r\n"
				"Content-Length: 11\r\n"
				"\r\n"
				"Bad Request");
			break;
	}

	if (r == -1) {
		loge("Create Response Error: alloc\n");
		return -1;
	}

	s->pos = 0;

	logd("Http Response:\n%s\n", s->array);

	r = tcp_send(peer->conn.sock, s);
	if (r == -1) {
		loge("Send Response Error: %d, %s\n", errno, strerror(errno));
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

static int run_websocket(peer_t *peer)
{
	request_t *c = peer->hsctx->hs;
	stream_t *s = &peer->conn.ws;
	int r;

	if (strcasecmp(c->upgrade, "websocket") || strlen(c->ws_key) == 0) {
		r = stream_writef(s,
			"HTTP/1.1 400 Bad Request\r\n"
			"Content-Type: text/plain\r\n"
			"Content-Length: 11\r\n"
			"\r\n"
			"Bad Request");
	}
	else {
		char *key;
		key = gen_ws_accept_key(c->ws_key);
		s->pos = 0;
		r = stream_writef(s,
			"HTTP/1.1 101 Switching Protocols\r\n"
			"Connection: Upgrade\r\n"
			"Sec-WebSocket-Accept: %s\r\n"
			"Upgrade: websocket\r\n"
			"\r\n", key);
		free(key);
	}

	logd("Http Response: \n%s\n", s->array);

	s->pos = 0;

	r = tcp_send(peer->conn.sock, s);
	if (r == -1) {
		loge("Send Response Error: %d, %s\n", errno, strerror(errno));
		return -1;
	}

	peer->hsctx->is_handshake = TRUE;
	peer->keep_alive = TRUE;

	return 0;
}

static int on_message_begin(http_parser* parser)
{
	peer_t *peer = parser->data;
	request_t *c = peer->hsctx->hs;

	c->url[0] = '\0';
	c->path[0] = '\0';
	c->querystring[0] = '\0';
	c->upgrade[0] = '\0';
	c->connection[0] = '\0';
	c->content_type[0] = '\0';
	c->body[0] = '\0';
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
	peer_t *peer = parser->data;
	request_t* c = peer->hsctx->hs;
	strappend(c->url, sizeof(c->url), at, length);
	return 0;
}

static int on_header_field_complete(http_parser *parser)
{
	peer_t *peer = parser->data;
	request_t *c = peer->hsctx->hs;

	if (strcasecmp(c->hp_name, "Upgrade") == 0) {
		strncpy(c->upgrade, c->hp_value, sizeof(c->upgrade) - 1);
		logd("Upgrade: %s\n", c->upgrade);
	}
	else if (strcasecmp(c->hp_name, "Connection") == 0) {
		strncpy(c->connection, c->hp_value, sizeof(c->connection) - 1);
		logd("Connection: %s\n", c->connection);
	}
	else if (strcasecmp(c->hp_name, "Content-Type") == 0) {
		strncpy(c->content_type, c->hp_value, sizeof(c->content_type) - 1);
		logd("Content-Type: %s\n", c->content_type);
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
	request_t *c = peer->hsctx->hs;

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
	request_t *c = peer->hsctx->hs;

	c->hp_state = HP_STATE_VALUE;
	strappend(c->hp_value, sizeof(c->hp_value), at, length);

	return 0;
}

static int on_headers_complete(http_parser *parser)
{
	peer_t *peer = parser->data;
	request_t *c = peer->hsctx->hs;

	if (c->hp_state != HP_STATE_NONE) {
		if (on_header_field_complete(parser))
			return -1;
	}

	return 0;
}

static int on_body(http_parser *parser, const char *at, size_t length)
{
	peer_t *peer = parser->data;
	request_t* c = peer->hsctx->hs;
	strappend(c->body, sizeof(c->body), at, length);
	return 0;
}

static int on_message_complete(http_parser *parser)
{
	peer_t *peer = parser->data;
	request_t *c = peer->hsctx->hs;

	if (strlen(c->upgrade) > 0) {
		return run_websocket(peer);
	}
	else {
		return run_http_server(peer);
	}
}
#endif
