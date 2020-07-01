#ifndef DOHCLIENT_HTTP_H_
#define DOHCLIENT_HTTP_H_

#include <stdint.h>
#ifdef WINDOWS
#include "../windows/win.h"
#else
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#endif

#include "config.h"
#include "netutils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_HTTP_TIMEOUT 5000

#define HTTP_OK			0
#define HTTP_ABORT		1
#define HTTP_TIMEOUT	2
#define HTTP_ERROR		3


typedef struct http_ctx_t http_ctx_t;

typedef struct http_request_t http_request_t;

typedef struct http_response_t http_response_t;

typedef void (*http_callback_fun_t)(
	int status,
	http_request_t* request,
	http_response_t* response,
	void* state);

int http_init(const config_t* conf);

void http_uninit();

http_request_t* http_request_create(
	const char* method, const char* path,
	const char* host);

void http_request_destroy(http_request_t* request);

const char* http_request_get_header(http_request_t* request,
	const char* name);

int http_request_set_header(http_request_t* request,
	const char* name, const char* value);

const char* http_request_get_method(http_request_t* request);

void http_request_set_method(http_request_t* request,
	const char* value);

const char* http_request_get_path(http_request_t* request);

void http_request_set_path(http_request_t* request,
	const char* value);

const char* http_request_get_host(http_request_t* request);

void http_request_set_host(http_request_t* request,
	const char* value);

const char* http_request_get_data(http_request_t* request, int* data_len);

void http_request_set_data(http_request_t* request,
	const char* data, int data_len);

int http_request_header_next(http_request_t* request, struct dliterator_t* iterator,
	const char** name, const char** value);

http_response_t* http_response_create();

void http_response_destroy(http_response_t* response);

int http_response_get_status_code(http_response_t* response, const char** status_text);

int http_response_header_next(http_response_t* response, struct dliterator_t* iterator,
	const char** name, const char** value);

const char* http_response_get_header(http_response_t* response,
	const char* name);

int http_response_add_header(http_response_t* response,
	const char* name, const char* value);

int http_response_set_header(http_response_t* response,
	const char* name, const char* value);

http_ctx_t* http_create(int timeout);

void http_destroy(http_ctx_t* ctx);

sock_t http_fdset(http_ctx_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset);

int http_step(http_ctx_t* ctx,
	fd_set* readset, fd_set* writeset, fd_set* errorset);

int http_send(http_ctx_t* ctx, sockaddr_t* addr, http_request_t* request,
	http_callback_fun_t callback, void* state);

#ifdef __cplusplus
}
#endif

#endif
