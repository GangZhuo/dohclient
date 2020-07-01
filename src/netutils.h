#ifndef DOHCLIENT_NETUTILS_H_
#define DOHCLIENT_NETUTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>

#ifdef WINDOWS

#include "../windows/win.h"
typedef SOCKET sock_t;

#else /* else WINDOWS */

#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <net/if.h>
#include <ifaddrs.h>

typedef int sock_t;

#endif  /* endif WINDOWS */

#include "utils.h"
#include "log.h"
#include "dllist.h"
#include "stream.h"

#define LISTEN_BACKLOG	128

#ifndef MAX_LISTEN
#define MAX_LISTEN 8
#endif

#ifndef BUF_SIZE
#define BUF_SIZE 4096
#endif

#ifndef MAX_HEADER_SIZE
#define MAX_HEADER_SIZE (1024 * 1024) /* 1MB */
#endif

#ifndef MAX_PROXY
#define MAX_PROXY 8
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef EINPROGRESS
#define EINPROGRESS EAGAIN
#endif

#ifndef WSAEWOULDBLOCK
#define WSAEWOULDBLOCK EINPROGRESS
#endif

#ifndef WSAETIMEDOUT
#define WSAETIMEDOUT ETIMEDOUT
#endif

#ifndef EAI_NODATA
#define EAI_NODATA EAI_NONAME
#endif

#ifndef EAI_ADDRFAMILY
#define EAI_ADDRFAMILY EAI_NODATA
#endif

#ifndef SO_EXCLUSIVEADDRUSE
#define SO_EXCLUSIVEADDRUSE SO_REUSEADDR
#endif

#define is_eagain(err) ((err) == EAGAIN || (err) == EINPROGRESS || (err) == EWOULDBLOCK || (err) == WSAEWOULDBLOCK)

typedef struct sockaddr_t sockaddr_t;
typedef struct conn_t conn_t;
typedef struct peer_t peer_t;

struct sockaddr_t {
	struct sockaddr_storage addr;
	socklen_t addrlen;
};

typedef struct proxy_t {
	sockaddr_t addr;
	int proxy_index;
} proxy_t;

typedef struct listen_t {
	sockaddr_t addr;
	sock_t sock; /* tcp sock */
	sock_t usock; /* udp sock */
} listen_t;

typedef enum conn_status {
	cs_none = 0,
	cs_connecting,
	cs_connected,
	cs_closing, /* close immediately */
	cs_rsp_closing, /* close after send */

	cs_proxy_handshaking,
	cs_proxy_handshaked,

	cs_ssl_handshaking,
	cs_ssl_handshaking_want_read,
	cs_ssl_handshaking_want_write,
	cs_ssl_handshaked,

	cs_error,
	cs_err_create_sock = cs_error, /* error when create sock */
	cs_err_set_nonblock, /* error when set non-block */
	cs_err_connect, /* error when connect the address */
} conn_status;

struct conn_t {
	sock_t sock;
	stream_t rs; /* read stream */
	stream_t ws; /* write stream */
	conn_status status;
	dlitem_t entry;
	time_t expire;
	uint64_t rx; /* receive bytes */
	uint64_t tx; /* transmit bytes */
	/*void* data;*/
};

struct peer_t {
	conn_t conn;
	int listen;
	dllist_t reqs;
	void* data;
};

#define get_addrport(/* struct sockaddr* */a) \
	((a)->addr.ss_family == AF_INET ? \
		((struct sockaddr_in*)(&((a)->addr)))->sin_port :\
		((struct sockaddr_in6*)(&((a)->addr)))->sin6_port)

#ifdef __cplusplus
extern "C" {
#endif

int try_parse_as_ip4(sockaddr_t* addr, const char* host, const char* port);
int try_parse_as_ip6(sockaddr_t* addr, const char* host, const char* port);
int try_parse_as_ip(sockaddr_t* addr, const char* host, const char* port);

int setnonblock(sock_t sock);

int setreuseaddr(sock_t sock);

int setnodelay(sock_t sock);

int getsockerr(sock_t sock);

/* convert sockaddr_in(6) address to string */
char* get_ipname(int family, const void* addr);

/* convert to string (IP:PORT) */
char* get_addrname(const struct sockaddr* addr);

static inline char* get_sockaddrname(const sockaddr_t* addr)
{
	return get_addrname((const struct sockaddr*)(&addr->addr));
}

/* convert to string (IP:PORT) */
char* get_sockname(sock_t sock);

/* parse string (like IP:PORT or [IPv]:PORT) as host and port. :PORT is optional.  */
int parse_host_port(char* s, char** host, char** port, int* ai_family);

int host2addr(sockaddr_t* addr, const char* host, const char* port, int ai_family);

/* convert string (like IP:PORT or [IPv]:PORT) to sockaddr_t.  */
int str2addr(
	const char* s, sockaddr_t* addr,
	const char* default_port);

/* convert string (like IP:PORT,IP:PORT... or [IPv]:PORT,...) to sockaddr_t array. return number of sockaddr_t.  */
int str2addrs(
	const char* str,
	sockaddr_t* addrs,
	int max_num,
	int element_size,
	const char* default_port);

/* convert string (like IP:PORT,IP:PORT... or [IPv]:PORT,...) to listen_t array. return number of listen_t.  */
int str2listens(
	const char* str,
	listen_t* listens,
	int max_num,
	int element_size,
	const char* default_port);


/* create sock, and listen on address. */
int tcp_listen(listen_t* ctx);

/* create sock, and bind on address. */
int udp_listen(listen_t* ctx);

/* create tcp and udp sock, and listen/bind on address. (multi listens) */
int init_listens(listen_t* listens, int listen_num);

void print_listens(const listen_t* listens, int listen_num);


conn_status tcp_connect(const sockaddr_t* addr, sock_t* psock);

int tcp_send(sock_t sock, stream_t* s);

int tcp_recv(sock_t sock, char* buf, int buflen);


int udp_send(sock_t sock, stream_t* s,
	const struct sockaddr* to, int tolen);

int udp_recv(sock_t sock, char* buf, int buflen,
	struct sockaddr* from, int* fromlen);


conn_t* conn_new(sock_t sock);

int conn_init(conn_t* conn, sock_t sock);

void conn_free(conn_t* conn);

void conn_destroy(conn_t* conn);


peer_t* peer_new(sock_t sock, int listen);

int peer_init(peer_t* peer, sock_t sock, int listen);

void peer_free(peer_t* peer);

void peer_destroy(peer_t* peer);


#ifdef __cplusplus
}
#endif

#endif
