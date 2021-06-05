#include "netutils.h"
#include <time.h>
#include <assert.h>
#include "mleak.h"

const sockaddr_t empty_sockaddr[1] = {0};

int try_parse_as_ip4(sockaddr_t* addr, const char* host, const char* port)
{
	struct sockaddr_in* in = (struct sockaddr_in*)(&addr->addr);

	if (inet_pton(AF_INET, host, &in->sin_addr) == 1) {
		in->sin_family = AF_INET;
		in->sin_port = htons(atoi(port));
		addr->addrlen = sizeof(struct sockaddr_in);
		return TRUE;
	}

	return FALSE;
}

int try_parse_as_ip6(sockaddr_t* addr, const char* host, const char* port)
{
	struct sockaddr_in6* in = (struct sockaddr_in6*)(&addr->addr);

	if (inet_pton(AF_INET6, host, &in->sin6_addr) == 1) {
		in->sin6_family = AF_INET6;
		in->sin6_port = htons(atoi(port));
		addr->addrlen = sizeof(struct sockaddr_in);
		return TRUE;
	}

	return FALSE;
}

int try_parse_as_ip(sockaddr_t* addr, const char* host, const char* port)
{
	if (try_parse_as_ip4(addr, host, port))
		return TRUE;

	return try_parse_as_ip6(addr, host, port);
}

int setnonblock(sock_t sock)
{
#ifdef WINDOWS
	int iResult;
	/* If iMode!=0, non-blocking mode is enabled.*/
	u_long iMode = 1;
	iResult = ioctlsocket(sock, FIONBIO, &iMode);
	if (iResult != NO_ERROR) {
		loge("ioctlsocket() error: result=%ld, errno=%d, %s\n",
			iResult, errno, strerror(errno));
		return -1;
	}
#else
	int flags;
	flags = fcntl(sock, F_GETFL, 0);
	if (flags == -1) {
		loge("fcntl() error: errno=%d, %s\n", errno, strerror(errno));
		return -1;
	}
	if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
		loge("fcntl() error: errno=%d, %s\n", errno, strerror(errno));
		return -1;
	}
#endif

	return 0;
}

int setreuseaddr(sock_t sock)
{
	int opt = 1;

	if (setsockopt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&opt, sizeof(opt)) != 0) {
		loge("setsockopt() error: errno=%d, %s\n", errno, strerror(errno));
		return -1;
	}

	return 0;
}

int setnodelay(sock_t sock)
{
	int opt = 1;

	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&opt, sizeof(opt)) != 0) {
		loge("setsockopt() error: errno=%d, %s\n", errno, strerror(errno));
		return -1;
	}

	return 0;
}

int getsockerr(sock_t sock)
{
	int err = 0;
	int len = sizeof(int);
	if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)& err, &len) < 0)
		return errno;
	return err;
}

char* get_ipname(int family, const void* addr)
{
	static char sip[INET6_ADDRSTRLEN];
	inet_ntop(family, addr, sip, sizeof(sip));
	return sip;
}

char* get_addrname(const struct sockaddr* addr)
{
	static char addrname[INET6_ADDRSTRLEN + 16];
	char sip[INET6_ADDRSTRLEN];
	if (addr->sa_family == AF_INET) {
		const struct sockaddr_in* addr_in = (const struct sockaddr_in*)addr;
		inet_ntop(AF_INET, &addr_in->sin_addr, sip, sizeof(sip));
		snprintf(addrname, sizeof(addrname), "%s:%d", sip,
			(int)(htons(addr_in->sin_port) & 0xFFFF));
	}
	else if (addr->sa_family == AF_INET6) {
		const struct sockaddr_in6* addr_in6 = (const struct sockaddr_in6*)addr;
		inet_ntop(AF_INET6, &addr_in6->sin6_addr, sip, sizeof(sip));
		snprintf(addrname, sizeof(addrname), "[%s]:%d", sip,
			(int)(htons(addr_in6->sin6_port) & 0xFFFF));
	}
	else {
		addrname[0] = '\0';
	}
	return addrname;
}

char* get_sockname(sock_t sock)
{
	static char buffer[INET6_ADDRSTRLEN + 16] = { 0 };
	char sip[INET6_ADDRSTRLEN];
	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);
	int err = getpeername(sock, (struct sockaddr*) & addr, &len);
	if (err != 0)
		return NULL;
	if (addr.ss_family == AF_INET) {
		struct sockaddr_in* s = (struct sockaddr_in*) & addr;
		inet_ntop(AF_INET, &s->sin_addr, sip, sizeof(sip));
		snprintf(buffer, sizeof(buffer), "%s:%d", sip,
			(int)(htons(s->sin_port) & 0xFFFF));
		return buffer;
	}
	else if (addr.ss_family == AF_INET6) {
		struct sockaddr_in6* s = (struct sockaddr_in6*) & addr;
		inet_ntop(AF_INET6, &s->sin6_addr, sip, sizeof(sip));
		snprintf(buffer, sizeof(buffer), "[%s]:%d", sip,
			(int)(htons(s->sin6_port) & 0xFFFF));
		return buffer;
	}
	return NULL;
}

int parse_host_port(char* s, char** host, char** port, int* ai_family)
{
	char* p;
	int cnt = 0;

	/* ipv6 */
	if (*s == '[') {
		p = strrchr(s, ']');
		if (p) {
			*host = s + 1;
			*p = '\0';
			p++;
			if (*p == ':')
				* port = p + 1;
			else
				*port = NULL;
			*ai_family = AF_INET6;
			return 0;
		}
		else {
			return -1;
		}
	}

	p = strrchr(s, ':');
	if (p) {
		*port = p + 1;
		*p = '\0';
	}
	else {
		*port = NULL;
	}

	*host = s;
	*ai_family = AF_INET;

	return 0;
}

int host2addr(sockaddr_t* addr, const char* host, const char* port, int ai_family)
{
	struct addrinfo hints;
	struct addrinfo* addrinfo;
	int r;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = ai_family;
	hints.ai_socktype = SOCK_STREAM;

	r = getaddrinfo(host, port, &hints, &addrinfo);

	if (r != 0)
	{
		loge("host2addr() error: retval=%d %s %s:%s\n",
			r, gai_strerror(r), host, port);
		return -1;
	}

	memcpy(&addr->addr, addrinfo->ai_addr, addrinfo->ai_addrlen);
	addr->addrlen = (int)addrinfo->ai_addrlen;

	freeaddrinfo(addrinfo);

	return 0;
}

int str2addr(
	const char* s, sockaddr_t* addr,
	const char* default_port)
{
	char* copy = strdup(s);
	char* host, * port;
	int ai_family;
	int r;

	if (parse_host_port(copy, &host, &port, &ai_family)) {
		free(copy);
		return -1;
	}

	if (!port || strlen(port) == 0)
		port = (char*)default_port;

	r = host2addr(addr, host, port, ai_family);

	free(copy);

	return r;
}

int str2addrs(
	const char* str,
	sockaddr_t* addrs,
	int max_num,
	int element_size,
	const char* default_port)
{
	char* s, * p, *saveptr = NULL;
	int i;
	sockaddr_t* addr;

	s = strdup(str);

	for (i = 0, p = strtok_r(s, ",", &saveptr);
		p && *p && i < max_num;
		p = strtok_r(NULL, ",", &saveptr)) {

		addr = (sockaddr_t*)(((char*)addrs) + (size_t)element_size * i);

		if (str2addr(p, addr, default_port)) {
			free(s);
			loge("str2addrs() error: resolve \"%s\" failed\n", str);
			return -1;
		}

		i++;
	}

	free(s);

	return i;
}

static char *get_proxy_type(char *s, int *proxy_type)
{
	char *p;

	p = strstr(s, "://");

	if (!p) {
		/* socks5 default */
		*proxy_type = SOCKS5_PROXY;
		return s;
	}

	*p = '\0';
	if (strcmp(s, "socks5") == 0) {
		*proxy_type = SOCKS5_PROXY;
	}
	else if (strcmp(s, "http") == 0) {
		*proxy_type = HTTP_PROXY;
	}
	else {
		loge("get_proxy_type() error: unsupport proxy(%s), "
			"only \"socks5\" and \"http\" supported\n", s);
		*p = ':'; /* restore */
		return NULL;
	}

	*p = ':'; /* restore */
	p += strlen("://");

	return p;
}

static char *get_proxy_username_and_password(char *s, char *username, char *password)
{
	char *p, *colon;

	p = strchr(s, '@');

	if (!p) {
		*username = '\0';
		*password = '\0';
		return s;
	}

	*p = '\0';
	colon = strchr(s, ':');

	if (colon) {
		*colon = '\0';
		strncpy(username, s, PROXY_USERNAME_LEN - 1);
		strncpy(password, colon + 1, PROXY_PASSWORD_LEN - 1);
		*colon = ':';
	}
	else {
		strncpy(username, s, PROXY_USERNAME_LEN - 1);
		*password = '\0';
	}

	/* restore */
	*p = '@';

	if (strlen(username) == 0) {
		loge("get_proxy_username_and_password() error: no username\n");
		return NULL;
	}
	if (strlen(password) == 0) {
		loge("get_proxy_username_and_password() error: no password\n");
		return NULL;
	}

	++p;

	return p;
}

static const char *get_proxy_default_port(int proxy_type)
{
	switch (proxy_type) {
		case SOCKS5_PROXY: return "1080";
		case HTTP_PROXY: return "80";
		default: return NULL;
	}
}

int str2proxy(const char *s, proxy_t *proxy)
{
	char *copy = strdup(s), *p;
	char *host, *port;
	int ai_family;
	int r;

	p = get_proxy_type(copy, &proxy->proxy_type);
	if (!p) {
		free(copy);
		return -1;
	}

	p = get_proxy_username_and_password(p, proxy->username, proxy->password);
	if (!p) {
		free(copy);
		return -1;
	}

	if (parse_host_port(p, &host, &port, &ai_family)) {
		free(copy);
		return -1;
	}

	if (!port || strlen(port) == 0) {
		port = (char*)get_proxy_default_port(proxy->proxy_type);
		assert(port);
	}

	r = host2addr(&proxy->addr, host, port, ai_family);

	free(copy);

	return r;
}

int str2proxies(
	const char* str,
	proxy_t* proxies,
	int max_num)
{
	char* s, * p, *saveptr = NULL;
	int i;
	proxy_t* proxy;

	s = strdup(str);

	for (i = 0, p = strtok_r(s, ",", &saveptr);
		p && *p && i < max_num;
		p = strtok_r(NULL, ",", &saveptr)) {

		proxy = proxies + i;

		if (str2proxy(p, proxy)) {
			free(s);
			loge("str2proxies() error: resolve \"%s\" failed\n", str);
			return -1;
		}

		i++;
	}

	free(s);

	return i;
}

int str2listens(
	const char* str,
	listen_t * listens,
	int max_num,
	int element_size,
	const char* default_port)
{
	int listen_num;

	memset(listens, 0, (size_t)element_size * max_num);

	listen_num = str2addrs(
		str,
		&listens[0].addr,
		max_num,
		element_size,
		default_port);

	if (listen_num == -1) {
		loge("str2listens() error: parse \"%s\" failed\n",
			str);
		return -1;
	}

	return listen_num;
}

int tcp_listen(listen_t* ctx)
{
	sockaddr_t* addr;
	struct sockaddr* sockaddr;
	sock_t sock;

	addr = &ctx->addr;
	sockaddr = (struct sockaddr*)(&addr->addr);

	sock = socket(sockaddr->sa_family, SOCK_STREAM, IPPROTO_TCP);

	if (sock == -1) {
		loge("tcp_listen() error: create socket error. errno=%d, %s\n", errno, strerror(errno));
		return -1;
	}

	if (setnonblock(sock) != 0) {
		loge("tcp_listen() error: set sock non-block failed\n");
		close(sock);
		return -1;
	}

	if (setreuseaddr(sock) != 0) {
		loge("tcp_listen() error: set sock reuse address failed\n");
		close(sock);
		return -1;
	}

	if (bind(sock, sockaddr, addr->addrlen) != 0) {
		loge("tcp_listen() error: bind() error: %s errno=%d, %s\n",
			get_sockaddrname(addr), errno, strerror(errno));
		close(sock);
		return -1;
	}

	if (listen(sock, LISTEN_BACKLOG) != 0) {
		loge("tcp_listen() error: listen() error: %s errno=%d, %s\n",
			get_sockaddrname(addr), errno, strerror(errno));
		close(sock);
		return -1;
	}

	ctx->sock = sock;

	return 0;
}

int udp_listen(listen_t* ctx)
{
	sockaddr_t* addr;
	struct sockaddr* sockaddr;
	sock_t sock;

	addr = &ctx->addr;
	sockaddr = (struct sockaddr*)(&addr->addr);

	sock = socket(sockaddr->sa_family, SOCK_DGRAM, IPPROTO_UDP);

	if (sock == -1) {
		loge("udp_listen() error: create socket error. errno=%d, %s\n", errno, strerror(errno));
		return -1;
	}

	if (setnonblock(sock) != 0) {
		loge("udp_listen() error: set sock non-block failed\n");
		close(sock);
		return -1;
	}

	if (setreuseaddr(sock) != 0) {
		loge("udp_listen() error: set sock reuse address failed\n");
		close(sock);
		return -1;
	}

#ifdef WINDOWS
	disable_udp_connreset(sock);
#endif

	if (bind(sock, sockaddr, addr->addrlen) != 0) {
		loge("udp_listen() error: bind() error: %s errno=%d, %s\n",
			get_sockaddrname(addr), errno, strerror(errno));
		close(sock);
		return -1;
	}

	ctx->usock = sock;

	return 0;
}

int init_listens(listen_t* listens, int listen_num)
{
	int i, num = listen_num;
	listen_t* listen;

	for (i = 0; i < num; i++) {
		listen = listens + i;
		if (tcp_listen(listen) != 0) {
			loge("init_listens() error\n");
			return -1;
		}
		if (udp_listen(listen) != 0) {
			close(listen->sock);
			listen->sock = 0;
			loge("init_listens() error\n");
			return -1;
		}
	}

	return 0;
}

void print_listens(const listen_t* listens, int listen_num)
{
	int i;
	for (i = 0; i < listen_num; i++) {
		logn("listen on %s\n",
			get_sockaddrname(&listens[i].addr));
	}
}

conn_status tcp_connect(const sockaddr_t* addr, sock_t* psock)
{
	sock_t sock = *psock;

	if (sock == -1) {
		sock = socket(addr->addr.ss_family, SOCK_STREAM, IPPROTO_TCP);

		if (sock == -1) {
			loge("tcp_connect() error: create socket error. errno=%d, %s - %s\n",
				errno, strerror(errno), get_sockaddrname(addr));
			return cs_err_create_sock;
		}

		if (setnonblock(sock) != 0) {
			loge("tcp_connect() error: set sock non-block failed - %s\n",
				get_sockaddrname(addr));
			close(sock);
			return cs_err_set_nonblock;
		}

		if (setnodelay(sock) != 0) {
			loge("tcp_connect() error: set sock nodelay failed - %s\n",
				get_sockaddrname(addr));
			close(sock);
			return cs_err_set_nodelay;
		}

	}

	if (connect(sock, (const struct sockaddr*)(&addr->addr), addr->addrlen) != 0) {
		int err = errno;
		if (!is_eagain(err)) {
			loge("tcp_connect() error: errno=%d, %s - %s\n",
				errno, strerror(errno), get_sockaddrname(addr));
			if (sock != *psock) {
				close(sock);
			}
			return cs_err_connect;
		}
		else {
			*psock = sock;
			return cs_connecting;
		}
	}
	else {
		*psock = sock;
		return cs_connected;
	}
}

int tcp_send(sock_t sock, stream_t* s)
{
	int rsize = stream_rsize(s);
	int nsend;

	if (rsize == 0)
		return 0;

	nsend = send(sock, s->array + s->pos, rsize, 0);
	if (nsend == -1) {
		int err = errno;
		if (!is_eagain(err)) {
			loge("tcp_send() error: errno=%d, %s \n",
				err, strerror(err));
			return -1;
		}
		return 0;
	}
	else {
		s->pos += nsend;
		logv("tcp_send(): send %d bytes\n", nsend);
		if (stream_quake(s)) {
			loge("tcp_send() error: stream_quake()\n");
			return -1;
		}
		return nsend;
	}
}

int tcp_recv(sock_t sock, char* buf, int buflen)
{
	int nread;

	nread = recv(sock, buf, buflen, 0);
	if (nread == -1) {
		int err = errno;
		if (!is_eagain(err)) {
			loge("tcp_recv() error: errno=%d, %s\n",
				err, strerror(err));
			return -1;
		}
		return 0;
	}
	else if (nread == 0) {
		loge("tcp_recv(): connection closed by peer\n");
		return -1;
	}
	else {
		logv("tcp_recv(): recv %d bytes\n", nread);

		return nread;
	}
}

int udp_send(sock_t sock, stream_t* s,
	const struct sockaddr* to, int tolen)
{
	int nsend;
	int rsize = stream_rsize(s);

	nsend = sendto(sock, s->array + s->pos, rsize, 0, to, tolen);
	if (nsend == -1) {
		loge("udp_send() error: to=%s, errno=%d, %s\n",
			get_addrname(to), errno, strerror(errno));
		return -1;
	}
	return nsend;
}

int udp_recv(sock_t sock, char* buf, int buflen,
	struct sockaddr* from, int* fromlen)
{
	int nread;

	nread = recvfrom(sock, buf, buflen, 0, from, fromlen);
	if (nread > 0) {
		return nread;
	}
	else {
		loge("udp_recv() error: errno=%d, %s\n", errno, strerror(errno));
		return -1;
	}
}

conn_t* conn_new(sock_t sock)
{
	conn_t* conn = (conn_t*)malloc(sizeof(conn_t));
	if (!conn) {
		loge("conn_new() error: alloc\n");
		return NULL;
	}

	if (conn_init(conn, sock)) {
		free(conn);
		loge("conn_new() error: conn_init() error\n");
		return NULL;
	}

	return conn;
}

int conn_init(conn_t* conn, sock_t sock)
{
	memset(conn, 0, sizeof(conn_t));

	if (stream_init(&conn->rs)) {
		loge("conn_init() error: stream_init() error\n");
		return -1;
	}

	if (stream_init(&conn->ws)) {
		stream_free(&conn->rs);
		loge("conn_init() error: stream_init() error\n");
		return -1;
	}

	conn->sock = sock;

	return 0;
}

void conn_free(conn_t* conn)
{
	if (conn == NULL)
		return;
	if (conn->sock) {
		close(conn->sock);
		conn->sock = 0;
	}
	stream_free(&conn->rs);
	stream_free(&conn->ws);
}

void conn_destroy(conn_t* conn)
{
	conn_free(conn);
	free(conn);
}

peer_t* peer_new(sock_t sock, int listen)
{
	peer_t* peer = (peer_t*)malloc(sizeof(peer_t));
	if (!peer) {
		loge("peer_new() error: alloc\n");
		return NULL;
	}

	if (peer_init(peer, sock, listen)) {
		free(peer);
		loge("peer_new() error: peer_init() error\n");
		return NULL;
	}

	return peer;
}

int peer_init(peer_t* peer, sock_t sock, int listen)
{
	memset(peer, 0, sizeof(peer_t));

	if (conn_init(&peer->conn, sock)) {
		loge("peer_init() error: conn_init() error\n");
		return -1;
	}

	dllist_init(&peer->reqs);

	peer->listen = listen;

	return 0;
}

void peer_free(peer_t* peer)
{
	if (peer == NULL)
		return;
	conn_free(&peer->conn);
}

void peer_destroy(peer_t* peer)
{
	peer_free(peer);
	free(peer);
}

unsigned long OS_GetTickCount()
{
#ifdef WINDOWS
	return clock();
#else
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
#endif
}
