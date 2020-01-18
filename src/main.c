#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>

#include "utils.h"
#include "log.h"
#include "dllist.h"
#include "stream.h"
#include "chnroute.h"
#include "netutils.h"
#include "config.h"
#include "ns_msg.h"
#include "dns_request.h"
#include "../rbtree/rbtree.h"

#define PROGRAM_NAME    "dohclient"
#define PROGRAM_VERSION "0.0.1"

static config_t conf = {
	.timeout = -1,
	.dns_timeout = -1,
};
static int running = 0;
static listen_t listens[MAX_LISTEN] = { 0 };
static int listen_num = 0;
static dllist_t peers = DLLIST_INIT(peers);
static proxy_t proxy_list[MAX_PROXY] = { 0 };
static int proxy_num = 0;
static chnroute_ctx chnr = NULL;

#ifdef WINDOWS

static SERVICE_STATUS ServiceStatus = { 0 };
static SERVICE_STATUS_HANDLE hStatus = NULL;

static void ServiceMain(int argc, char** argv);
static void ControlHandler(DWORD request);

#endif

#define get_proxyinfo(index) \
	(proxy_list + (index))

#define get_proxyname(index) \
	get_sockaddrname(&get_proxyinfo(index)->addr)

#define get_conn_proxyname(peer) \
	get_sockaddrname(&get_proxyinfo((peer)->proxy->proxy_index)->addr)

static void usage()
{
	printf("%s\n", "\n"
		PROGRAM_NAME " " PROGRAM_VERSION "\n\
\n\
Usage:\n\
\n\
dohclient [-b BIND_ADDR] [-p BIND_PORT] [--config=CONFIG_PATH]\n\
         [--log=LOG_FILE_PATH] [--log-level=LOG_LEVEL]\n\
         [--chnroute=CHNROUTE_FILE] [--proxy=SOCKS5_PROXY]\n\
         [--daemon] [--pid=PID_FILE_PATH] [-v] [-V] [-h]\n\
\n\
DoH client.\n\
\n\
Options:\n\
\n\
  -b BIND_ADDR             Address that listens, default: " DEFAULT_LISTEN_ADDR ".\n\
                           Use comma to separate multi addresses, \n\
                           e.g. -b 127.0.0.1:5354,[::1]:5354.\n\
  -p BIND_PORT             Port that listen on, default: " DEFAULT_LISTEN_PORT ".\n\
                           The port specified in \"-b\" is priority .\n\
  -t TIMEOUT               Timeout (seconds), default: " XSTR(DEFAULT_TIMEOUT) ".");
	printf("%s\n", "\
  --dns-server=DNS_SERVER  DNS servers, e.g. " DEFAULT_DNS_SERVER ".");
	printf("%s\n", "\
  --dns-timeout=TIMEOUT    DNS cache timeout (seconds), default: " XSTR(DEFAULT_DNS_TIMEOUT) ".\n\
                           0 mean no cache.\n\
  --daemon                 Daemonize.\n\
  --pid=PID_FILE_PATH      pid file, default: " DEFAULT_PID_FILE ", \n\
                           only available on daemonize.\n\
  --log=LOG_FILE_PATH      Write log to a file.\n\
  --log-level=LOG_LEVEL    Log level, range: [0, 7], default: " LOG_DEFAULT_LEVEL_NAME ".\n\
  --config=CONFIG_PATH     Config file, find sample at \n\
                           https://github.com/GangZhuo/dohclient.\n\
  --chnroute=CHNROUTE_FILE Path to china route file, \n\
                           e.g.: --chnroute=lan.txt,chnroute.txt,chnroute6.txt.\n\
  --proxy=SOCKS5_PROXY     Socks5 proxy, e.g. --proxy=127.0.0.1:1080\n\
                           or --proxy=[::1]:1080. More than one proxy is supported,\n\
                           in the case, if first proxy is unconnectable, it is \n\
                           automatic to switch to next proxy.\n\
                           Only socks5 with no authentication is supported.\n\
  -v                       Verbose logging.\n\
  -h                       Show this help message and exit.\n\
  -V                       Print version and then exit.\n\
\n\
Online help: <https://github.com/GangZhuo/dohclient>\n");
}

static inline void update_expire(conn_t* conn)
{
	close_after(conn, conf.timeout);
}

static inline void close_conn(conn_t* conn)
{
	conn->status = cs_closing;
}

static inline void close_conn_after_rsp(conn_t* conn)
{
	conn->status = cs_rsp_closing;
}

static inline int is_close_after_rsp(conn_t* conn)
{
	return conn->status == cs_rsp_closing;
}

static int server_recv_msg(const char *data, int datalen, void *from, int fromlen, int fromtcp)
{
	req_t* req;

	req = new_req(data, datalen, from, fromlen, fromtcp);
	if (!req) {
		return -1;
	}

	print_req(req);

	if (loglevel >= LOG_INFO) {
		print_req_questions(req);
	}

	//TODO: 

	destroy_req(req);

	return 0;
}

static int server_udp_recv(int listen_index)
{
	listen_t* ctx = listens + listen_index;
	sock_t sock = ctx->usock;
	int nread;
	char buffer[NS_PAYLOAD_SIZE + 1];
	struct sockaddr_storage from = { 0 };
	int fromlen = sizeof(struct sockaddr_storage);

	nread = udp_recv(sock, buffer, sizeof(buffer),
		(struct sockaddr*) & from, &fromlen);

	if (nread == -1)
		return -1;

	if (nread == 0)
		return 0;

	logd("server_udp_recv(): recv %d bytes from %s\n",
		nread, get_addrname((struct sockaddr*) & from));

	bprint(buffer, nread);

	if (nread > NS_PAYLOAD_SIZE) {
		loge("server_udp_recv(): too large dns-message\n");
		return -1;
	}

	if (server_recv_msg(buffer, nread, &from, fromlen, FALSE)) {
		return -1;
	}

	return 0;
}

static int peer_accept(int listen_index)
{
	listen_t* ctx = listens + listen_index;
	sock_t sock;
	sockaddr_t from = {
		.addr = {0},
		.addrlen = sizeof(struct sockaddr_storage),
	};
	peer_t* peer;

	sock = accept(ctx->sock, (struct sockaddr*) & from.addr, &from.addrlen);
	if (sock == -1) {
		loge("accept() error: errno=%d, %s \n",
			errno, strerror(errno));
		return -1;
	}
	logd("accept() from %s\n", get_sockaddrname(&from));
	peer = new_peer(sock, listen_index);
	if (!peer) {
		close(sock);
		return -1;
	}

	dllist_add(&peers, &peer->conn.entry);

	update_expire(&peer->conn);

	return 0;
}

static int peer_handle_recv(peer_t* peer)
{
	stream_t* s = &peer->conn.rs;
	int msglen, left;

	while ((left = stream_rsize(s)) >= 2) {
		msglen = stream_geti(s, s->pos, 2);
		if (msglen > NS_PAYLOAD_SIZE) {
			loge("peer_recv() error: too large dns-message (msglen=0x%.4x)\n", msglen);
			return -1;
		}
		else if (left >= (msglen + 2)) {
			if (server_recv_msg(s->array + s->pos + 2, msglen, peer, 0, TRUE)) {
				return -1;
			}
			else {
				s->pos += (msglen + 2);
			}
		}
		else {
			break;
		}
	}

	if (s->pos > 0) {
		if (stream_quake(s)) {
			loge("peer_recv() error: stream_quake() failed\n");
			return -1;
		}
	}

	return 0;
}

static int peer_recv(peer_t* peer)
{
	sock_t sock = peer->conn.sock;
	stream_t* s = &peer->conn.rs;
	char* buffer;
	int buflen, nread;

	if (stream_set_cap(s, NS_PAYLOAD_SIZE + 2)) {
		return -1;
	}

	buffer = s->array + s->size;
	buflen = s->cap - s->size;

	nread = tcp_recv(sock, buffer, buflen);

	if (nread == -1)
		return -1;

	if (nread == 0)
		return 0;

	s->size += nread;

	peer->conn.rx += nread;

	logd("peer_recv(): recv %d bytes from %s\n",
		nread, get_sockname(peer->conn.sock));

	bprint(buffer, nread);

	if (peer_handle_recv(peer)) {
		return -1;
	}

	update_expire(&peer->conn);

	return 0;
}

static int peer_write(peer_t* peer)
{
	sock_t sock = peer->conn.sock;
	stream_t* s = &peer->conn.ws;
	int nsend;

	nsend = tcp_send(sock, s);

	if (nsend == -1)
		return -1;

	if (nsend == 0)
		return 0;

	peer->conn.tx += nsend;

	logd("peer_write(): write to %s\n", get_sockname(sock));

	if (is_close_after_rsp(&peer->conn)) {
		/* wait 3 seconds */
		close_after(&peer->conn, 3);
	}
	else {
		update_expire(&peer->conn);
	}

	return 0;
}

static int do_loop()
{
	fd_set readset, writeset, errorset;
	sock_t max_fd;
	int i, r;
	time_t now;

	running = 1;
	while (running) {
		struct timeval timeout = {
			.tv_sec = 0,
			.tv_usec = 50 * 1000,
		};

		FD_ZERO(&readset);
		FD_ZERO(&writeset);
		FD_ZERO(&errorset);


		max_fd = 0;

		for (i = 0; i < listen_num; i++) {
			listen_t* listen = listens + i;

			if (!running) break;

			max_fd = MAX(max_fd, listen->sock);

			FD_SET(listen->sock, &readset);
			FD_SET(listen->sock, &errorset);

			max_fd = MAX(max_fd, listen->usock);

			FD_SET(listen->usock, &readset);
			FD_SET(listen->usock, &errorset);
		}

		{
			dlitem_t* cur, * nxt;
			peer_t* peer;
			int is_local_sending;
			int is_closing;

			dllist_foreach(&peers, cur, nxt, peer_t, peer, conn.entry) {

				if (!running) break;

				max_fd = MAX(max_fd, peer->conn.sock);
				is_local_sending = stream_rsize(&peer->conn.ws) > 0;
				is_closing = peer->conn.status == cs_closing ||
					peer->conn.status == cs_rsp_closing;
				if (is_local_sending)
					FD_SET(peer->conn.sock, &writeset);
				/* read when request header is not complete,
				   or remote connection established and not sending data */
				else if(!is_closing)
					FD_SET(peer->conn.sock, &readset);
				FD_SET(peer->conn.sock, &errorset);
			}
		}

		if (!running) break;

		if (select(max_fd + 1, &readset, &writeset, &errorset, &timeout) == -1) {
			loge("select() error: errno=%d, %s \n",
				errno, strerror(errno));
			return -1;
		}

		if (!running) break;

		now = time(NULL);

		for (i = 0; i < listen_num; i++) {
			listen_t* listen = listens + i;

			if (!running) break;

			if (FD_ISSET(listen->sock, &errorset)) {
				loge("do_loop(): listen.sock error\n");
				return -1;
			}

			if (FD_ISSET(listen->usock, &errorset)) {
				loge("do_loop(): listen.usock error\n");
				return -1;
			}

			if (FD_ISSET(listen->sock, &readset)) {
				r = peer_accept(i);
			}

			if (FD_ISSET(listen->usock, &readset)) {
				r = server_udp_recv(i);
			}
		}

		{
			dlitem_t* cur, * nxt;
			peer_t* peer;

			dllist_foreach(&peers, cur, nxt, peer_t, peer, conn.entry) {

				if (!running) break;

				if (FD_ISSET(peer->conn.sock, &errorset)) {
					int err = getsockerr(peer->conn.sock);
					loge("do_loop(): peer.conn.sock error: errno=%d, %s \n",
						err, strerror(err));
					r = -1;
				}
				else if (FD_ISSET(peer->conn.sock, &writeset)) {
					r = peer_write(peer);
				}
				else if (FD_ISSET(peer->conn.sock, &readset)) {
					r = peer_recv(peer);
				}
				else {
					r = 0;
				}

				if (!running) break;

				if (!r && is_expired(&peer->conn, now)) {
					logd("connection timeout - %s\n", get_sockname(peer->conn.sock));
					r = -1;
				}

				if (r) {
					dllist_remove(&peer->conn.entry);
					destroy_peer(peer);
					continue;
				}
			}
		}
	}

	return 0;
}

static int init_dohclient()
{
	int i;

	if (conf.log_file) {
		open_logfile(conf.log_file);
	}
	else if (conf.launch_log) {
		open_logfile(conf.launch_log);
	}

	if (!conf.is_config_file_readed && conf.config_file) {
		if (read_config_file(&conf, conf.config_file, FALSE)) {
			return -1;
		}
		conf.is_config_file_readed = 1;
		if (conf.log_file) {
			open_logfile(conf.log_file);
		}
	}

	if (check_config(&conf))
		return -1;

	loglevel = conf.log_level;
	if (conf.log_level >= LOG_DEBUG) {
		logflags = LOG_MASK_RAW;
	}

	listen_num = str2listens(
		conf.listen_addr,
		listens,
		MAX_LISTEN,
		sizeof(listen_t),
		conf.listen_port);

	if (listen_num < 0)
		return -1;

	if (listen_num == 0) {
		loge("init_dohclient() error: no listens\n");
		return -1;
	}

	if (init_listens(listens, listen_num) != 0)
		return -1;

	if (conf.proxy) {
		proxy_num = str2addrs(
			conf.proxy,
			&proxy_list[0].addr,
			MAX_PROXY,
			sizeof(proxy_t),
			"1080");
		if (proxy_num == -1) {
			loge("init_dohclient() error: parse \"%s\" failed\n",
				conf.proxy);
			return -1;
		}
		for (i = 0; i < proxy_num; i++) {
			proxy_list[i].proxy_index = i;
		}
	}

	if (conf.chnroute) {
		if ((chnr = chnroute_create()) == NULL) {
			loge("init_dohclient() error: chnroute_create()\n");
			return -1;
		}
		if (chnroute_parse(chnr, conf.chnroute)) {
			loge("init_dohclient() error: invalid chnroute \"%s\"\n", conf.chnroute);
			return -1;
		}
	}

	print_listens(listens, listen_num);
	logn("loglevel: %d\n", loglevel);
	print_config(&conf);

	return 0;
}

static void uninit_dohclient()
{
	int i;

	for (i = 0; i < listen_num; i++) {
		listen_t* listen = listens + i;
		if (listen->sock)
			close(listen->sock);
		if (listen->usock)
			close(listen->usock);
	}

	listen_num = 0;

	{
		dlitem_t* cur, * nxt;
		peer_t* peer;

		dllist_foreach(&peers, cur, nxt, peer_t, peer, conn.entry) {
			destroy_peer(peer);
		}

		dllist_init(&peers);
	}

	chnroute_free(chnr);
	chnr = NULL;

	proxy_num = 0;

	if (is_use_logfile()) {
		close_logfile();
	}

	if (is_use_syslog()) {
		close_syslog();
	}
}

#ifdef WINDOWS

BOOL WINAPI sig_handler(DWORD signo)
{
	switch (signo) {
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
	case CTRL_CLOSE_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:
		running = 0;
		break;
	default:
		break;
	}
	return TRUE;
}

static void ServiceMain(int argc, char** argv)
{
	BOOL bRet;
	bRet = TRUE;

	ServiceStatus.dwServiceType = SERVICE_WIN32;
	ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

	ServiceStatus.dwWin32ExitCode = 0;
	ServiceStatus.dwServiceSpecificExitCode = 0;
	ServiceStatus.dwCheckPoint = 0;
	ServiceStatus.dwWaitHint = 0;

	hStatus = RegisterServiceCtrlHandler(PROGRAM_NAME, (LPHANDLER_FUNCTION)ControlHandler);
	if (hStatus == (SERVICE_STATUS_HANDLE)0)
	{
		loge("ServiceMain(): cannot register service ctrl handler");
		return;
	}

	ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(hStatus, &ServiceStatus);

	if (init_dohclient(&conf) != 0)
		return;

	if (do_loop() != 0)
		return;

	uninit_dohclient();

	free_config(&conf);

	ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	ServiceStatus.dwWin32ExitCode = 0;
	SetServiceStatus(hStatus, &ServiceStatus);
}

static void ControlHandler(DWORD request)
{
	switch (request) {
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:
		running = 0;
		break;
	default:
		SetServiceStatus(hStatus, &ServiceStatus);
		break;
	}
}

#else

static void sig_handler(int signo) {
	if (signo == SIGINT)
		exit(1);  /* for gprof*/
	else
		running = 0;
}

#endif

static void run_as_daemonize()
{
#ifdef WINDOWS
	SERVICE_TABLE_ENTRY ServiceTable[2];

	ServiceTable[0].lpServiceName = PROGRAM_NAME;
	ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

	ServiceTable[1].lpServiceName = NULL;
	ServiceTable[1].lpServiceProc = NULL;

	if (!StartServiceCtrlDispatcher(ServiceTable)) {
		loge("run_as_daemonize(): cannot start service ctrl dispatcher");
	}
#else
	pid_t pid, sid;
	int dev_null;

	if (!pid_file) {
		pid_file = strdup(DEFAULT_PID_FILE);
	}

	pid = fork();
	if (pid < 0) {
		exit(1);
	}

	if (pid > 0) {
		if (pid_file) {
			FILE* file = fopen(pid_file, "w");
			if (file == NULL) {
				logc("Invalid pid file: %s\n", pid_file);
				exit(1);
			}
			fprintf(file, "%d", (int)pid);
			fclose(file);
		}
		
		exit(0);
	}

	if (init_dohclient(&conf) != 0)
		exit(1);

	umask(0);

	if (!log_file) {
		open_syslog();
	}

	sid = setsid();
	if (sid < 0) {
		exit(1);
	}

	if ((chdir("/")) < 0) {
		exit(1);
	}

	dev_null = open("/dev/null", O_WRONLY);
	if (dev_null) {
		dup2(dev_null, STDOUT_FILENO);
		dup2(dev_null, STDERR_FILENO);
	}
	else {
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	close(STDIN_FILENO);

	if (do_loop() != 0)
		exit(1);

	uninit_dohclient();

	free_config(&conf);

#endif
}

int main(int argc, char** argv)
{
#ifdef WINDOWS
	win_init();
#endif

	conf.log_level = loglevel;

	if (parse_args(&conf, argc, argv) != 0) {
		usage();
		exit(-1);
		return EXIT_FAILURE;
	}

	if (conf.is_print_help) {
		usage();
		exit(0);
		return EXIT_SUCCESS;
	}

	if (conf.is_print_version) {
		printf(PROGRAM_NAME " %s\n", PROGRAM_VERSION);
		exit(0);
		return EXIT_SUCCESS;
	}

	loglevel = conf.log_level;
	if (conf.log_level >= LOG_DEBUG) {
		logflags = LOG_MASK_RAW;
	}

	if (conf.daemonize) {
		run_as_daemonize();
		return EXIT_SUCCESS;
	}

#ifdef WINDOWS
	if (0 == SetConsoleCtrlHandler((PHANDLER_ROUTINE)sig_handler, TRUE)) {
		loge("can not set control handler\n");
		return EXIT_FAILURE;
	}
#else
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
#endif

	if (init_dohclient(&conf) != 0)
		return EXIT_FAILURE;

	if (do_loop() != 0)
		return EXIT_FAILURE;

	uninit_dohclient();

	free_config(&conf);

	return EXIT_SUCCESS;
}
