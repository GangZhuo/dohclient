#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <assert.h>

#include "version.h"
#include "netutils.h"
#include "mleak.h"

#define MAX_CMD_ARGS 4

static char *host = "127.0.0.1:5354";
static int   timeout = 3;
static int   tcp_mode = 0;
static char *cmd = NULL;
static char *cmd_args[MAX_CMD_ARGS] = {0};
static int   cmd_arg_len = 0;

static sockaddr_t server_addr[1] = {0};
static char recvbuffer[2 * 1024 * 1024]; /* 2MiB */

static void usage()
{
	fprintf(stdout, "%s\n", "\n"
		DOHCLIENT_NAME "-cache " DOHCLIENT_VERSION "\n\
\n\
Usage:\n\
\n\
" DOHCLIENT_NAME "-cache [-s HOST:PORT] [-t TIMEOUT] [-T] [-v] [-h] \n\
                <command> [command_arguments]\n\
\n\
Cache Manager.\n\
\n\
Options:\n\
\n\
  -s HOST:PORT             Host Address, default: 127.0.0.1:5354.\n\
  -t TIMEOUT               Timeout (seconds), default: 3.\n\
  -T                       TCP mode.\n\
  -h                       Show this help message and exit.\n\
  -v                       Print version and then exit.\n\
\n\
Commands:\n\
\n\
  GET <A|AAAA> <DOMAIN>\n\
\n\
      Used to query the cache.\n\
      e.g. " DOHCLIENT_NAME "-cache get A www.baidu.com\n\
\n\
  LIST\n\
\n\
      Used to query all cached domains.\n\
      e.g. " DOHCLIENT_NAME "-cache list\n\
\n\
  PUT <DOMAIN> <A|AAAA> <IPv4|IPv6> [TTL]\n\
\n\
      Used to add/edit cache.\n\
      e.g. " DOHCLIENT_NAME "-cache put www.baidu.com A 180.101.49.11 289\n\
\n\
  DELETE <A|AAAA> <DOMAIN>\n\
\n\
      Used to remove a item from the cache.\n\
      e.g. " DOHCLIENT_NAME "-cache delete A www.baidu.com\n\
\n\
Online help: <https://github.com/GangZhuo/dohclient>\n");
}


static int send_by_udp(const char *pkg, int len)
{
	struct sockaddr *to;
	socklen_t tolen;
	sock_t sock;
	fd_set readset, writeset, errorset;
	struct timeval tv;
	int is_sent = FALSE;
	time_t begin_time;
	time_t now;

	to = (struct sockaddr*)(&server_addr->addr);
	tolen = server_addr->addrlen;

	sock = socket(to->sa_family, SOCK_DGRAM, IPPROTO_UDP);

	if (sock == -1) {
		fprintf(stderr, "send_by_udp() error: "
				"create socket error. errno=%d, %s\n",
				errno, strerror(errno));
		return -1;
	}

	if (setnonblock(sock) != 0) {
		fprintf(stderr, "send_by_udp() error: set sock non-block failed. errno=%d, %s\n",
			errno, strerror(errno));
		close(sock);
		return -1;
	}

	if (setreuseaddr(sock) != 0) {
		fprintf(stderr, "send_by_udp() error: set sock reuse address failed. errno=%d, %s\n",
			errno, strerror(errno));
		close(sock);
		return -1;
	}

#ifdef WINDOWS
	disable_udp_connreset(sock);
#endif

	begin_time = time(NULL);

	while (1) {

		FD_ZERO(&readset);
		FD_ZERO(&writeset);
		FD_ZERO(&errorset);

		if (is_sent) {
			FD_SET(sock, &readset);
		}
		else {
			FD_SET(sock, &writeset);
		}

		FD_SET(sock, &errorset);

		tv.tv_sec = 0;
		tv.tv_usec = 50 * 1000;

		if (select(sock + 1, &readset, &writeset, &errorset, &tv) == -1) {
			fprintf(stderr, "select() error: errno=%d, %s \n",
				errno, strerror(errno));
			close(sock);
			return -1;
		}

		if (FD_ISSET(sock, &errorset)) {
			fprintf(stderr, "send_by_udp() error: sock error: errno=%d, %s\n",
					errno, strerror(errno));
			close(sock);
			return -1;
		}

		if (FD_ISSET(sock, &readset)) {
			int nread;
			struct sockaddr_storage from[1] = {0};
			socklen_t fromlen[1] = { sizeof(*from) };

			nread = recvfrom(sock, recvbuffer, sizeof(recvbuffer) - 1, 0,
					(struct sockaddr*)from, fromlen);
			if (nread > 0) {
				recvbuffer[nread] = '\0';
				fprintf(stdout, "%s\n", recvbuffer);
				break;
			}
			else {
				fprintf(stderr, "send_by_udp() error: recvfrom() error: errno=%d, %s\n",
						errno, strerror(errno));
				close(sock);
				return -1;
			}
		}

		if (FD_ISSET(sock, &writeset)) {
			int nsend = sendto(sock, pkg, len, 0, to, tolen);
			if (nsend == -1) {
				fprintf(stderr, "send_by_udp() error: sendto() error: to=%s, errno=%d, %s\n",
					get_addrname(to), errno, strerror(errno));
				close(sock);
				return -1;
			}
			else {
				is_sent = TRUE;
			}
		}

		now = time(NULL);

		if ((int)(now - begin_time) > timeout) {
			fprintf(stderr, "send_by_udp() error: timeout\n");
			close(sock);
			return -1;
		}
	}

	close(sock);

	return 0;
}

static int send_by_tcp(const char *pkg, int len)
{
	struct sockaddr *to;
	socklen_t tolen;
	sock_t sock;
	fd_set readset, writeset, errorset;
	struct timeval tv;
	stream_t s[1] = {0};
	int is_sent = FALSE;
	time_t begin_time;
	time_t now;
	int totalsize = -1;
	int readsize = 0;

	to = (struct sockaddr*)(&server_addr->addr);
	tolen = server_addr->addrlen;

	s->array = (char*)pkg - 2;
	s->pos = 0;
	s->size = len + 2;
	s->cap = len + 2;

	stream_seti16(s, 0, len);

	sock = socket(to->sa_family, SOCK_STREAM, IPPROTO_TCP);

	if (sock == -1) {
		fprintf(stderr, "send_by_tcp() error: "
				"create socket error. errno=%d, %s\n",
				errno, strerror(errno));
		return -1;
	}

	if (setnonblock(sock) != 0) {
		fprintf(stderr, "send_by_tcp() error: set sock non-block failed. errno=%d, %s\n",
			errno, strerror(errno));
		close(sock);
		return -1;
	}

	if (setreuseaddr(sock) != 0) {
		fprintf(stderr, "send_by_tcp() error: set sock reuse address failed. errno=%d, %s\n",
			errno, strerror(errno));
		close(sock);
		return -1;
	}

	if (setnodelay(sock) != 0) {
		fprintf(stderr, "send_by_tcp() error: set sock nodelay failed. errno=%d, %s\n",
			errno, strerror(errno));
		close(sock);
		return -1;
	}

	if (connect(sock, to, tolen) != 0) {
		int err = errno;
		if (!is_eagain(err)) {
			loge("send_by_tcp() error: connect() error: errno=%d, %s - %s\n",
				errno, strerror(errno), get_addrname(to));
			close(sock);
			return -1;
		}
	}

	begin_time = time(NULL);

	while (1) {

		FD_ZERO(&readset);
		FD_ZERO(&writeset);
		FD_ZERO(&errorset);

		if (is_sent) {
			FD_SET(sock, &readset);
		}
		else {
			FD_SET(sock, &writeset);
		}

		FD_SET(sock, &errorset);

		tv.tv_sec = 0;
		tv.tv_usec = 50 * 1000;

		if (select(sock + 1, &readset, &writeset, &errorset, &tv) == -1) {
			fprintf(stderr, "send_by_tcp() error: select() error: errno=%d, %s \n",
				errno, strerror(errno));
			close(sock);
			return -1;
		}

		if (FD_ISSET(sock, &errorset)) {
			fprintf(stderr, "send_by_tcp() error: sock error: errno=%d, %s\n",
					errno, strerror(errno));
			close(sock);
			return -1;
		}

		if (FD_ISSET(sock, &readset)) {
			int nread;

			nread = tcp_recv(sock, s->array + s->size, s->cap - s->size - 1);
			if (nread > 0) {
				s->array[s->size + nread] = '\0';
				if (totalsize == -1) {
					s->size += nread;
					if (s->size >= 2) {
						totalsize = stream_readi16(s);
						readsize = s->size - 2;
						s->size = 0;
						fprintf(stdout, "%s", s->array + 2);
					}
				}
				else {
					fprintf(stdout, "%s", s->array);
					readsize += nread;
				}
				if (readsize >= totalsize) {
					fprintf(stdout, "\n");
					break;
				}
			}
			else if (nread < 0) {
				if (errno != 0) {
					fprintf(stderr, "send_by_tcp() error: tcp_recv() error: errno=%d, %s\n",
						errno, strerror(errno));
				}
				close(sock);
				return -1;
			}
		}

		if (FD_ISSET(sock, &writeset)) {
			int nsend = tcp_send(sock, s);
			if (nsend == -1) {
				fprintf(stderr, "send_by_tcp() error: tcp_send() error: to=%s, errno=%d, %s\n",
					get_addrname(to), errno, strerror(errno));
				close(sock);
				return -1;
			}
			else { /* Prepare recv stream */
				s->array = recvbuffer;
				s->pos = 0;
				s->size = 0;
				s->cap = sizeof(recvbuffer);
				is_sent = TRUE;
			}
		}

		now = time(NULL);

		if ((int)(now - begin_time) > timeout) {
			fprintf(stderr, "send_by_tcp() error: timeout\n");
			close(sock);
			return -1;
		}
	}

	close(sock);

	return 0;
}

static int is_digitstr(const char *s)
{
	char *p = s;
	while (*p) {
		if (!isdigit(*p))
			return FALSE;
		p++;
	}
	return TRUE;
}

int main(int argc, char **argv)
{
	int ch, i, n, r;
	char buf[1024];
	char *pkg = buf + 2; /* 2 bytes length for TCP */
	int pkgsize = sizeof(buf) - 2;

#ifdef WINDOWS
	win_init();
#endif

	while ((ch = getopt(argc, argv, "s:t:Tvh")) != -1) {
		switch (ch) {
		case 'h':
			usage();
			exit(0);
			break;
		case 'v':
			fprintf(stdout, DOHCLIENT_NAME "-cache %s\n", DOHCLIENT_VERSION);
			exit(0);
			break;
		case 's':
			host = optarg;
			break;
		case 't':
			if (!is_digitstr(optarg)) {
				fprintf(stderr, "Invalid timeout -- %s\n", optarg);
				exit(1);
			}
			timeout = atoi(optarg);
			break;
		case 'T':
			tcp_mode = TRUE;
			break;
		case '?':
		default:
			exit(1);
			break;
		}
	}

	if (optind < argc)
		cmd = argv[optind++];

	for (i = optind; i < argc && cmd_arg_len < MAX_CMD_ARGS; i++) {
		cmd_args[cmd_arg_len++] = argv[i];
	}

	if (!cmd) {
		fprintf(stderr, "No command\n");
		exit(1);
	}

	if (timeout <= 0) {
		fprintf(stderr, "Invalid timeout\n");
		exit(1);
	}

	if (str2addr(host, server_addr, "5354")) {
		fprintf(stderr, "Invalid host address\n");
		exit(1);
	}

	if (strcasecmp(cmd, "GET") == 0) {
		if (cmd_arg_len < 2) {
			fprintf(stderr, "Missing arguments\n");
			exit(1);
		}
		else if (cmd_arg_len > 2) {
			for (i = 2; i < cmd_arg_len; i++) {
				fprintf(stderr, "Invalid argument -- %s\n", cmd_args[i]);
			}
			exit(1);
		}
		if (strcmp(cmd_args[0], "A") && strcmp(cmd_args[0], "AAAA")) {
			fprintf(stderr,
					"Invalid qtype -- %s\n"
					"Available value should be \"A\" or \"AAAA\".\n",
					cmd_args[0]);
			exit(1);
		}
		n = snprintf(pkg, pkgsize,
				"GET '%s IN %s.'", cmd_args[0], cmd_args[1]);
		if (n <= 0 || n >= pkgsize) {
			fprintf(stderr, "Domain too long -- %s\n", cmd_args[1]);
			exit(1);
		}
	}
	else if (strcasecmp(cmd, "LIST") == 0) {
		if (cmd_arg_len != 0) {
			for (i = 0; i < cmd_arg_len; i++) {
				fprintf(stderr, "Invalid argument -- %s\n", cmd_args[i]);
			}
			exit(1);
		}
		n = snprintf(pkg, pkgsize, "LIST");
		assert(n > 0 && n < pkgsize);
	}
	else if (strcasecmp(cmd, "PUT") == 0) {
		if (cmd_arg_len < 3) {
			fprintf(stderr, "Missing arguments\n");
			exit(1);
		}
		else if (cmd_arg_len > 4) {
			for (i = 4; i < cmd_arg_len; i++) {
				fprintf(stderr, "Invalid argument -- %s\n", cmd_args[i]);
			}
			exit(1);
		}
		if (strcmp(cmd_args[1], "A") && strcmp(cmd_args[1], "AAAA")) {
			fprintf(stderr,
					"Invalid type -- %s\n"
					"Available value should be \"A\" or \"AAAA\".\n",
					cmd_args[1]);
			exit(1);
		}
		if (cmd_arg_len == 4) {
			if (!is_digitstr(cmd_args[3])) {
				fprintf(stderr, "Invalid TTL -- %s\n", cmd_args[3]);
				exit(1);
			}
		}
		if (cmd_arg_len == 4) {
			n = snprintf(pkg, pkgsize,
					"PUT %s. %s %s %s",
					cmd_args[0], cmd_args[1], cmd_args[2], cmd_args[3]);
		}
		else {
			n = snprintf(pkg, pkgsize,
					"PUT %s. %s %s",
					cmd_args[0], cmd_args[1], cmd_args[2]);
		}
		if (n <= 0 || n >= pkgsize) {
			fprintf(stderr, "Domain or IP too long -- %s %s\n", cmd_args[0], cmd_args[2]);
			exit(1);
		}
	}
	else if (strcasecmp(cmd, "DELETE") == 0) {
		if (cmd_arg_len < 2) {
			fprintf(stderr, "Missing arguments\n");
			exit(1);
		}
		else if (cmd_arg_len > 2) {
			for (i = 2; i < cmd_arg_len; i++) {
				fprintf(stderr, "Invalid argument -- %s\n", cmd_args[i]);
			}
			exit(1);
		}
		if (strcasecmp(cmd_args[0], "A") && strcasecmp(cmd_args[0], "AAAA")) {
			fprintf(stderr,
					"Invalid qtype -- %s\n"
					"Available value should be \"A\" or \"AAAA\".\n",
					cmd_args[0]);
			exit(1);
		}
		n = snprintf(pkg, pkgsize,
				"DELETE '%s IN %s.'", cmd_args[0], cmd_args[1]);
		if (n <= 0 || n >= pkgsize) {
			fprintf(stderr, "Domain too long -- %s\n", cmd_args[1]);
			exit(1);
		}
	}
	else {
		fprintf(stderr, "Invalid command -- %s\n", cmd);
		exit(1);
	}

	/*fprintf(stdout, "%s\n", pkg);*/

	if (tcp_mode)
		r = send_by_tcp(pkg, n);
	else
		r = send_by_udp(pkg, n);

	print_leak();

	return r;
}

