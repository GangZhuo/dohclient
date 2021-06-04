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

#include "version.h"
#include "netutils.h"

static void usage()
{
	printf("%s\n", "\n"
		DOHCLIENT_NAME "-cache " DOHCLIENT_VERSION "\n\
\n\
Usage:\n\
\n\
" DOHCLIENT_NAME "-cache [-h HOST_ADDR] [-p HOST_PORT] [-t TIMEOUT] [-V] [-h] \n\
                <command> [command_arguments]\n\
\n\
Cache Manager.\n\
\n\
Options:\n\
\n\
  -h HOST_ADDR             Host Address, default: 127.0.0.1.\n\
  -p HOST_PORT             Host Port, default: 5354.\n\
  -t TIMEOUT               Timeout (seconds), default: 3.\n\
  -h                       Show this help message and exit.\n\
  -V                       Print version and then exit.\n\
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


int main(int argc, char **argv)
{
	usage();
	return 0;
}

