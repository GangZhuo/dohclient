#ifndef DOHCLIENT_WIN_H_
#define DOHCLIENT_WIN_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <time.h>
#include <sys/stat.h>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <MSWSock.h>

#ifdef __cplusplus
extern "C" {
#endif

#undef errno
#define errno WSAGetLastError()
#define close(fd) closesocket(fd)
#define strerror(errcode) win_strerror(errcode)

extern void win_init();

extern void win_uninit();

const char* win_strerror(int err_code);

/* See https://support.microsoft.com/en-us/kb/263823 */
int disable_udp_connreset(SOCKET sockfd);

#ifdef __cplusplus
}
#endif

#endif