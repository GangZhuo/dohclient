#include "win.h"
#include "../src/log.h"

char* rtrim(char* s);

void win_init()
{
	WSADATA wsaData;
	int err;

	err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (err != 0) {
		loge("FATAL ERROR: unable to initialise Winsock 2.x.\n");
		exit(-1);
	}
}

void win_uninit()
{
	WSACleanup();
}

const char* win_strerror(int err_code)
{
	static char s_errstr[2048];

	LPSTR errString = NULL;  /* will be allocated and filled by FormatMessage */

	int size = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM, /* use windows internal message table */
		0,       /* 0 since source is internal message table */
		err_code, /*this is the error code returned by WSAGetLastError()
				  Could just as well have been an error code from generic
				  Windows errors from GetLastError() */
		0,        /*auto-determine language to use */
		(LPSTR)& errString, /* this is WHERE we want FormatMessage
							to plunk the error string.  Note the
							peculiar pass format:  Even though
							errString is already a pointer, we
							pass &errString (which is really type LPSTR* now)
							and then CAST IT to (LPSTR).  This is a really weird
							trip up.. but its how they do it on msdn:
							http://msdn.microsoft.com/en-us/library/ms679351(VS.85).aspx */
		0,                 /* min size for buffer */
		0);               /* 0, since getting message from system tables */

	memset(s_errstr, 0, sizeof(s_errstr));

	strncpy(s_errstr, errString, sizeof(s_errstr) - 1);

	LocalFree(errString); /* if you don't do this, you will get an
	 ever so slight memory leak, since we asked
	 FormatMessage to FORMAT_MESSAGE_ALLOCATE_BUFFER,
	 and it does so using LocalAlloc
	 Gotcha!  I guess. */

	return rtrim(s_errstr);
}


