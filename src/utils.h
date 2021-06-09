#ifndef DOHCLIENT_UTILS_H_
#define DOHCLIENT_UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WINDOWS
#ifndef strdup
#define strdup(s) _strdup(s)
#define strtok_r(s,d,c) strtok_s((s),(d),(c))
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#endif
#else
#ifndef strnicmp
#define strnicmp strncasecmp
#endif
#endif

#ifndef MAX
#define MAX(a, b) (((a) < (b)) ? (b) : (a))
#endif

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#define _XSTR(x) #x  
#define XSTR(x) _XSTR(x)

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

int is_littleendian();
char* ltrim(char* s);
char* rtrim(char* s);
char* trim_quote(char* s);
char *urldecode(char *s);
int parse_querystring(const char *query,
	int (*callback)(char *name, char *value, void *state),
	void *state);

#ifdef __cplusplus
}
#endif

#endif
