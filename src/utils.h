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
#define strdup(s) _strdup(s)
#else
#define strnicmp strncasecmp
#endif

#define MAX(a, b) (((a) < (b)) ? (b) : (a))
#define _XSTR(x) #x  
#define XSTR(x) _XSTR(x)

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

char* ltrim(char* s);
char* rtrim(char* s);
char* trim_quote(char* s);

#ifdef __cplusplus
}
#endif

#endif
