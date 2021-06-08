#include "utils.h"
#include "mleak.h"

int is_littleendian()
{
	short int number = 0x1;
	char *numPtr = (char*)&number;
	return (numPtr[0] == 1);
}

char* ltrim(char* s)
{
	char* p = s;
	while (p && (*p) && isspace((int)(*((unsigned char*)p))))
		p++;
	return p;
}

char* rtrim(char* s)
{
	size_t len;
	char* p;

	len = strlen(s);
	p = s + len - 1;

	while (p >= s && isspace((int)(*((unsigned char*)p)))) (*(p--)) = '\0';

	return s;
}

char* trim_quote(char* s)
{
	char* start, * end;
	size_t len;

	len = strlen(s);
	start = s;
	end = s + len - 1;

	while ((*start) && ((*start) == '\'' || (*start) == '"'))
		start++;

	while (end >= start && ((*end) == '\'' || (*end) == '"')) (*(end--)) = '\0';

	return start;
}

static inline int ch2dec(int ch)
{
	if (ch >= '0' && ch <= '9')
		ch -= '0';
	else if (ch >= 'a' && ch <= 'z')
		ch -= 'a';
	else if (ch >= 'A' && ch <= 'F')
		ch -= 'A';
	else {
		ch = -1;
	}
	return ch;
}

static inline int hex2dec(const char *s)
{
	int h = ch2dec(s[0]);
	int l = ch2dec(s[1]);
	/* a or b is not a hex char */
	if (h == -1 || l == -1) {
		return -1;
	}
	else {
		return (h << 8) | l;
	}
}

char *urldecode(char *s)
{
	char *src = s, *dest = s;
	while (*src) {
		if (*src == '%') {
			int a = (int)src[1] & 0xF;
			int b = a ? ((int)src[2] & 0xF) : 0;
			int ch = b ? hex2dec(src + 1) : -1;
			if (ch == -1) {
				*dest++ = *src++;
			}
			else {
				*dest++ = (char)ch;
				src += 3;
			}
		}
		else if (*src == '+') {
			*dest++ = ' ';
			src++;
		}
		else {
			*dest++ = *src++;
		}
	}
	*dest = '\0';
	return s;
}

int parse_querystring(const char *query,
	int (*callback)(char *name, char *value, void *state),
	void *state)
{
	char *cpy, *saveptr = NULL;
	char *p;
	char *v;

	if (!query || !*query) return -1;

	cpy = strdup(query);

	for (p = strtok_r(cpy, "&", &saveptr);
		p && *p;
		p = strtok_r(NULL, "&", &saveptr)) {

		v = strchr(p, '=');
		if (!v) continue;

		*v = '\0';
		v++;

		urldecode(v);

		if (callback(p, v, state)) {
			return -1;
		}
	}

	free(cpy);
	return 0;
}
