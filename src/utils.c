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
	else if (ch >= 'a' && ch <= 'f')
		ch -= 'a' - 10;
	else if (ch >= 'A' && ch <= 'F')
		ch -= 'A' - 10;
	else {
		ch = -1;
	}
	return ch;
}

static inline int dec2ch(int d)
{
	if (d < 0xA) {
		return d + '0';
	}
	else if (d <= 0xF) {
		return 'A' + d - 0xA;
	}
	else {
		return -1;
	}
}

static inline int hex2dec(const unsigned char *s)
{
	int h = ch2dec(s[0]);
	int l = ch2dec(s[1]);
	/* a or b is not a hex char */
	if (h == -1 || l == -1) {
		return -1;
	}
	else {
		return (h << 4) | l;
	}
}

/* Percent-encoding
 * See https://developer.mozilla.org/en-US/docs/Glossary/percent-encoding */
char *urldecode(char *s)
{
	unsigned char *src  = (unsigned char *)s,
				  *dest = (unsigned char *)s;
	while (*src) {
		if (*src == '%') {
			int a = (int)src[1] & 0xFF;
			int b = a ? ((int)src[2] & 0xFF) : 0;
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

int urlencode(char *buf, int buflen, const char *s)
{
	unsigned char *src  = (unsigned char *)s,
				  *dest = (unsigned char *)buf,
				  *end  = dest + buflen;
	int n = 0;
	while ((*src) && dest < end) {
		int ch = *src++;
		if (ch <= ' ' || ch > '~' ||
				ch == ':' || ch ==  '/' || ch == '?' || ch == '#' ||
				ch == '[' || ch ==  ']' || ch == '@' || ch == '!' ||
				ch == '$' || ch ==  '&' || ch == '\''|| ch == '(' ||
				ch == ')' || ch ==  '*' || ch == '+' || ch == ',' ||
				ch == ';' || ch ==  '=' || ch ==  '%') {
			if (ch == ' ') {
				*dest++ = '+';
			}
			else {
				int h = dec2ch((ch >> 4) & 0xf);
				int l = dec2ch(ch & 0xf);
				*dest++ = '%';
				if (dest < end) {
					*dest++ = h;
					if (dest < end) {
						*dest++ = l;
					}
				}
			}
		}
		else {
			*dest++ = ch;
		}
	}
	if (dest < end) {
		*dest = '\0';
	}
	return (int)(dest - (unsigned char*)buf);
}

int parse_querystring(const char *query,
	int (*callback)(char *name, char *value, void *state),
	void *state)
{
	char *cpy, *saveptr = NULL;
	char *p;
	char *v;
	int r;

	if (!query || !*query) return 0;

	cpy = strdup(query);

	for (p = strtok_r(cpy, "&", &saveptr);
		p && *p;
		p = strtok_r(NULL, "&", &saveptr)) {

		v = strchr(p, '=');
		if (!v) continue;

		*v = '\0';
		v++;

		urldecode(v);

		if ((r = callback(p, v, state)) != 0) {
			return r;
		}
	}

	free(cpy);
	return 0;
}
