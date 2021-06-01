#include "utils.h"
#include "mleak.h"

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

int parse_querystring(const char *query,
	int (*callback)(char *name, char *value, void *state),
	void *state)
{
	char *cpy, *saveptr = NULL;
	char *p;
	char *v;

	if (!query) return -1;

	cpy = strdup(query);

	for (p = strtok_r(cpy, "&", &saveptr);
		p && *p;
		p = strtok_r(NULL, "&", &saveptr)) {

		v = strchr(p, '=');
		if (!v) continue;

		*v = '\0';
		v++;

		if (callback(p, v, state)) {
			return -1;
		}
	}

	free(cpy);
	return 0;
}
