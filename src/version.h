#ifndef DOHCLIENT_VERSION_H_
#define DOHCLIENT_VERSION_H_

#define DOHCLIENT_NAME    "dohclient"
#define DOHCLIENT_VERSION "0.0.4"

#include "build_version.h"

static inline const char *git_version()
{
	const char *v = GIT_VERSION;
	if (v && *v) {
		v = "-" GIT_VERSION;
	}
	else {
		v = "";
	}
	return v;
}

#endif
