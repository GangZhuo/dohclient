#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef WINDOWS
#include <syslog.h>
#endif

log_vprintf_fun log_vprintf = log_vprintf_default;
log_vprintf_fun log_vprintf_with_timestamp = log_vprintf_with_timestamp_default;

static int s_log_level = LOG_DEFAULT_LEVEL;
static int s_log_flags = LOG_FLG_TIME;

static int s_is_use_syslog = 0;
static int s_is_use_logfile = 0;
static const char* s_current_log_file = NULL;

static const char *prioritynames[] = {
	"emerg", "alert", "crit", "err", "warning", NULL /*notice*/,
	NULL /*info*/, "debug", "verbos",
};

int *log_pflags()
{
	return &s_log_flags;
}

int *log_plevel()
{
	return &s_log_level;
}

void log_vwrite(int mask, const char *fmt, va_list args)
{
	if (log_level_comp(mask) <= loglevel) {
		if (mask & LOG_MASK_RAW) {
			log_vprintf(mask, fmt, args);
		}
		else if (s_log_flags & LOG_FLG_TIME) {
			log_vprintf_with_timestamp(mask, fmt, args);
		}
		else {
			log_vprintf(mask, fmt, args);
		}
	}
}

void log_write(int mask, const char *fmt, ...)
{
	if (log_level_comp(mask) <= loglevel) {
		va_list args;
		va_start(args, fmt);
		log_vwrite(mask, fmt, args);
		va_end(args);
	}
}

const char* log_priorityname(int priority)
{
	if (priority >= 0 && priority < (sizeof(prioritynames) / sizeof(const char*)))
		return prioritynames[priority];
	
	return NULL;
}

static FILE *log_fp(int mask)
{
	FILE *pf;
	if (log_level_comp(mask) >= LOG_ERR)
		pf = stdout;
	else
		pf = stderr;
	return pf;
}

void log_vprintf_default(int mask, const char *fmt, va_list args)
{
	FILE *pf = log_fp(mask);
	vfprintf(pf, fmt, args);
	fflush(pf);
}

void log_vprintf_with_timestamp_default(int mask, const char *fmt, va_list args)
{
	char buf[8 * 1024];
	int level = log_level_comp(mask);
	char date[32];
	const char *extra_msg;
	time_t now;
	FILE *pf = log_fp(mask);

	memset(buf, 0, sizeof(buf));
	vsnprintf(buf, sizeof(buf) - 1, fmt, args);

	now = time(NULL);

	strftime(date, sizeof(date), LOG_TIMEFORMAT, localtime(&now));
	extra_msg = log_priorityname(level);
	if (extra_msg && strlen(extra_msg)) {
		fprintf(pf, "%s [%s] %s", date, extra_msg, buf);
	}
	else {
		fprintf(pf, "%s %s", date, buf);
	}
	fflush(pf);
}

void log_vprintf_writefile(int mask, const char* fmt, va_list args)
{
	char buf[8 * 1024], buf2[16 * 1024];
	int len;
	int level = log_level_comp(mask);
	char date[32];
	const char* extra_msg;
	time_t now;

	memset(buf, 0, sizeof(buf));
	len = vsnprintf(buf, sizeof(buf) - 1, fmt, args);

	now = time(NULL);

	strftime(date, sizeof(date), LOG_TIMEFORMAT, localtime(&now));
	extra_msg = log_priorityname(level);

	memset(buf2, 0, sizeof(buf2));

	if (extra_msg && strlen(extra_msg)) {
		len = snprintf(buf2, sizeof(buf2) - 1, "%s [%s] %s", date, extra_msg, buf);
	}
	else {
		len = snprintf(buf2, sizeof(buf2) - 1, "%s %s", date, buf);
	}

	if (len > 0) {
		FILE* pf;
		pf = fopen(s_current_log_file, "a+");
		if (pf) {
			fwrite(buf2, 1, len, pf);
			fclose(pf);
		}
		else {
			printf("cannot open %s\n", s_current_log_file);
		}
	}
}

void log_vprintf_syslog(int mask, const char* fmt, va_list args)
{
#ifdef WINDOWS
	logw("log_vprintf_syslog(): not implemented in Windows port");
#else
	char buf[8 * 1024];
	int priority = log_level_comp(mask);

	memset(buf, 0, sizeof(buf));
	vsnprintf(buf, sizeof(buf) - 1, fmt, args);
	syslog(priority, "%s", buf);
#endif
}

void open_logfile(const char* log_file)
{
	if (log_file && strlen(log_file)) {
		s_current_log_file = log_file;
		log_vprintf = log_vprintf_writefile;
		log_vprintf_with_timestamp = log_vprintf_writefile;
		s_is_use_logfile = 1;
	}
}

void close_logfile()
{
	if (s_is_use_logfile) {
		log_vprintf = log_vprintf_default;
		log_vprintf_with_timestamp = log_vprintf_with_timestamp_default;
		s_is_use_logfile = 0;
	}
}

void open_syslog(const char *ident)
{
#ifdef WINDOWS
	logw("use_syslog(): not implemented in Windows port");
#else
	if (!s_is_use_syslog) {
		openlog(ident, LOG_CONS | LOG_PID, LOG_DAEMON);
		s_is_use_syslog = 1;
		log_vprintf = log_vprintf_syslog;
		log_vprintf_with_timestamp = log_vprintf_syslog;
	}
#endif
}

void close_syslog()
{
#ifdef WINDOWS
	logw("close_syslog(): not implemented in Windows port");
#else
	if (s_is_use_syslog) {
		s_is_use_syslog = 0;
		log_vprintf = log_vprintf_default;
		log_vprintf_with_timestamp = log_vprintf_with_timestamp_default;
		closelog();
	}
#endif
}

int is_use_syslog()
{
	return s_is_use_syslog;
}

int is_use_logfile()
{
	return s_is_use_logfile;
}

const char *get_logfile()
{
	return s_current_log_file;
}
