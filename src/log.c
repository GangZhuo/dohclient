#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef WINDOWS
#include <syslog.h>
#endif
#include "mleak.h"

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

void log_vwrite(int mask,
		const char *file, const char *func, int line,
		const char *fmt, va_list args)
{
	if (log_level_comp(mask) <= loglevel) {
		if (mask & LOG_MASK_RAW) {
			log_vprintf(mask, file, func, line, fmt, args);
		}
		else if (s_log_flags & LOG_FLG_TIME) {
			log_vprintf_with_timestamp(mask, file, func, line, fmt, args);
		}
		else {
			log_vprintf(mask, file, func, line, fmt, args);
		}
	}
}

void log_write(int mask,
		const char *file, const char *func, int line,
		const char *fmt, ...)
{
	if (log_level_comp(mask) <= loglevel) {
		va_list args;
		va_start(args, fmt);
		log_vwrite(mask, file, func, line, fmt, args);
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

/* Print to memory, returned new created memory */
static char *log_vmprintf(const char *fmt, va_list args)
{
	int cnt, sz;
	char *buf;
	va_list ap_try;

	sz = 1024;
	buf = (char*)malloc(sz);
	if (!buf)
		return NULL;
try_print:
	va_copy(ap_try, args);
	cnt = vsnprintf(buf, sz, fmt, ap_try);
	va_end(ap_try);
	if (cnt >= sz) {
		char *newbuf;
		sz *= 2;
		newbuf = (char*)realloc(buf, sz);
		if (!newbuf) {
			free(buf);
			return NULL;
		}
		buf = newbuf;
		goto try_print;
	}
	if (cnt < 0) {
		free(buf);
		return NULL;
	}
	return buf;
}

/* Print to memory, returned new created memory */
static char *log_mprintf(const char *fmt, ...)
{
	char *retval;
	va_list args;
	va_start(args, fmt);
	retval = log_vmprintf(fmt, args);
	va_end(args);
	return retval;
}

static const char *get_filename(const char *file)
{
	size_t len;
	const char *p;
	if (!file) return NULL;
	len = strlen(file);
	for (p = file + len; p > file && *p != '/' && *p != '\\'; --p);
	if (*p == '/' || *p == '\\') ++p;
	return p;
}

static char *log_text(int mask, int timestamp,
		const char *file, const char *func, int line,
		const char *fmt, va_list args)
{
	int level = log_level_comp(mask);
	char date[32];
	const char *extra_msg;
	const char *fname;
	char *text, *retval;
	time_t now;

	if (timestamp) {
		int x;
		now = time(NULL);
		strftime(date, sizeof(date), LOG_TIMEFORMAT, localtime(&now));
		x = strlen(date);
		date[x++] = ' ';
		date[x++] = '\0';
	}
	extra_msg = log_priorityname(level);
	fname = get_filename(file);
	text = log_vmprintf(fmt, args);

	if (extra_msg && (*extra_msg)) {
		retval = log_mprintf("%s%s:%d [%s] %s",
				date, fname, line, extra_msg, text);
	}
	else {
		retval = log_mprintf("%s%s:%d %s",
				date, fname, line, text);
	}

	free(text);
	return retval;
}

void log_vprintf_default(int mask,
		const char *file, const char *func, int line,
		const char *fmt, va_list args)
{
	FILE *pf = log_fp(mask);
	char *text = log_text(mask, 0, file, func, line, fmt, args);
	fprintf(pf, "%s", text);
	free(text);
}

void log_vprintf_with_timestamp_default(int mask,
		const char *file, const char *func, int line,
		const char *fmt, va_list args)
{
	char *text = log_text(mask, 1, file, func, line, fmt, args);
	FILE *pf = log_fp(mask);
	fprintf(pf, "%s", text);
	free(text);
}

void log_vprintf_writefile(int mask,
		const char *file, const char *func, int line,
		const char* fmt, va_list args)
{
	char *text = log_text(mask, 1, file, func, line, fmt, args);
	size_t len;
	if (text && (len = strlen(text)) > 0) {
		FILE* pf;
		pf = fopen(s_current_log_file, "a+");
		if (pf) {
			fwrite(text, 1, len, pf);
			fclose(pf);
		}
		else {
			printf("cannot open %s\n", s_current_log_file);
		}
	}
	free(text);
}

void log_vprintf_syslog(int mask,
		const char *file, const char *func, int line,
		const char* fmt, va_list args)
{
#ifdef WINDOWS
	logw("log_vprintf_syslog(): not implemented in Windows port");
#else
	char *text = log_text(mask, 0, file, func, line, fmt, args);
	int priority = log_level_comp(mask);
	syslog(priority, "%s", text);
	free(text);
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
