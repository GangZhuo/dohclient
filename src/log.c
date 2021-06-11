#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef WINDOWS
#include <Windows.h>
#else
#include <syslog.h>
#endif
#include "mleak.h"

#ifdef WINDOWS
typedef WORD ttycolor_t;
#define COLOR_FWHITE          FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY
#define COLOR_FRED            FOREGROUND_RED | FOREGROUND_INTENSITY
#define COLOR_FYELLOW         FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY
#define COLOR_FMAGEN          FOREGROUND_BLUE | FOREGROUND_RED
#define COLOR_FGREEN          FOREGROUND_GREEN
#define COLOR_FBLUE           FOREGROUND_BLUE
#define COLOR_FCYAN           FOREGROUND_GREEN | FOREGROUND_BLUE
#else
typedef const char *ttycolor_t;
#define COLOR_ESC                "\033["
#define COLOR_END                "m"
/* Foreground colors values */
#define COLOR_F_BLACK            "30"
#define COLOR_F_RED              "31"
#define COLOR_F_GREEN            "32"
#define COLOR_F_YELLOW           "33"
#define COLOR_F_BLUE             "34"
#define COLOR_F_MAGEN            "35"
#define COLOR_F_CYAN             "36"
#define COLOR_F_WHITE            "37"

#define COLOR_FWHITE   COLOR_ESC COLOR_F_WHITE  COLOR_END
#define COLOR_FRED     COLOR_ESC COLOR_F_RED    COLOR_END
#define COLOR_FYELLOW  COLOR_ESC COLOR_F_YELLOW COLOR_END
#define COLOR_FMAGEN   COLOR_ESC COLOR_F_MAGEN  COLOR_END
#define COLOR_FGREEN   COLOR_ESC COLOR_F_GREEN  COLOR_END
#define COLOR_FBLUE    COLOR_ESC COLOR_F_BLUE   COLOR_END
#define COLOR_FCYAN    COLOR_ESC COLOR_F_CYAN   COLOR_END
#endif

log_vprintf_fun log_vprintf = log_vprintf_default;
log_vprintf_fun log_vprintf_with_timestamp = log_vprintf_with_timestamp_default;

static int s_log_level = LOG_DEFAULT_LEVEL;
static int s_log_flags = LOG_FLG_TIME;

static int s_is_use_syslog = 0;
static int s_is_use_logfile = 0;
static const char* s_current_log_file = NULL;

static const char *prioritynames[] = {
	"EMERG",
	"ALERT",
	"CRIT",
	"ERROR",
	"WARNING",
	"NOTICE",
	"INFO",
	"DEBUG",
	"VERBOSE",
};

static ttycolor_t colors[] = {
	COLOR_FRED,     /* EMERG */
	COLOR_FRED,     /* ALERT */
	COLOR_FRED,     /* CRIT */
	COLOR_FRED,     /* ERROR */
	COLOR_FMAGEN,   /* WARNING */
	COLOR_FCYAN,    /* NOTICE */
	COLOR_FGREEN,   /* INFO */
	COLOR_FYELLOW,  /* DEBUG */
	COLOR_FWHITE,   /* VERBOSE */
};

int *log_pflags()
{
	return &s_log_flags;
}

int *log_plevel()
{
	return &s_log_level;
}

#ifdef WINDOWS
static HANDLE hStdout = INVALID_HANDLE_VALUE;
static HANDLE hStderr = INVALID_HANDLE_VALUE;
static CONSOLE_SCREEN_BUFFER_INFO csbiInfo = { 0 };
static WORD wOldColorAttrs = COLOR_FWHITE;
int log_init()
{
	hStderr = GetStdHandle(STD_ERROR_HANDLE);
	hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hStdout != INVALID_HANDLE_VALUE) {
		if (GetConsoleScreenBufferInfo(hStdout, &csbiInfo)) {
			wOldColorAttrs = csbiInfo.wAttributes;
			return 0;
		}
	}

	if (hStderr != INVALID_HANDLE_VALUE) {
		if (GetConsoleScreenBufferInfo(hStderr, &csbiInfo)) {
			wOldColorAttrs = csbiInfo.wAttributes;
			return 0;
		}
	}

	return -1;
}
#endif

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

	retval = log_mprintf("%s[%s] %s:%d %s", date, extra_msg, fname, line, text);

	free(text);
	return retval;
}

static inline void log_write_stdout(int mask, int timestamp,
	const char* file, const char* func, int line,
	const char* fmt, va_list args)
{
	int level = log_level_comp(mask);
	FILE* pf = level <= LOG_ERR ? stderr : stdout;
	ttycolor_t color =
		(level >= 0 && level < (sizeof(colors) / sizeof(colors[0]))) ?
		colors[level] : COLOR_FWHITE;
	char* text = log_text(mask, timestamp, file, func, line, fmt, args);
#ifdef WINDOWS
	HANDLE h = level <= LOG_ERR ? hStderr : hStdout;
	if (h != INVALID_HANDLE_VALUE)
		SetConsoleTextAttribute(h, color);
	fprintf(pf, "%s", text);
	if (h != INVALID_HANDLE_VALUE)
		SetConsoleTextAttribute(h, wOldColorAttrs);
#else
	fprintf(pf, "%s%s", color, text);
#endif
	free(text);
}

void log_vprintf_default(int mask,
		const char *file, const char *func, int line,
		const char *fmt, va_list args)
{
	log_write_stdout(mask, 0, file, func, line, fmt, args);
}

void log_vprintf_with_timestamp_default(int mask,
		const char *file, const char *func, int line,
		const char *fmt, va_list args)
{
	log_write_stdout(mask, 1, file, func, line, fmt, args);
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
