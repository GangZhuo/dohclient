#ifndef DOHCLIENT_LOG_H_
#define DOHCLIENT_LOG_H_

#include <stdarg.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ___I2STR1(R)  #R
#define I2STR(R)  ___I2STR1(R)

/* priorities (same syslog.h) */
#define	LOG_EMERG		0	/* system is unusable */
#define	LOG_ALERT		1	/* action must be taken immediately */
#define	LOG_CRIT		2	/* critical conditions */
#define	LOG_ERR			3	/* error conditions */
#define	LOG_WARNING		4	/* warning conditions */
#define	LOG_NOTICE		5	/* normal but significant condition */
#define	LOG_INFO		6	/* informational */
#define	LOG_DEBUG		7	/* debug-level messages */
#define	LOG_VERBOS		8	/* verbos messages */

#define LOG_FLG_TIME	(1 << 0) /* log with timestamp */

#define LOG_MASK_RAW	(1 << 8) /* log raw message */

#define LOG_TIMEFORMAT "%Y-%m-%d %H:%M:%S"

#define LOG_DEFAULT_LEVEL		LOG_NOTICE

#define LOG_DEFAULT_LEVEL_NAME	I2STR(LOG_NOTICE)

#ifdef _MSC_VER
#define __DOHCLIENT_FUNC__ __FUNCTION__
#else
#define __DOHCLIENT_FUNC__ ((const char *)__func__)
#endif

#define __DOHCLIENT_FILE__ __FILE__
#define __DOHCLIENT_LINE__ __LINE__

typedef void (*log_vprintf_fun)(int mask,
		const char *file, const char *func, int line,
		const char* fmt, va_list args);

extern log_vprintf_fun log_vprintf;
extern log_vprintf_fun log_vprintf_with_timestamp;

int *log_pflags();
int *log_plevel();

#ifdef WINDOWS
int log_init();
#endif

const char* log_priorityname(int priority);
void log_write(int mask,
		const char *file, const char *func, int line,
		const char *fmt, ...);
void log_vwrite(int mask,
		const char *file, const char *func, int line,
		const char *fmt, va_list args);
void log_vprintf_default(int mask,
		const char *file, const char *func, int line,
		const char* fmt, va_list args);
void log_vprintf_with_timestamp_default(int mask,
		const char *file, const char *func, int line,
		const char* fmt, va_list args);
void log_vprintf_writefile(int mask,
		const char *file, const char *func, int line,
		const char* fmt, va_list args);
void log_vprintf_syslog(int mask,
		const char *file, const char *func, int line,
		const char* fmt, va_list args);
void open_logfile(const char* log_file);
void close_logfile();
void open_syslog(const char *ident);
void close_syslog();
int is_use_syslog();
int is_use_logfile();
const char* get_logfile();

#define loglevel (*(log_plevel()))
#define logflags (*(log_pflags()))

#define log_level_comp(mask) ((mask) & 0xFF)

#define llog_write(mask, file, func, line, fmt, ...) \
	log_write((mask), (file), (func), (line), (fmt), ##__VA_ARGS__)

#define logc(fmt, ...) \
	do { \
		if (loglevel >= LOG_CRIT) { \
			llog_write(LOG_CRIT, \
					__DOHCLIENT_FILE__, \
					__DOHCLIENT_FUNC__, \
					__DOHCLIENT_LINE__,\
					(fmt), \
					##__VA_ARGS__); \
		} \
		exit(-1); \
	} while (0)

#define loge(fmt, ...) \
	do { \
		if (loglevel >= LOG_ERR) { \
			llog_write(LOG_ERR, \
					__DOHCLIENT_FILE__, \
					__DOHCLIENT_FUNC__, \
					__DOHCLIENT_LINE__,\
					(fmt), \
					##__VA_ARGS__); \
		} \
	} while (0)

#define logw(fmt, ...) \
	do { \
		if (loglevel >= LOG_WARNING) { \
			llog_write(LOG_WARNING, \
					__DOHCLIENT_FILE__, \
					__DOHCLIENT_FUNC__, \
					__DOHCLIENT_LINE__,\
					(fmt), \
					##__VA_ARGS__); \
		} \
	} while (0)

#define logn(fmt, ...) \
	do { \
		if (loglevel >= LOG_NOTICE) { \
			llog_write(LOG_NOTICE, \
					__DOHCLIENT_FILE__, \
					__DOHCLIENT_FUNC__, \
					__DOHCLIENT_LINE__,\
					(fmt), \
					##__VA_ARGS__); \
		} \
	} while (0)

#define logi(fmt, ...) \
	do { \
		if (loglevel >= LOG_INFO) { \
			llog_write(LOG_INFO, \
					__DOHCLIENT_FILE__, \
					__DOHCLIENT_FUNC__, \
					__DOHCLIENT_LINE__,\
					(fmt), \
					##__VA_ARGS__); \
		} \
	} while (0)

#define logd(fmt, ...) \
	do { \
		if (loglevel >= LOG_DEBUG) { \
			llog_write(LOG_DEBUG, \
					__DOHCLIENT_FILE__, \
					__DOHCLIENT_FUNC__, \
					__DOHCLIENT_LINE__,\
					(fmt), \
					##__VA_ARGS__); \
		} \
	} while (0)

#define logv(fmt, ...) \
	do { \
		if (loglevel >= LOG_VERBOS) { \
			llog_write(LOG_VERBOS, \
					__DOHCLIENT_FILE__, \
					__DOHCLIENT_FUNC__, \
					__DOHCLIENT_LINE__,\
					(fmt), \
					##__VA_ARGS__); \
		} \
	} while (0)

#ifdef __cplusplus
}
#endif

#endif
