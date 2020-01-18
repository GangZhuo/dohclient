#ifndef DOHCLIENT_STREAM_H_
#define DOHCLIENT_STREAM_H_

#include <stdio.h>
#include <stdarg.h>
#include "log.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct stream_t {
	char *array;
	int size; /* elements size */
	int pos; /* position */
	int cap; /* capacity */
} stream_t;

#define STREAM_INIT() { 0 }

/* remaining capacity */
#define stream_rcap(stream) ((stream)->cap - (stream)->pos)

/* remaining size */
#define stream_rsize(stream) ((stream)->size - (stream)->pos)

#define stream_reset(stream) ((stream)->size = (stream)->pos = 0)

int stream_init(stream_t *stream);

void stream_free(stream_t *stream);

int stream_seek(stream_t *stream, int offset, int whence);

int stream_shrink(stream_t *stream);

int stream_quake(stream_t* stream);

int stream_set_cap(stream_t *stream, int cap);

int stream_read(stream_t *stream, char *dst, int n);

int stream_write(stream_t *stream, const char *s, int n);

int stream_writei(stream_t *stream, int v, int nb);

int stream_vwritef(stream_t *stream, const char *fmt, va_list args);

int stream_writef(stream_t *stream, const char *fmt, ...);

int stream_writes(stream_t* stream, const char* s, int n);

int stream_writess(stream_t *dst, stream_t *src, int n);

int stream_readi(stream_t *stream, int nb);

int stream_seti(stream_t *stream, int position, int v, int nb);

int stream_geti(stream_t* stream, int position, int nb);

int stream_append(stream_t* stream, const char* s, int n);

int stream_appends(stream_t* stream, const char* s, int n);

int stream_vappendf(stream_t* stream, const char* fmt, va_list args);

int stream_appendf(stream_t* stream, const char* fmt, ...);

void _bprint(char *data, int len);

#define bprint(d, n) \
	do { \
		if (loglevel >= LOG_DEBUG) { \
			_bprint((d), (n)); \
		} \
	} while(0)

/* int stream_writee(stream_t *stream, void *p, int elementsize, int elementnumber) */
/*
write elements.
  p  - array
  sz - element size in bytes
  n  - element count
*/
#define stream_writee(s, p, sz, n) \
	stream_write((s), (p), (sz) * (n))

#define stream_writei32(s, v) \
	stream_writei((s), (v), 4)

#define stream_writei16(s, v) \
	stream_writei((s), (v), 2)

#define stream_writei8(s, v) \
	stream_writei((s), (v), 1)

#define stream_writestr(s, str) \
	stream_writes((s), (str), strlen(str))

#define stream_seti16(s, p, v) \
	stream_seti((s), (p), (v), 2)

#define stream_readi32(s) \
	stream_readi((s), 4)

#define stream_readi16(s) \
	stream_readi((s), 2)

#define stream_readi8(s) \
	stream_readi((s), 1)


#ifdef __cplusplus
}
#endif

#endif
