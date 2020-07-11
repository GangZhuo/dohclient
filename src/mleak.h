#ifndef DOHCLIENT_MLEAK_H_
#define DOHCLIENT_MLEAK_H_

/* 自定义malloc,free方法。用于检查内存泄漏。 */
#ifdef WIN32
# include <malloc.h>
#else
# include <alloca.h>
#endif


#ifdef __cplusplus
extern "C" {
#endif

typedef void(*mleak_print_fun)(void *ptr, const char *filename, int line, const char* time);

/* 原始的 malloc() 函数 */
void *mleak_malloc_raw(size_t size);
/* 原始的 free() 函数 */
void mleak_free_raw(void *ptr);

/* 带有泄漏检测的 malloc() 函数 */
void *mleak_malloc(size_t size, const char *filename, int line);
/* 带有泄漏检测的 malloc() 函数 */
void *mleak_malloc_arg1(size_t sz);
void* mleak_realloc(void* ptr, size_t size, const char* filename, int line);
void* mleak_strdup(const char* s, const char* filename, int line);
void* mleak_calloc(size_t count, size_t size, const char* filename, int line);
/* 带有泄漏检测的 free() 函数 */
void mleak_free(void *p);
/* 打印泄漏的内存 */
void mleak_print_leak();

void mleak_set_print_func(mleak_print_fun print);


#if defined(DEBUG) || defined(_DEBUG)

#  define print_leak()			mleak_print_leak()
#  define malloc(size)			mleak_malloc((size), __FILE__, __LINE__)
#  define realloc(ptr, size)	mleak_realloc((ptr), (size), __FILE__, __LINE__)
#  define calloc(count, size)	mleak_calloc((count), (size), __FILE__, __LINE__)
#  undef strdup
#  define strdup(s)	            mleak_strdup((s), __FILE__, __LINE__)
#  define free(ptr)				mleak_free(ptr)

#else
#  include <stdlib.h>
#  define print_leak()			while(0)
#endif


#ifdef __cplusplus
}
#endif

#endif
