#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

struct mleak_mem_t {
	struct mleak_mem_t	*prev;
	struct mleak_mem_t	*next;

	void				*ptr;
	size_t              size;
	const char			*filename;
	int					line;

};

typedef void(*mleak_print_fun)(void *ptr, const char *filename, int line);

static void cb_leak_printf(void *ptr, const char *filename, int line);

static struct mleak_mem_t *_mem = 0;
static mleak_print_fun _print = cb_leak_printf;

static void cb_leak_printf(void *ptr, const char *filename, int line)
{
	printf("Memory leak on %p %s, %d\n", ptr, filename, line);
}

static inline void append_mem_ent(struct mleak_mem_t *mem)
{
	if (!_mem) {
		_mem = mem;
		mem->next = mem;
		mem->prev = mem;
	}
	else {
		mem->next = _mem;
		mem->prev = _mem->prev;
		_mem->prev->next = mem;
		_mem->prev = mem;
	}
}

static inline void remove_mem_ent(struct mleak_mem_t *mem)
{
	if (mem->next == mem) {
		_mem = 0;
		return;
	}
	else {
		if (mem == _mem) _mem = _mem->next;
		mem->prev->next = mem->next;
		mem->next->prev = mem->prev;
	}
}

void *mleak_malloc(size_t size, const char *filename, int line)
{
	struct mleak_mem_t *ent;
	ent = (struct mleak_mem_t *) malloc(sizeof(struct mleak_mem_t) + size);
	ent->ptr = (void *)(((char *)ent) + sizeof(struct mleak_mem_t));
	ent->size = size;
	ent->filename = filename;
	ent->line = line;
	append_mem_ent(ent);
	return ent->ptr;
}

void *mleak_malloc_arg1(size_t sz)
{
	return mleak_malloc(sz, "unknow", 0);
}

void mleak_free(void *ptr)
{
    if (!ptr) return;
	struct mleak_mem_t *ent;
	ent = (struct mleak_mem_t *)(((char *)ptr) - sizeof(struct mleak_mem_t));
	remove_mem_ent(ent);
	free(ent);
}

void* mleak_realloc(void* ptr, size_t size, const char* filename, int line)
{
	void* newptr = mleak_malloc(size, filename, line);
	if (!newptr) return NULL;
	if (ptr) {
		struct mleak_mem_t* ent;
		ent = (struct mleak_mem_t*)(((char*)ptr) - sizeof(struct mleak_mem_t));
		memcpy(newptr, ptr, min(size, ent->size));
		mleak_free(ptr);
	}
	return newptr;
}

void* mleak_strdup(const char *s, const char* filename, int line)
{
	int len = strlen(s);
	void* newptr = mleak_malloc(len + 1, filename, line);
	if (!newptr) return NULL;
	memcpy(newptr, s, len + 1);
	return newptr;
}

void* mleak_calloc(size_t count, size_t size, const char* filename, int line)
{
	return mleak_malloc(count * size, filename, line);
}

void mleak_print_leak()
{
	struct mleak_mem_t *ent, *p;
	if (!_mem) return;
	ent = _mem;
	do {
		_print(ent->ptr, ent->filename, ent->line);
		ent = ent->next;
	} while(ent != _mem);
	ent = _mem;
	do {
		p = ent;
		ent = ent->next;
		free(p);
	} while(ent != _mem);
	_mem = 0;
}

void *mleak_malloc_raw(size_t size)
{
	return malloc(size);
}

void mleak_free_raw(void *ptr)
{
	free(ptr);
}

void mleak_set_print_func(mleak_print_fun print)
{
	_print = print;
}

#ifdef __cplusplus
}
#endif
