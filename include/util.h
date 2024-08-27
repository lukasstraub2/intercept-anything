#pragma once

#include "stdint.h"
#include "tls.h"

#define max(a,b)             \
({                           \
	__typeof__ (a) _a = (a); \
	__typeof__ (b) _b = (b); \
	_a > _b ? _a : _b;       \
})

#define min(a,b)             \
({                           \
	__typeof__ (a) _a = (a); \
	__typeof__ (b) _b = (b); \
	_a < _b ? _a : _b;       \
})

#define assert(cond) \
	if (!(cond)) { \
		abort(); \
	}

#define alloca	__builtin_alloca

int is_tid_dead(pid_t tid);
int is_pid_dead(pid_t pid);

size_t concat(char *out, size_t out_len, const char *a, const char *b);
size_t concat3(char *out, size_t out_len,
			   const char *a, const char *b, const char *c);
int strcmp_prefix(const char *a, const char *b);

int getcwd_cache(Cache *cache, char *out, size_t out_len);
ssize_t readlink_cache(Cache *cache, char *out, size_t out_len,
					   int dirfd, const char *path);
ssize_t concatat(Cache *cache, char *out, size_t out_len,
				 int dirfd, const char *path);
