#pragma once

#include "stdint.h"

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

size_t concat(char *out, size_t out_len, const char *a, const char *b);
int strcmp_prefix(const char *a, const char *b);
