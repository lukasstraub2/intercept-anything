#pragma once

#include "std.h"

#define TLS_LIST_ALLOC 4096

typedef struct TlsList TlsList;
typedef struct Tls Tls;
struct Tls {
	pid_t tid;
};

TlsList *tls_search_binary(uint32_t tid);

Tls *_tls_get_noalloc(uint32_t tid);
Tls *_tls_get(uint32_t tid);
void _tls_free(uint32_t tid);

Tls *tls_get_noalloc();
Tls *tls_get();
void tls_free();
