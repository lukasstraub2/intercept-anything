#pragma once

#include "std.h"

#define TLS_LIST_ALLOC 4096

typedef struct TlsList TlsList;
typedef struct Tls Tls;
struct Tls {
	char data[4096];
};

TlsList *tls_search_binary(uint32_t tid);
Tls *_tls_get(uint32_t tid);
void _tls_free(uint32_t tid);
Tls *tls_get();
void tls_free();
