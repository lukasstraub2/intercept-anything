#pragma once

#include "std.h"

typedef struct Tls Tls;
struct Tls {
	char data[4096];
};

Tls *tls_get(uint32_t tid);
void tls_free(uint32_t tid);
