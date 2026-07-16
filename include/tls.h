#pragma once

#include "base_types.h"
#include "mylock.h"

#include <stdint.h>
#include <sys/types.h>
#include <limits.h>

#define SCRATCH_SIZE (64 * 1024)
static_assert(SCRATCH_SIZE >= PATH_MAX, "SCRATCH_SIZE");

struct Tls {
    pid_t pid;
    pid_t tid;
    RobustMutexList my_robust_mutex_list;
    RwLockList my_rwlock_list;
    void* jumpbuf[5];  // for lock tests
    int workarounds_traceme;
    char scratch[SCRATCH_SIZE];
};

RMapEntry* tls_search_binary(uint32_t tid);
void tls_clean_dead();

Tls* _tls_get_noalloc(uint32_t tid);
Tls* _tls_get(uint32_t tid);
void _tls_free(uint32_t tid);

Tls* tls_get_noalloc();
Tls* tls_get();
void tls_free();

void tls_init();
