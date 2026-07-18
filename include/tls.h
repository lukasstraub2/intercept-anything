#pragma once

#include "base_types.h"
#include "mylock.h"

#include <stdint.h>
#include <sys/types.h>
#include <limits.h>

#define SCRATCH_SIZE (64 * 1024)
static_assert(SCRATCH_SIZE >= PATH_MAX, "SCRATCH_SIZE");

struct Tls {
    int vfork_idx;
    pid_t pid;
    pid_t tid;
    RobustMutexList my_robust_mutex_list;
    RwLockList my_rwlock_list;
    void* jumpbuf[5];  // for lock tests
    int workarounds_traceme;
    char scratch[SCRATCH_SIZE];
};
