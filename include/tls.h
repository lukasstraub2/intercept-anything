#pragma once

#include "base_types.h"
#include "mynolibc.h"
#include "config.h"
#include "mylock.h"

// Needed by libgcc due to atomics
__attribute__((weak, unused, section(".text.nolibc___getauxval"))) unsigned long
__getauxval(unsigned long type) {
    return getauxval(type);
}

typedef volatile uint32_t TlsAtomic32 __attribute__((aligned(8)));
static_assert(__atomic_always_lock_free(sizeof(TlsAtomic32), 0), "TlsAtomic32");

#define TLS_READ(var) __atomic_load_n(&(var), __ATOMIC_RELAXED)
#define TLS_WRITE(var, x) __atomic_store_n(&(var), (x), __ATOMIC_RELAXED)
#define TLS_INC_FETCH(var) __atomic_add_fetch(&(var), 1, __ATOMIC_RELAXED)
#define TLS_BARRIER() __asm volatile("" ::: "memory")

enum CacheType { CACHETYPE_READLINK, CACHETYPE_GETCWD };
typedef enum CacheType CacheType;

struct Cache {
    TlsAtomic32 reentrant_cnt;
    CacheType type;
    int in_dirfd;
    size_t out_len;
    char in_path[SCRATCH_SIZE];
    char out[SCRATCH_SIZE];
};

#define JUMPBUF_MAGIC \
    "jumpbuf magic .o0o._.o0o._.o0o._.o0o._.o0o._.o0o._.o0o._.o0o._."
#define JUMPBUF_MAGIC_LEN (64)
typedef struct MyJumpbuf MyJumpbuf;
struct MyJumpbuf {
    char magic[JUMPBUF_MAGIC_LEN];
    void* jumpbuf[5];
};

#define TLS_LIST_ALLOC 4096
#define jumpbuf_alloc (32)
struct Tls {
    pid_t pid;
    pid_t tid;
    Cache cache;
    RobustMutexList my_robust_mutex_list;
    RwLockList my_rwlock_list;
    MyJumpbuf* jumpbuf[jumpbuf_alloc];
    int workarounds_traceme;
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
