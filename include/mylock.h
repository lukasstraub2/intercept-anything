#pragma once

#include "mylist.h"
#include "base_types.h"

#include <stdint.h>

typedef uint32_t Spinlock __attribute__((aligned(8)));
typedef Spinlock Mutex;
static_assert(__atomic_always_lock_free(sizeof(Spinlock), 0), "Spinlock");

struct RobustMutex {
    Mutex mutex;
    RLIST_ENTRY(RobustMutex) next;
};

#define holders_alloc (32)
struct RwLockHolder {
    RwLock* lock;
    RLIST_ENTRY(RwLockHolder) next;
};

struct RwLock {
    RobustMutex mutex;
    Mutex waiters;
    uint32_t writer_waiter;
    uint32_t num_readers;
    uint32_t writer;
    uint32_t reader[holders_alloc];
    RwLockHolder writer_entry;
    RwLockHolder reader_entry[holders_alloc];
};

RLIST_HEAD(RobustMutexHead, RobustMutex);
RLIST_HEAD(RwLockHead, RwLockHolder);

struct RobustMutexList {
    RobustMutexHead head;
    RobustMutex* pending;
};

struct RwLockList {
    RwLockHead head;
    RwLock* pending;
};

#define WRITE_ONCE(var, x) __atomic_store_n(&(var), (x), __ATOMIC_RELAXED)

int mutex_lock(Tls* tls, RobustMutex* mutex);
void mutex_unlock(Tls* tls, RobustMutex* mutex);
int mutex_locked(Tls* tls, RobustMutex* mutex);
void mutex_recover(Tls* tls);

void mutex_init();
RobustMutex* mutex_alloc();

void rwlock_lock_read(Tls* tls, RwLock* lock);
void rwlock_unlock_read(Tls* tls, RwLock* lock);
int rwlock_lock_write(Tls* tls, RwLock* lock);
void rwlock_unlock_write(Tls* tls, RwLock* lock);
