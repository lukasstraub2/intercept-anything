#pragma once

#include "types.h"
#include "mylist.h"
#include "base_types.h"

typedef uint32_t Spinlock __attribute__((aligned(8)));
typedef Spinlock Mutex;
_Static_assert(__atomic_always_lock_free(sizeof(Spinlock), 0), "Spinlock");

struct RobustMutex {
	Mutex mutex;
	RLIST_ENTRY(RobustMutex) next;
};

RLIST_HEAD(RobustMutexHead, RobustMutex);

struct RobustMutexList {
	RobustMutexHead head;
	RobustMutex *pending;
};

#define WRITE_ONCE(var, x) __atomic_store_n(&(var), (x), __ATOMIC_RELAXED)

int mutex_lock(Tls *tls, RobustMutex *mutex);
void mutex_unlock(Tls *tls, RobustMutex *mutex);
void mutex_recover(Tls *tls);

void mutex_init();
RobustMutex *mutex_alloc();
