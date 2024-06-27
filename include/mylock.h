#pragma once

#include "types.h"
#include "mysys.h"
#include "linux/futex.h"

typedef uint32_t Spinlock __attribute__((aligned(8)));
typedef Spinlock Mutex;
_Static_assert(__atomic_always_lock_free(sizeof(Spinlock), 0), "Spinlock");

typedef struct wstarving_t wstarving_t;
struct wstarving_t {
	Mutex read_lock;
	int reader_cnt;
	Mutex global_lock;
};

static __attribute__((unused))
void spinlock_lock(Spinlock *lock) {
	Spinlock expected = 0;

	while (!__atomic_compare_exchange_n(lock, &expected, 1, 0,
										__ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
		expected = 0;
	}
}

static __attribute__((unused))
int spinlock_trylock(Spinlock *lock) {
	Spinlock expected = 0;

	if (!__atomic_compare_exchange_n(lock, &expected, 1, 0,
									 __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
		return -1;
	}

	return 0;
}

static __attribute__((unused))
int mutex_trylock(Mutex *lock) {
	Mutex expected = 0;

	if (!__atomic_compare_exchange_n(lock, &expected, 1, 0,
									 __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
		return -1;
	}

	return 0;
}

static __attribute__((unused))
void spinlock_unlock(Spinlock *lock) {
	__atomic_store_n(lock, 0, __ATOMIC_RELEASE);
}

static __attribute__((unused))
void mutex_lock(Mutex *mutex) {
	Mutex expected = 0;
	int tries = 0;

	while (!__atomic_compare_exchange_n(mutex, &expected, 1, 0,
										__ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
		expected = 0;

		if (tries++ > 1000) {
			signed long ret;
			tries = 0;

			ret = futex(mutex, FUTEX_WAIT, 1, NULL, NULL, 0);
			if (ret < 0 && errno != EAGAIN) {
				abort();
			}
		}
	}
}

static __attribute__((unused))
void mutex_unlock(Mutex *mutex) {
	signed long ret;
	__atomic_store_n(mutex, 0, __ATOMIC_RELEASE);
	ret = futex(mutex, FUTEX_WAKE, 1, NULL, NULL, 0);
	if (ret < 0) {
		abort();
	}
}

static __attribute__((unused))
void wstarving_read_lock(wstarving_t *lock) {
	mutex_lock(&lock->read_lock);
	lock->reader_cnt++;
	if (lock->reader_cnt == 1) {
		mutex_lock(&lock->global_lock);
	}
	mutex_unlock(&lock->read_lock);
}

static __attribute__((unused))
void wstarving_read_unlock(wstarving_t *lock) {
	mutex_lock(&lock->read_lock);
	lock->reader_cnt--;
	if (lock->reader_cnt == 0) {
		mutex_unlock(&lock->global_lock);
	}
	mutex_unlock(&lock->read_lock);
}

static __attribute__((unused))
void wstarving_write_lock(wstarving_t *lock) {
	mutex_lock(&lock->global_lock);
}

static __attribute__((unused))
void wstarving_write_unlock(wstarving_t *lock) {
	mutex_unlock(&lock->global_lock);
}
