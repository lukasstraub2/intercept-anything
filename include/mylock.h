#pragma once

#include "types.h"
#include "mysys.h"
#include "linux/futex.h"

typedef uint32_t spinlock_t __attribute__((aligned(8)));
typedef spinlock_t mutex_t;

typedef struct wstarving_t wstarving_t;
struct wstarving_t {
	mutex_t read_lock;
	int reader_cnt;
	mutex_t global_lock;
};

static __attribute__((unused))
void spinlock_lock(spinlock_t *lock) {
	spinlock_t expected = 0;

	while (!__atomic_compare_exchange_n(lock, &expected, 1, 0,
										__ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
		expected = 0;
	}
}

static __attribute__((unused))
int spinlock_trylock(spinlock_t *lock) {
	spinlock_t expected = 0;

	if (!__atomic_compare_exchange_n(lock, &expected, 1, 0,
									 __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
		return -1;
	}

	return 0;
}

static __attribute__((unused))
int mutex_trylock(mutex_t *lock) {
	mutex_t expected = 0;

	if (!__atomic_compare_exchange_n(lock, &expected, 1, 0,
									 __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
		return -1;
	}

	return 0;
}

static __attribute__((unused))
void spinlock_unlock(spinlock_t *lock) {
	__atomic_store_n(lock, 0, __ATOMIC_RELEASE);
}

static __attribute__((unused))
void mutex_lock(mutex_t *mutex) {
	mutex_t expected = 0;
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
void mutex_unlock(mutex_t *mutex) {
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
