
#include "mylock.h"
#include "util.h"

#include "mysys.h"
#include "linux/futex.h"

typedef struct rwlock_t rwlock_t;
struct rwlock_t {
	Mutex serialize_lockers;
	Mutex update_lock;
	int rcount_new;
	Mutex write_lock;
	int rcount;
};

void spinlock_lock(Spinlock *lock) {
	Spinlock expected = 0;

	while (!__atomic_compare_exchange_n(lock, &expected, 1, 0,
										__ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
		expected = 0;
	}
}

int spinlock_trylock(Spinlock *lock) {
	Spinlock expected = 0;

	if (!__atomic_compare_exchange_n(lock, &expected, 1, 0,
									 __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
		return -1;
	}

	return 0;
}

static int _mutex_trylock(pid_t tid, Mutex *lock) {
	Mutex expected = 0;

	if (!__atomic_compare_exchange_n(lock, &expected, tid, 0,
									 __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
		return -1;
	}

	return 0;
}

void spinlock_unlock(Spinlock *lock) {
	__atomic_store_n(lock, 0, __ATOMIC_RELEASE);
}

static int is_ownerdead(Mutex expected) {
	while (1) {
		int ret = sys_tkill(expected, 0);
		if (ret < 0) {
			if (ret == -EAGAIN) {
				continue;
			} else if (ret == -ESRCH) {
				return 1;
			} else {
				abort();
			}
		} else {
			return 0;
		}
	}
}

static int _mutex_lock(const pid_t tid, Mutex *mutex) {
	Mutex expected = 0;
	int tries = 0;
	int ownerdead = 0;

	while (!__atomic_compare_exchange_n(mutex, &expected, tid, 0,
										__ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
		if (tries++ > 1000) {
			signed long ret;
			tries = 0;

			if (is_ownerdead(expected)) {
				ownerdead = 1;
				continue;
			}

			ret = sys_futex(mutex, FUTEX_WAIT, expected, NULL, NULL, 0);
			if (ret < 0 && ret != -EAGAIN) {
				abort();
			}
		}

		expected = 0;
		ownerdead = 0;
	}

	return ownerdead;
}

static void __mutex_unlock(Mutex *mutex, pid_t val) {
	signed long ret;
	__atomic_store_n(mutex, val, __ATOMIC_RELEASE);
	ret = sys_futex(mutex, FUTEX_WAKE, 1, NULL, NULL, 0);
	if (ret < 0) {
		abort();
	}
}

static void _mutex_unlock(Mutex *mutex) {
	__mutex_unlock(mutex, 0);
}

int mutex_lock(Tls *tls, RobustMutex *mutex) {
	RobustMutexList *list = &tls->my_robust_mutex_list;

	assert(!list->pending);

	WRITE_ONCE(list->pending, mutex);
	__asm volatile ("" ::: "memory");
	int ownerdead = _mutex_lock(tls->tid, &mutex->mutex);
	__asm volatile ("" ::: "memory");
	RLIST_INSERT_HEAD(&list->head, mutex, next);
	__asm volatile ("" ::: "memory");
	WRITE_ONCE(list->pending, NULL);
	__asm volatile ("" ::: "memory");

	return ownerdead;
}

void mutex_unlock(Tls *tls, RobustMutex *mutex) {
	RobustMutexList *list = &tls->my_robust_mutex_list;

	assert(!list->pending);

	WRITE_ONCE(list->pending, mutex);
	__asm volatile ("" ::: "memory");
	RLIST_REMOVE(&list->head, mutex, next);
	__asm volatile ("" ::: "memory");
	_mutex_unlock(&mutex->mutex);
	__asm volatile ("" ::: "memory");
	WRITE_ONCE(list->pending, NULL);
	__asm volatile ("" ::: "memory");
}

static void mutex_recover_pending(Tls *tls) {
	RobustMutexList *list = &tls->my_robust_mutex_list;
	RobustMutex *mutex = list->pending;

	if (!mutex) {
		return;
	}

	pid_t mutex_tid = __atomic_load_n(&mutex->mutex, __ATOMIC_RELAXED);
	int found = 0;
	RobustMutex *elm, *temp;
	RLIST_FOREACH(elm, &list->head, next, temp) {
		if (elm == mutex) {
			found = 1;
		}
	}

	__asm volatile ("" ::: "memory");
	if (found) {
		RLIST_REMOVE(&list->head, mutex, next);
	}
	__asm volatile ("" ::: "memory");
	if (tls->tid == mutex_tid) {
		__mutex_unlock(&mutex->mutex, FUTEX_TID_MASK);
	}
	__asm volatile ("" ::: "memory");
	WRITE_ONCE(list->pending, NULL);
	__asm volatile ("" ::: "memory");
}

static void mutex_recover_one(Tls *tls, RobustMutex *mutex) {
	RobustMutexList *list = &tls->my_robust_mutex_list;
	pid_t mutex_tid = __atomic_load_n(&mutex->mutex, __ATOMIC_RELAXED);

	assert(!list->pending);
	assert(tls->tid == mutex_tid);

	WRITE_ONCE(list->pending, mutex);
	__asm volatile ("" ::: "memory");
	RLIST_REMOVE(&list->head, mutex, next);
	__asm volatile ("" ::: "memory");
	__mutex_unlock(&mutex->mutex, FUTEX_TID_MASK);
	__asm volatile ("" ::: "memory");
	WRITE_ONCE(list->pending, NULL);
	__asm volatile ("" ::: "memory");
}

void mutex_recover(Tls *tls) {
	RobustMutexList *list = &tls->my_robust_mutex_list;

	mutex_recover_pending(tls);

	RobustMutex *elm, *temp;
	RLIST_FOREACH(elm, &list->head, next, temp) {
		mutex_recover_one(tls, elm);
	}
}

/*
void rwlock_read_lock(rwlock_t *lock) {
	int rcount;

	_mutex_lock(1, &lock->serialize_lockers);
	_mutex_lock(1, &lock->update_lock);

	rcount = lock->rcount + 1;

	lock->rcount_new = rcount;
	__asm volatile ("" ::: "memory");
	lock->rcount = rcount;

	_mutex_unlock(&lock->serialize_lockers);
	if (rcount == 1) {
		_mutex_lock(1, &lock->write_lock);
	}

	_mutex_unlock(&lock->update_lock);
}

void rwlock_read_unlock(rwlock_t *lock) {
	int rcount;

	_mutex_lock(1, &lock->update_lock);

	rcount = lock->rcount - 1;

	lock->rcount_new = rcount;
	__asm volatile ("" ::: "memory");
	lock->rcount = rcount;

	if (rcount == 0) {
		_mutex_unlock(&lock->write_lock);
	}
	_mutex_unlock(&lock->update_lock);
}

void rwlock_write_lock(rwlock_t *lock) {
	_mutex_lock(1, &lock->serialize_lockers);
	_mutex_lock(1, &lock->write_lock);
	_mutex_unlock(&lock->serialize_lockers);
}

void rwlock_write_unlock(rwlock_t *lock) {
	_mutex_unlock(&lock->write_lock);
}
*/
