
#include "mylock.h"
#include "util.h"

#include "mysys.h"
#include "linux/futex.h"

typedef struct LocalMutexes LocalMutexes;
struct LocalMutexes {
	Spinlock size;
	uint32_t alloc;
	RobustMutex data[];
};

static LocalMutexes *local_mutexes = NULL;

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

void spinlock_unlock(Spinlock *lock) {
	__atomic_store_n(lock, 0, __ATOMIC_RELEASE);
}

static void futex_wait(Mutex *mutex, Mutex expected) {
	signed long ret;
	struct timespec timeout = {1, 0};

	ret = sys_futex(mutex, FUTEX_WAIT, expected, &timeout, NULL, 0);
	if (ret < 0 && ret != -EAGAIN && ret != -ETIMEDOUT) {
		abort();
	}
}

static void futex_wake(Mutex *mutex) {
	signed long ret = sys_futex(mutex, FUTEX_WAKE, 1, NULL, NULL, 0);
	if (ret < 0) {
		abort();
	}
}

static int _mutex_lock(const pid_t tid, Mutex *mutex) {
	Mutex expected = 0;
	int tries = 0;
	int ownerdead = 0;

	while (!__atomic_compare_exchange_n(mutex, &expected, tid, 0,
										__ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
		if (tries++ > 1000) {
			tries = 0;

			if (is_tid_dead(expected)) {
				ownerdead = 1;
				continue;
			}

			futex_wait(mutex, expected);
		}

		expected = 0;
		ownerdead = 0;
	}

	return ownerdead;
}

static void __mutex_unlock(Mutex *mutex, pid_t val) {
	__atomic_store_n(mutex, val, __ATOMIC_RELEASE);
	futex_wake(mutex);
}

static void _mutex_unlock(Mutex *mutex) {
	__mutex_unlock(mutex, 0);
}

static void _mutex_wait(Mutex *mutex) {
	Mutex expected = __atomic_load_n(mutex, __ATOMIC_ACQUIRE);
	futex_wait(mutex, expected);
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

int mutex_locked(Tls *tls, RobustMutex *mutex) {
	uint32_t val = __atomic_load_n(&mutex->mutex, __ATOMIC_RELAXED);

	return val == (uint32_t) tls->tid;
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
			break;
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

static void rwlock_recover_pending(Tls *tls);
static void rwlock_recover_one(Tls *tls, RwLock *lock);
void mutex_recover(Tls *tls) {
	RobustMutexList *list = &tls->my_robust_mutex_list;
	RwLockList *rwlock_list = &tls->my_rwlock_list;

	mutex_recover_pending(tls);

	RobustMutex *elm, *temp;
	RLIST_FOREACH(elm, &list->head, next, temp) {
		mutex_recover_one(tls, elm);
	}

	rwlock_recover_pending(tls);
	RwLockHolder *relm, *rtemp;
	RLIST_FOREACH(relm, &rwlock_list->head, next, rtemp) {
		rwlock_recover_one(tls, relm->lock);
	}
}

void mutex_init() {
	if (local_mutexes) {
		abort();
	}

	// map shared, so we don't deadlock after fork()
	void *alloc = sys_mmap(NULL, 4096, PROT_READ|PROT_WRITE,
						   MAP_ANONYMOUS|MAP_SHARED, -1, 0);
	if ((unsigned long)alloc >= -4095UL) {
		abort();
	}
	local_mutexes = alloc;

	local_mutexes->alloc = (4096 - sizeof(LocalMutexes)) / sizeof(RobustMutex);
	assert(sizeof(LocalMutexes) + local_mutexes->alloc * sizeof(RobustMutex) <= 4096);
}

RobustMutex *mutex_alloc() {
	uint32_t idx = __atomic_fetch_add(&local_mutexes->size, 1, __ATOMIC_ACQUIRE);
	if (idx >= local_mutexes->alloc) {
		return NULL;
	}

	return local_mutexes->data + idx;
}

static int rwlock_cleanup_dead(RwLock *lock) {
	int dead = 0;
	if (lock->writer && is_tid_dead(lock->writer)) {
		dead = 1;
		__asm volatile ("" ::: "memory");
		WRITE_ONCE(lock->writer, FUTEX_TID_MASK);
		__asm volatile ("" ::: "memory");
	}

	if (lock->writer_waiter && is_tid_dead(lock->writer_waiter)) {
		__asm volatile ("" ::: "memory");
		WRITE_ONCE(lock->writer_waiter, 0);
		__asm volatile ("" ::: "memory");
	}

	for (int i = 0; i < holders_alloc; i++) {
		uint32_t *reader = lock->reader + i;

		if (*reader && is_tid_dead(*reader)) {
			dead = 1;
			lock->num_readers--;
			__asm volatile ("" ::: "memory");
			WRITE_ONCE(*reader, 0);
			__asm volatile ("" ::: "memory");
		}
	}

	return dead;
}

static void _rwlock_recover(RwLock *lock) {
	uint32_t num_readers = 0;
	for (int i = 0; i < holders_alloc; i++) {
		if (lock->reader[i]) {
			num_readers++;
		}
	}

	__asm volatile ("" ::: "memory");
	WRITE_ONCE(lock->num_readers, num_readers);
	__asm volatile ("" ::: "memory");
}

static void __rwlock_lock(Tls *tls, RwLock *lock, uint32_t *thelock,
						  RwLockHolder *entry) {
	RwLockList *list = &tls->my_rwlock_list;

	assert(thelock);
	assert(!list->pending);

	__asm volatile ("" ::: "memory");
	WRITE_ONCE(list->pending, lock);
	__asm volatile ("" ::: "memory");
	WRITE_ONCE(*thelock, tls->tid);
	__asm volatile ("" ::: "memory");
	RLIST_INSERT_HEAD(&list->head, entry, next);
	__asm volatile ("" ::: "memory");
	WRITE_ONCE(list->pending, NULL);
}

static void __rwlock_unlock(Tls *tls, RwLock *lock, uint32_t *thelock,
							RwLockHolder *entry) {
	RwLockList *list = &tls->my_rwlock_list;

	assert(thelock);
	assert(!list->pending);

	__asm volatile ("" ::: "memory");
	WRITE_ONCE(list->pending, lock);
	__asm volatile ("" ::: "memory");
	RLIST_REMOVE(&list->head, entry, next);
	__asm volatile ("" ::: "memory");
	WRITE_ONCE(*thelock, 0);
	__asm volatile ("" ::: "memory");
	WRITE_ONCE(list->pending, NULL);
}

static void _rwlock_lock_read(Tls *tls, RwLock *lock, int i) {
	uint32_t *reader = lock->reader + i;
	RwLockHolder *reader_entry = lock->reader_entry + i;

	lock->num_readers++;
	reader_entry->lock = lock;

	__rwlock_lock(tls, lock, reader, reader_entry);
}

static void _rwlock_unlock_read(Tls *tls, RwLock *lock, int i) {
	uint32_t *reader = lock->reader + i;
	RwLockHolder *reader_entry = lock->reader_entry + i;

	assert(*reader == (uint32_t)tls->tid);
	lock->num_readers--;

	__rwlock_unlock(tls, lock, reader, reader_entry);
}

static void _rwlock_lock_write(Tls *tls, RwLock *lock) {
	lock->writer_entry.lock = lock;

	__rwlock_lock(tls, lock, &lock->writer, &lock->writer_entry);
}

static void _rwlock_unlock_write(Tls *tls, RwLock *lock) {
	assert(lock->writer == (uint32_t)tls->tid);

	__rwlock_unlock(tls, lock, &lock->writer, &lock->writer_entry);
}

void rwlock_lock_read(Tls *tls, RwLock *lock) {
	int defer_once = 1;
	while (1) {
		int ownerdead = mutex_lock(tls, &lock->mutex);
		if (ownerdead) {
			_rwlock_recover(lock);
		}

		if (lock->writer || lock->num_readers == holders_alloc ||
				(lock->writer_waiter && lock->num_readers && defer_once) ) {
			int dead = rwlock_cleanup_dead(lock);
			mutex_unlock(tls, &lock->mutex);
			if (!dead) {
				_mutex_wait(&lock->waiters);
				defer_once = 0;
			}
			continue;
		}

		if (lock->writer_waiter) {
			WRITE_ONCE(lock->writer_waiter, 0);
		}

		for (int i = 0; i < holders_alloc; i++) {
			if (!lock->reader[i]) {
				_rwlock_lock_read(tls, lock, i);

				mutex_unlock(tls, &lock->mutex);
				return;
			}
		}

		//mutex_unlock(tls, &lock->mutex);
		abort();
	}
}

void rwlock_unlock_read(Tls *tls, RwLock *lock) {
	int ownerdead = mutex_lock(tls, &lock->mutex);
	if (ownerdead) {
		_rwlock_recover(lock);
	}

	for (int i = 0; i < holders_alloc; i++) {
		if (lock->reader[i] == (uint32_t)tls->tid) {
			_rwlock_unlock_read(tls, lock, i);

			mutex_unlock(tls, &lock->mutex);
			futex_wake(&lock->waiters);
			return;
		}
	}

	//mutex_unlock(tls, &lock->mutex);
	abort();
}

int rwlock_lock_write(Tls *tls, RwLock *lock) {
	while (1) {
		int ownerdead = mutex_lock(tls, &lock->mutex);
		if (ownerdead) {
			_rwlock_recover(lock);
		}

		if (lock->writer) {
			int ownerdead = is_tid_dead(lock->writer);
			if (ownerdead) {
				_rwlock_lock_write(tls, lock);
				if (lock->writer_waiter == (uint32_t)tls->tid) {
					WRITE_ONCE(lock->writer_waiter, 0);
				}

				mutex_unlock(tls, &lock->mutex);
				return 1;
			}
		}

		if (lock->writer || lock->num_readers) {
			int dead = rwlock_cleanup_dead(lock);
			if (!lock->writer_waiter) {
				WRITE_ONCE(lock->writer_waiter, tls->tid);
			}
			mutex_unlock(tls, &lock->mutex);
			if (!dead) {
				_mutex_wait(&lock->waiters);
			}
			continue;
		}

		_rwlock_lock_write(tls, lock);
		if (lock->writer_waiter == (uint32_t)tls->tid) {
			WRITE_ONCE(lock->writer_waiter, 0);
		}

		mutex_unlock(tls, &lock->mutex);
		return 0;
	}
}

void rwlock_unlock_write(Tls *tls, RwLock *lock) {
	int ownerdead = mutex_lock(tls, &lock->mutex);
	if (ownerdead) {
		_rwlock_recover(lock);
	}

	_rwlock_unlock_write(tls, lock);

	mutex_unlock(tls, &lock->mutex);
}

static void rwlock_recover_pending(Tls *tls) {
	RwLockList *list = &tls->my_rwlock_list;
	RwLock *lock = list->pending;

	if (!lock) {
		return;
	}

	int ownerdead = mutex_lock(tls, &lock->mutex);
	if (ownerdead) {
		_rwlock_recover(lock);
	}

	uint32_t *thelock = NULL;
	RwLockHolder *entry = NULL;
	if (lock->writer == (uint32_t)tls->tid) {
		thelock = &lock->writer;
		entry = &lock->writer_entry;
	}
	for (int i = 0; i < holders_alloc; i++) {
		if (lock->reader[i] == (uint32_t)tls->tid) {
			thelock = lock->reader + i;
			entry = lock->reader_entry + i;
		}
	}

	int found = 0;
	RwLockHolder *elm, *temp;
	RLIST_FOREACH(elm, &list->head, next, temp) {
		if (elm == entry) {
			found = 1;
			break;
		}
	}

	__asm volatile ("" ::: "memory");
	if (found) {
		RLIST_REMOVE(&list->head, entry, next);
	}
	__asm volatile ("" ::: "memory");
	if (thelock) {
		WRITE_ONCE(*thelock, FUTEX_TID_MASK);
	}
	__asm volatile ("" ::: "memory");
	WRITE_ONCE(list->pending, NULL);
	__asm volatile ("" ::: "memory");

	mutex_unlock(tls, &lock->mutex);
}

static void rwlock_recover_one(Tls *tls, RwLock *lock) {
	RwLockList *list = &tls->my_rwlock_list;

	assert(!list->pending);

	int ownerdead = mutex_lock(tls, &lock->mutex);
	if (ownerdead) {
		_rwlock_recover(lock);
	}

	uint32_t *thelock = NULL;
	RwLockHolder *entry = NULL;
	if (lock->writer == (uint32_t)tls->tid) {
		thelock = &lock->writer;
		entry = &lock->writer_entry;
	}
	for (int i = 0; i < holders_alloc; i++) {
		if (lock->reader[i] == (uint32_t)tls->tid) {
			thelock = lock->reader + i;
			entry = lock->reader_entry + i;
		}
	}

	__asm volatile ("" ::: "memory");
	WRITE_ONCE(list->pending, lock);
	__asm volatile ("" ::: "memory");
	RLIST_REMOVE(&list->head, entry, next);
	__asm volatile ("" ::: "memory");
	WRITE_ONCE(*thelock, FUTEX_TID_MASK);
	__asm volatile ("" ::: "memory");
	WRITE_ONCE(list->pending, NULL);

	mutex_unlock(tls, &lock->mutex);
}
