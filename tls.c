
#include "common.h"
#include "nolibc.h"

#define DEBUG_ENV "DEBUG_TLS"
#include "debug.h"
#include "tls.h"
#include "mylock.h"
#include "util.h"

struct TlsList {
	Spinlock tid;
	Tls *data;
};
_Static_assert(sizeof(Spinlock) >= sizeof(pid_t), "pid_t > Spinlock");

static Spinlock thread_data_size = 0;
static TlsList thread_data[TLS_LIST_ALLOC] = {0};

static int tls_size() {
	uint32_t size = __atomic_load_n(&thread_data_size, __ATOMIC_RELAXED);

	return min(size, (uint32_t)TLS_LIST_ALLOC);
}

static TlsList *_tls_search_binary(const uint32_t tid, int u, int o) {
	if (u > o) {
		return NULL;
	}

	int index = (u + o)/2;

	TlsList *current_entry = thread_data + index;
	uint32_t current_tid = __atomic_load_n(&current_entry->tid, __ATOMIC_RELAXED);
	while (!current_tid) {
		if (current_entry == thread_data) {
			return NULL;
		}
		current_entry--;
		current_tid = __atomic_load_n(&current_entry->tid, __ATOMIC_RELAXED);
	}

	if (current_tid == tid) {
		return current_entry;
	} else if (tid < current_tid) {
		return _tls_search_binary(tid, u, index - 1);
	} else {
		return _tls_search_binary(tid, index + 1, o);
	}
}

TlsList *tls_search_binary(const uint32_t tid) {
	int size = tls_size();

	if (!size) {
		return NULL;
	}

	return _tls_search_binary(tid, 0, size -1);
}

static TlsList *tls_search_linear(const uint32_t tid) {
	int size = tls_size();

	for (int i = 0; i < size; i++) {
		TlsList *current_entry = thread_data + i;
		uint32_t current_tid = __atomic_load_n(&current_entry->tid, __ATOMIC_RELAXED);

		if (current_tid == tid) {
			return current_entry;
		}
	}

	return NULL;
}

// TODO: This is not reentrant at all
static TlsList *tls_alloc(TlsList *entry, const uint32_t tid) {
	Tls *tls;
	pid_t pid = getpid();
	trace("malloc()\n");

	tls = malloc(sizeof(Tls));
	if (!tls) {
		abort();
	}

	// nolibc implementation ensures tls is zero-initialized
	tls->pid = pid;
	tls->tid = tid;
	__asm volatile ("" ::: "memory");

	entry->data = tls;
	return entry;
}

static TlsList *tls_alloc_append(const uint32_t tid) {
	int size = tls_size();
	Spinlock expected = 0;

	if (size >= TLS_LIST_ALLOC) {
		return NULL;
	}

	while (1) {
		uint32_t idx = __atomic_fetch_add(&thread_data_size, 1, __ATOMIC_ACQUIRE);
		TlsList *current_entry = thread_data + idx;

		if (idx >= TLS_LIST_ALLOC) {
			return NULL;
		}

		if (!__atomic_compare_exchange_n(&current_entry->tid, &expected, tid, 0,
										 __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
			expected = 0;
			continue;
		}

		return tls_alloc(current_entry, tid);
	}
}

static TlsList *tls_alloc_sparse(const uint32_t tid) {
	int size = tls_size();
	Spinlock expected = 0;

	for (int i = 0; i < size; i++) {
		TlsList *current_entry = thread_data + i;

		if (!__atomic_compare_exchange_n(&current_entry->tid, &expected, tid, 0,
										 __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
			expected = 0;
			continue;
		}

		return tls_alloc(current_entry, tid);
	}

	return NULL;
}

static TlsList *__tls_get_noalloc(const uint32_t tid) {
	TlsList *tls;

	if (!tid) {
		abort();
	}

	tls = tls_search_binary(tid);
	if (tls) {
		return tls;
	}

	tls = tls_search_linear(tid);
	if (tls) {
		return tls;
	}

	return NULL;
}

Tls *_tls_get_noalloc(const uint32_t tid) {
	TlsList *tls;

	tls = __tls_get_noalloc(tid);
	if (tls) {
		assert(tls->tid > 0);
		return tls->data;
	}

	return NULL;
}

Tls *_tls_get(const uint32_t tid) {
	TlsList *tls;

	tls = __tls_get_noalloc(tid);
	if (tls) {
		assert(tls->tid > 0);
		return tls->data;
	}

	tls = tls_alloc_append(tid);
	if (tls) {
		assert(tls->tid > 0);
		return tls->data;
	}

	tls = tls_alloc_sparse(tid);
	if (tls) {
		assert(tls->tid > 0);
		return tls->data;
	}

	abort();
	return NULL;
}

static void __tls_free(TlsList *entry) {
	uint32_t size = __atomic_load_n(&thread_data_size, __ATOMIC_ACQUIRE);
	uint32_t actual_size = min(size, (uint32_t)TLS_LIST_ALLOC);
	uint32_t idx = entry - thread_data;
	Spinlock expected = size;

	free(entry->data);
	entry->data = NULL;

	if (idx == actual_size -1) {
		__atomic_compare_exchange_n(&thread_data_size, &expected, actual_size -1,
									0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
	}

	__atomic_store_n(&entry->tid, 0, __ATOMIC_RELEASE);
}

void _tls_free(const uint32_t tid) {
	TlsList *tls;

	if (!tid) {
		abort();
	}

	tls = __tls_get_noalloc(tid);
	if (tls) {
		assert(tls->tid > 0);
		__tls_free(tls);
	}
}

Tls *tls_get_noalloc() {
	pid_t tid = gettid();
	trace("gettid(): %u\n", tid);
	return _tls_get_noalloc(tid);
}

Tls *tls_get() {
	pid_t tid = gettid();
	trace("gettid(): %u\n", tid);
	return _tls_get(tid);
}

void tls_free() {
	pid_t tid = gettid();
	trace("gettid(): %u\n", tid);
	_tls_free(tid);
}
