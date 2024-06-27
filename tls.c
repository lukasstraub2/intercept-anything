
#include "nolibc.h"
#include "tls.h"
#include "mylock.h"
#include "util.h"

struct TlsList {
	Spinlock tid;
	Tls *data;
};
_Static_assert(sizeof(Spinlock) >= sizeof(pid_t), "pid_t > Spinlock");

#define TLS_ALLOC 4096
static Spinlock thread_data_size = 0;
static TlsList thread_data[TLS_ALLOC] = {0};

static int tls_size() {
	uint32_t size = __atomic_load_n(&thread_data_size, __ATOMIC_RELAXED);

	return min(size, (uint32_t)TLS_ALLOC);
}

static TlsList *_tls_search_binary(uint32_t tid, int u, int o) {
	if (u > o) {
		return NULL;
	}

	int index = (u + o)/2;

	TlsList *current_entry = thread_data + index;
	uint32_t current_tid = __atomic_load_n(&current_entry->tid, __ATOMIC_RELAXED);
	while (!current_tid) {
		if (!index) {
			return NULL;
		}
		o--;
		index--;
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

TlsList *tls_search_binary(uint32_t tid) {
	int size = tls_size();

	if (!size) {
		return NULL;
	}

	return _tls_search_binary(tid, 0, size -1);
}

static TlsList *tls_search_linear(uint32_t tid) {
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

static TlsList *tls_alloc(TlsList *entry) {
	entry->data = malloc(sizeof(Tls));
	if (!entry->data) {
		abort();
	}

	return entry;
}

static TlsList *tls_alloc_append(uint32_t tid) {
	int size = tls_size();
	Spinlock expected = 0;

	if (size >= TLS_ALLOC) {
		return NULL;
	}

	while (1) {
		uint32_t idx = __atomic_fetch_add(&thread_data_size, 1, __ATOMIC_ACQUIRE);
		TlsList *current_entry = thread_data + idx;

		if (idx >= TLS_ALLOC) {
			return NULL;
		}

		if (!__atomic_compare_exchange_n(&current_entry->tid, &expected, tid, 0,
										 __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
			expected = 0;
			continue;
		}

		return tls_alloc(current_entry);
	}
}

static TlsList *tls_alloc_sparse(uint32_t tid) {
	int size = tls_size();
	Spinlock expected = 0;

	for (int i = 0; i < size; i++) {
		TlsList *current_entry = thread_data + i;

		if (!__atomic_compare_exchange_n(&current_entry->tid, &expected, tid, 0,
										 __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
			expected = 0;
			continue;
		}

		return tls_alloc(current_entry);
	}

	return NULL;
}

Tls *_tls_get(uint32_t tid) {
	TlsList *tls;

	if (!tid) {
		abort();
	}

	tls = tls_search_binary(tid);
	if (tls) {
		return tls->data;
	}

	tls = tls_search_linear(tid);
	if (tls) {
		return tls->data;
	}

	tls = tls_alloc_append(tid);
	if (tls) {
		return tls->data;
	}

	tls = tls_alloc_sparse(tid);
	if (tls) {
		return tls->data;
	}

	abort();
	return NULL;
}

void _tls_free(uint32_t tid) {
	TlsList *tls;

	if (!tid) {
		abort();
	}

	tls = tls_search_binary(tid);
	if (tls) {
		free(tls->data);
		tls->data = NULL;
		__atomic_store_n(&tls->tid, 0, __ATOMIC_RELEASE);
	}

	tls = tls_search_linear(tid);
	if (tls) {
		free(tls->data);
		tls->data = NULL;
		__atomic_store_n(&tls->tid, 0, __ATOMIC_RELEASE);
	}
}

Tls *tls_get() {
	pid_t tid = gettid();
	return _tls_get(tid);
}

void tls_free() {
	pid_t tid = gettid();
	_tls_free(tid);
}
