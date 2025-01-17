
#include "common.h"
#include "nolibc.h"

#include "tls.h"
#include "mylock.h"
#include "util.h"
#include "rmap.h"
#include "mysys.h"

_Static_assert(sizeof(Spinlock) >= sizeof(pid_t), "pid_t > Spinlock");

RMap *map = NULL;

RMapEntry *tls_search_binary(const uint32_t tid) {
	return rmap_search_binary(map, tid);
}

void tls_clean_dead() {
	for (int i = 0; i < (int)map->alloc; i++) {
		RMapEntry *entry = map->list + i;
		if (entry->id && is_tid_dead(entry->id)) {
			void *data = entry->data;
			if (data) {
				WRITE_ONCE(entry->data, NULL);
				__asm volatile ("" ::: "memory");
				free(data);
			}
			__asm volatile ("" ::: "memory");
			WRITE_ONCE(entry->id, 0);
			__asm volatile ("" ::: "memory");
		}
	}
}

// TODO: This is not reentrant at all
static Tls *tls_alloc(RMapEntry *entry, const uint32_t tid) {
	if (entry->data) {
		Tls *tls = entry->data;
		assert((uint32_t)tls->tid == tid);
		return entry->data;
	}

	tls_clean_dead();

	Tls *tls;
	pid_t pid = getpid();

	tls = malloc(sizeof(Tls));
	if (!tls) {
		abort();
	}

	// nolibc implementation ensures tls is zero-initialized
	WRITE_ONCE(tls->pid, pid);
	WRITE_ONCE(tls->tid, tid);
	__asm volatile ("" ::: "memory");
	WRITE_ONCE(entry->data, tls);

	return tls;
}

Tls *_tls_get_noalloc(const uint32_t tid) {
	RMapEntry *tls;

	tls = rmap_get_noalloc(map, tid);
	if (tls) {
		assert(tls->id > 0);
		return tls_alloc(tls, tid);
	}

	return NULL;
}

Tls *_tls_get(const uint32_t tid) {
	RMapEntry *tls;

	for (int i = 0; i < 2; i++) {
		tls = rmap_get(map, tid);
		if (tls) {
			assert(tls->id > 0);
			return tls_alloc(tls, tid);
		}

		tls_clean_dead();
	}

	abort();
	return NULL;
}

void _tls_free(const uint32_t tid) {
	tls_clean_dead();
	rmap_free(map, tid);
}

Tls *tls_get_noalloc() {
	pid_t tid = gettid();
	return _tls_get_noalloc(tid);
}

Tls *tls_get() {
	pid_t tid = gettid();
	return _tls_get(tid);
}

void tls_free() {
	pid_t tid = gettid();
	_tls_free(tid);
}

void tls_init() {
	map = rmap_alloc(TLS_LIST_ALLOC);
}
