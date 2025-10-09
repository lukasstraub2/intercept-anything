
#include "rmap.h"
#include "mylock.h"
#include "util.h"

#include <stdlib.h>

static uint32_t rmap_size(RMap* rmap) {
    uint32_t size = __atomic_load_n(&rmap->size, __ATOMIC_RELAXED);

    return min(size, rmap->alloc);
}

static RMapEntry* _rmap_search_binary(RMap* rmap,
                                      const uint32_t id,
                                      int u,
                                      int o) {
    if (u > o) {
        return nullptr;
    }

    int index = (u + o) / 2;

    RMapEntry* current_entry = rmap->list + index;
    uint32_t current_id = __atomic_load_n(&current_entry->id, __ATOMIC_RELAXED);
    while (!current_id) {
        if (current_entry == rmap->list) {
            return nullptr;
        }
        current_entry--;
        current_id = __atomic_load_n(&current_entry->id, __ATOMIC_RELAXED);
    }

    if (current_id == id) {
        return current_entry;
    } else if (id < current_id) {
        return _rmap_search_binary(rmap, id, u, index - 1);
    } else {
        return _rmap_search_binary(rmap, id, index + 1, o);
    }
}

RMapEntry* rmap_search_binary(RMap* rmap, const uint32_t id) {
    int size = rmap_size(rmap);

    if (!size) {
        return nullptr;
    }

    return _rmap_search_binary(rmap, id, 0, size - 1);
}

static RMapEntry* rmap_search_linear(RMap* rmap, const uint32_t id) {
    int size = rmap_size(rmap);

    for (int i = 0; i < size; i++) {
        RMapEntry* current_entry = rmap->list + i;
        uint32_t current_tid =
            __atomic_load_n(&current_entry->id, __ATOMIC_RELAXED);

        if (current_tid == id) {
            return current_entry;
        }
    }

    return nullptr;
}

static RMapEntry* rmap_alloc_append(RMap* rmap, const uint32_t tid) {
    uint32_t size = rmap_size(rmap);
    Spinlock expected = 0;

    if (size >= rmap->alloc) {
        return nullptr;
    }

    while (1) {
        uint32_t idx = __atomic_fetch_add(&rmap->size, 1, __ATOMIC_ACQUIRE);
        RMapEntry* current_entry = rmap->list + idx;

        if (idx >= rmap->alloc) {
            return nullptr;
        }

        if (!__atomic_compare_exchange_n(&current_entry->id, &expected, tid, 0,
                                         __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            expected = 0;
            continue;
        }

        return current_entry;
    }
}

static RMapEntry* rmap_alloc_sparse(RMap* rmap, const uint32_t tid) {
    int size = rmap_size(rmap);
    Spinlock expected = 0;

    for (int i = 0; i < size; i++) {
        RMapEntry* current_entry = rmap->list + i;

        if (!__atomic_compare_exchange_n(&current_entry->id, &expected, tid, 0,
                                         __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            expected = 0;
            continue;
        }

        return current_entry;
    }

    return nullptr;
}

static RMapEntry* __rmap_get_noalloc(RMap* rmap, const uint32_t id) {
    RMapEntry* entry;

    if (!id) {
        abort();
    }

    entry = rmap_search_binary(rmap, id);
    if (entry) {
        return entry;
    }

    entry = rmap_search_linear(rmap, id);
    if (entry) {
        return entry;
    }

    return nullptr;
}

RMapEntry* rmap_get_noalloc(RMap* rmap, const uint32_t id) {
    RMapEntry* entry;

    entry = __rmap_get_noalloc(rmap, id);
    if (entry) {
        assert(entry->id > 0);
        return entry;
    }

    return nullptr;
}

RMapEntry* rmap_get(RMap* rmap, const uint32_t id) {
    RMapEntry* entry;

    entry = __rmap_get_noalloc(rmap, id);
    if (entry) {
        assert(entry->id > 0);
        return entry;
    }

    entry = rmap_alloc_append(rmap, id);
    if (entry) {
        assert(entry->id > 0);
        return entry;
    }

    entry = rmap_alloc_sparse(rmap, id);
    if (entry) {
        assert(entry->id > 0);
        return entry;
    }

    return nullptr;
}

void _rmap_free(RMap* rmap, RMapEntry* entry) {
    uint32_t size = __atomic_load_n(&rmap->size, __ATOMIC_ACQUIRE);
    uint32_t actual_size = min(size, (uint32_t)rmap->alloc);
    uint32_t idx = entry - rmap->list;
    Spinlock expected = size;
    void* data = entry->data;

    WRITE_ONCE(entry->data, nullptr);
    __asm volatile("" ::: "memory");
    free(data);

    if (idx == actual_size - 1) {
        __atomic_compare_exchange_n(&rmap->size, &expected, actual_size - 1, 0,
                                    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
    }

    __atomic_store_n(&entry->id, 0, __ATOMIC_RELEASE);
}

void rmap_free(RMap* rmap, const uint32_t id) {
    RMapEntry* entry;

    if (!id) {
        abort();
    }

    entry = __rmap_get_noalloc(rmap, id);
    if (entry) {
        assert(entry->id > 0);
        _rmap_free(rmap, entry);
    }
}

RMap* rmap_alloc(uint32_t alloc) {
    size_t size = sizeof(RMap) + alloc * sizeof(RMapEntry);

    RMap* rmap = (RMap*)malloc(size);
    rmap->alloc = alloc;

    return rmap;
}
