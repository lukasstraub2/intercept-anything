
#include "common.h"
#include "nolibc.h"

#include "rmap.h"
#include "mylock.h"
#include "util.h"

static uint32_t rmap_size(RMap* this) {
    uint32_t size = __atomic_load_n(&this->size, __ATOMIC_RELAXED);

    return min(size, this->alloc);
}

static RMapEntry* _rmap_search_binary(RMap* this,
                                      const uint32_t id,
                                      int u,
                                      int o) {
    if (u > o) {
        return NULL;
    }

    int index = (u + o) / 2;

    RMapEntry* current_entry = this->list + index;
    uint32_t current_id = __atomic_load_n(&current_entry->id, __ATOMIC_RELAXED);
    while (!current_id) {
        if (current_entry == this->list) {
            return NULL;
        }
        current_entry--;
        current_id = __atomic_load_n(&current_entry->id, __ATOMIC_RELAXED);
    }

    if (current_id == id) {
        return current_entry;
    } else if (id < current_id) {
        return _rmap_search_binary(this, id, u, index - 1);
    } else {
        return _rmap_search_binary(this, id, index + 1, o);
    }
}

RMapEntry* rmap_search_binary(RMap* this, const uint32_t id) {
    int size = rmap_size(this);

    if (!size) {
        return NULL;
    }

    return _rmap_search_binary(this, id, 0, size - 1);
}

static RMapEntry* rmap_search_linear(RMap* this, const uint32_t id) {
    int size = rmap_size(this);

    for (int i = 0; i < size; i++) {
        RMapEntry* current_entry = this->list + i;
        uint32_t current_tid =
            __atomic_load_n(&current_entry->id, __ATOMIC_RELAXED);

        if (current_tid == id) {
            return current_entry;
        }
    }

    return NULL;
}

static RMapEntry* rmap_alloc_append(RMap* this, const uint32_t tid) {
    uint32_t size = rmap_size(this);
    Spinlock expected = 0;

    if (size >= this->alloc) {
        return NULL;
    }

    while (1) {
        uint32_t idx = __atomic_fetch_add(&this->size, 1, __ATOMIC_ACQUIRE);
        RMapEntry* current_entry = this->list + idx;

        if (idx >= this->alloc) {
            return NULL;
        }

        if (!__atomic_compare_exchange_n(&current_entry->id, &expected, tid, 0,
                                         __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            expected = 0;
            continue;
        }

        return current_entry;
    }
}

static RMapEntry* rmap_alloc_sparse(RMap* this, const uint32_t tid) {
    int size = rmap_size(this);
    Spinlock expected = 0;

    for (int i = 0; i < size; i++) {
        RMapEntry* current_entry = this->list + i;

        if (!__atomic_compare_exchange_n(&current_entry->id, &expected, tid, 0,
                                         __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            expected = 0;
            continue;
        }

        return current_entry;
    }

    return NULL;
}

static RMapEntry* __rmap_get_noalloc(RMap* this, const uint32_t id) {
    RMapEntry* entry;

    if (!id) {
        abort();
    }

    entry = rmap_search_binary(this, id);
    if (entry) {
        return entry;
    }

    entry = rmap_search_linear(this, id);
    if (entry) {
        return entry;
    }

    return NULL;
}

RMapEntry* rmap_get_noalloc(RMap* this, const uint32_t id) {
    RMapEntry* entry;

    entry = __rmap_get_noalloc(this, id);
    if (entry) {
        assert(entry->id > 0);
        return entry;
    }

    return NULL;
}

RMapEntry* rmap_get(RMap* this, const uint32_t id) {
    RMapEntry* entry;

    entry = __rmap_get_noalloc(this, id);
    if (entry) {
        assert(entry->id > 0);
        return entry;
    }

    entry = rmap_alloc_append(this, id);
    if (entry) {
        assert(entry->id > 0);
        return entry;
    }

    entry = rmap_alloc_sparse(this, id);
    if (entry) {
        assert(entry->id > 0);
        return entry;
    }

    return NULL;
}

void _rmap_free(RMap* this, RMapEntry* entry) {
    uint32_t size = __atomic_load_n(&this->size, __ATOMIC_ACQUIRE);
    uint32_t actual_size = min(size, (uint32_t)this->alloc);
    uint32_t idx = entry - this->list;
    Spinlock expected = size;
    void* data = entry->data;

    WRITE_ONCE(entry->data, NULL);
    __asm volatile("" ::: "memory");
    free(data);

    if (idx == actual_size - 1) {
        __atomic_compare_exchange_n(&this->size, &expected, actual_size - 1, 0,
                                    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
    }

    __atomic_store_n(&entry->id, 0, __ATOMIC_RELEASE);
}

void rmap_free(RMap* this, const uint32_t id) {
    RMapEntry* entry;

    if (!id) {
        abort();
    }

    entry = __rmap_get_noalloc(this, id);
    if (entry) {
        assert(entry->id > 0);
        _rmap_free(this, entry);
    }
}

RMap* rmap_alloc(uint32_t alloc) {
    size_t size = sizeof(RMap) + alloc * sizeof(RMapEntry);

    RMap* this = malloc(size);
    this->alloc = alloc;

    return this;
}
