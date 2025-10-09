#pragma once

#include "base_types.h"
#include "mylock.h"

struct RMapEntry {
    Spinlock id;
    void* data;
};

struct RMap {
    Spinlock size;
    uint32_t alloc;
    RMapEntry list[];
};

RMapEntry* rmap_search_binary(RMap* rmap, const uint32_t id);
RMapEntry* rmap_get_noalloc(RMap* rmap, const uint32_t id);
RMapEntry* rmap_get(RMap* rmap, const uint32_t id);
void _rmap_free(RMap* rmap, RMapEntry* entry);
void rmap_free(RMap* rmap, const uint32_t id);

RMap* rmap_alloc(uint32_t alloc);
