#pragma once

#include "base_types.h"
#include "types.h"
#include "mylock.h"

struct RMapEntry {
	Spinlock id;
	void *data;
};

RMapEntry *rmap_search_binary(RMap *this, const uint32_t id);
RMapEntry *rmap_get_noalloc(RMap *this, const uint32_t id);
RMapEntry *rmap_get(RMap *this, const uint32_t id);
void _rmap_free(RMap *this, RMapEntry *entry);
void rmap_free(RMap *this, const uint32_t id);

RMap *rmap_alloc(uint32_t alloc);
