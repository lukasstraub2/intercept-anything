
#include "mynolibc.h"

#define SCRATCH_SIZE (64 * 1024)
static_assert(SCRATCH_SIZE >= PATH_MAX, "SCRATCH_SIZE");

#define PREFIX "/data/data/com.termux/files/home/gentoo"
