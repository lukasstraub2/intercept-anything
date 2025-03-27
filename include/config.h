
#include "types.h"

#define SCRATCH_SIZE (64 * 1024)
_Static_assert(SCRATCH_SIZE >= PATH_MAX, "SCRATCH_SIZE");

#define PREFIX "/data/data/com.termux/files/home/gentoo"
