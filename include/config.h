
#include "types.h"

// I wanted 64k, but glibc vfork only allocates 32k stack
// TODO: Allocate on heap
#define SCRATCH_SIZE (12*1024)
_Static_assert(SCRATCH_SIZE >= PATH_MAX, "SCRATCH_SIZE");

#define PREFIX "/data/data/com.termux/files/home/gentoo"
