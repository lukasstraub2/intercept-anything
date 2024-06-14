#pragma once

#include "parent.h"

#include <string.h>
#include <glob.h>

def_parent(int, glob, const char *restrict pattern, int flags,
                      int (*errfunc)(const char *epath, int eerrno),
                      glob_t *restrict pglob)

#ifdef _INTERCEPT_GLIBC
static void parent_glob_load() {
	load_glob_func();
}
#endif
