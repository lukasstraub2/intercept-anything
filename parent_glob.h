#pragma once

#include "parent.h"
#include <glob.h>

def_parent(int, glob, const char *restrict pattern, int flags,
                      int (*errfunc)(const char *epath, int eerrno),
                      glob_t *restrict pglob)
