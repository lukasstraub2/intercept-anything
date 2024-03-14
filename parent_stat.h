#pragma once

#include "parent.h"

#include <sys/stat.h>

def_parent(int, stat, const char *, struct stat *)
#ifdef _STAT_VER
def_parent(int, __xstat, int, const char *, struct stat *)
#endif
#ifdef HAVE_OPEN64
def_parent(int, stat64, const char *, struct stat64 *)
#ifdef _STAT_VER
def_parent(int, __xstat64, int, const char *, struct stat64 *)
#endif
#endif
#ifdef _GNU_SOURCE
def_parent(int, statx, int dirfd, const char *restrict pathname, int flags,
                       unsigned int mask, struct statx *restrict statxbuf)
#endif

def_parent(int, access, const char *, int)
