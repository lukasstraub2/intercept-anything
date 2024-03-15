#pragma once

#include "parent.h"

#include <sys/stat.h>

def_parent(int, stat, const char *, struct stat *)
#ifdef HAVE_OPEN64
def_parent(int, stat64, const char *, struct stat64 *)
#endif

#ifdef _STAT_VER
def_parent(int, __xstat, int, const char *, struct stat *)
#ifdef HAVE_OPEN64
def_parent(int, __xstat64, int, const char *, struct stat64 *)
#endif
#endif

#ifdef _GNU_SOURCE
def_parent(int, statx, int dirfd, const char *restrict pathname, int flags,
                       unsigned int mask, struct statx *restrict statxbuf)
#endif

def_parent(int, lstat, const char *restrict pathname,
                       struct stat *restrict statbuf)
#ifdef HAVE_OPEN64
def_parent(int, lstat64, const char *restrict pathname,
                         struct stat64 *restrict statbuf)
#endif

def_parent(int, fstatat, int dirfd, const char *restrict pathname,
                         struct stat *restrict statbuf, int flags)
#ifdef HAVE_OPEN64
def_parent(int, fstatat64, int dirfd, const char *restrict pathname,
                           struct stat64 *restrict statbuf, int flags)
#endif

def_parent(ssize_t, readlink, const char *restrict pathname,
                              char *restrict buf, size_t bufsiz)
def_parent(ssize_t, readlinkat, int dirfd, const char *restrict pathname,
                                char *restrict buf, size_t bufsiz)

def_parent(int, access, const char *, int)
