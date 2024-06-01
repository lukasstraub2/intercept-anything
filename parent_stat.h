#pragma once

#include "parent.h"

#include <string.h>
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

def_parent(char *, realpath, const char *restrict path,
                              char *restrict resolved_path)

def_parent(int, access, const char *, int)
def_parent(int, faccessat, int dirfd, const char *pathname, int mode, int flags)
#ifdef _GNU_SOURCE
def_parent(int, euidaccess, const char *pathname, int mode)
def_parent(int, eaccess, const char *pathname, int mode)
#endif

static void parent_stat_load() {
	load_stat_func();
	load_stat64_func();
	load___xstat_func();
	load___xstat64_func();
	load_statx_func();
	load_lstat_func();
	load_lstat64_func();
	load_fstatat_func();
	load_fstatat64_func();
	load_readlink_func();
	load_readlinkat_func();
	load_realpath_func();
	load_access_func();
	load_faccessat_func();
	load_euidaccess_func();
	load_eaccess_func();
}
