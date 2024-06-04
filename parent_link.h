#pragma once

#include "parent.h"

#include <fcntl.h>
#include <unistd.h>

def_parent(int, unlink, const char *pathname)
def_parent(int, unlinkat, int dirfd, const char *pathname, int flags)

def_parent(int, link, const char *oldpath, const char *newpath)
def_parent(int, linkat, int olddirfd, const char *oldpath,
						int newdirfd, const char *newpath, int flags)

def_parent(int, symlink, const char *target, const char *linkpath)
def_parent(int, symlinkat, const char *target, int newdirfd, const char *linkpath)

def_parent(int, rename, const char *oldpath, const char *newpath)
def_parent(int, renameat, int olddirfd, const char *oldpath,
		   int newdirfd, const char *newpath)
def_parent(int, renameat2, int olddirfd, const char *oldpath,
		   int newdirfd, const char *newpath, unsigned int flags)

#ifdef _INTERCEPT_GLIBC
static void parent_link_load() {
	load_unlink_func();
	load_unlinkat_func();
	load_link_func();
	load_linkat_func();
	load_symlink_func();
	load_symlinkat_func();
	load_rename_func();
	load_renameat_func();
	load_renameat2_func();
}
#endif
