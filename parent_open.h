#pragma once

#include "parent.h"

#include <dirent.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>

/* make sure gcc doesn't redefine open and friends as macros */
#undef open
#undef open64
#undef openat
#undef openat64

def_parent(int, open, const char *, int, mode_t)
def_parent(int, __open_2, const char *, int)
#ifdef HAVE_OPEN64
def_parent(int, open64, const char *, int, mode_t)
def_parent(int, __open64_2, const char *, int)
#endif

#ifdef HAVE_OPENAT
def_parent(int, openat, int, const char *, int, mode_t)
def_parent(int, __openat_2, int, const char *, int)
#ifdef HAVE_OPEN64
def_parent(int, openat64, int, const char *, int, mode_t)
def_parent(int, __openat64_2, int, const char *, int)
#endif
#endif

def_parent(FILE*, fopen, const char *path, const char *mode)
#ifdef HAVE_OPEN64
def_parent(FILE*, fopen64, const char *path, const char *mode)
#endif

def_parent(DIR *, opendir, const char *)

static void parent_open_load() {
	load_open_func();
	load___open_2_func();
	load_open64_func();
	load___open64_2_func();
	load_openat_func();
	load___openat_2_func();
	load_openat64_func();
	load___openat64_2_func();
	load_fopen_func();
	load_fopen64_func();
	load_opendir_func();
}
