#pragma once

#include "parent.h"

#include <fcntl.h>
#include <dirent.h>

def_parent(int, scandir, const char *restrict dirp,
		   struct dirent ***restrict namelist,
		   int (*filter)(const struct dirent *),
		   int (*compar)(const struct dirent **,
						 const struct dirent **))

def_parent(int, scandirat, int dirfd, const char *restrict dirp,
		   struct dirent ***restrict namelist,
		   int (*filter)(const struct dirent *),
		   int (*compar)(const struct dirent **,
						 const struct dirent **));

def_parent(int, chdir, const char *path)
def_parent(int, fchdir, int fd)

def_parent(char *, mktemp, char *template);
def_parent(int, mkstemp, char *template)
def_parent(int, mkostemp, char *template, int flags)
def_parent(int, mkstemps, char *template, int suffixlen)
def_parent(int, mkostemps, char *template, int suffixlen, int flags)

#ifdef _INTERCEPT_GLIBC
static void parent_misc_load() {
	load_scandir_func();
	load_scandirat_func();
	load_chdir_func();
	load_fchdir_func();
}
#endif
