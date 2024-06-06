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

#ifdef _INTERCEPT_GLIBC
static void parent_misc_load() {
	load_scandir_func();
	load_scandirat_func();
	load_chdir_func();
	load_fchdir_func();
}
#endif
