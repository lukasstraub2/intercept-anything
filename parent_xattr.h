#pragma once

#include "parent.h"

#include <string.h>
#include <sys/xattr.h>

def_parent(ssize_t, listxattr, const char *path, char *list, size_t size);
def_parent(ssize_t, llistxattr, const char *path, char *list, size_t size);
def_parent(ssize_t, flistxattr, int fd, char *list, size_t size);

def_parent(int, setxattr, const char *path, const char *name,
		   const void *value, size_t size, int flags);
def_parent(int, lsetxattr, const char *path, const char *name,
		   const void *value, size_t size, int flags);
def_parent(int, fsetxattr, int fd, const char *name,
		   const void *value, size_t size, int flags);

def_parent(ssize_t, getxattr, const char *path, const char *name,
		   void *value, size_t size);
def_parent(ssize_t, lgetxattr, const char *path, const char *name,
		   void *value, size_t size);
def_parent(ssize_t, fgetxattr, int fd, const char *name,
		   void *value, size_t size);

static void parent_xattr_load() {
	load_listxattr_func();
	load_llistxattr_func();
	load_flistxattr_func();
	load_setxattr_func();
	load_lsetxattr_func();
	load_fsetxattr_func();
	load_getxattr_func();
	load_lgetxattr_func();
	load_fgetxattr_func();
}
