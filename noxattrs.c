/***
  l2s. Copied from PluseAudio's padsp.c

  This file is part of PulseAudio.

  Copyright 2006 Lennart Poettering
  Copyright 2006-2007 Pierre Ossman <ossman@cendio.se> for Cendio AB

  PulseAudio is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published
  by the Free Software Foundation; either version 2.1 of the License,
  or (at your option) any later version.

  PulseAudio is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with PulseAudio; if not, see <http://www.gnu.org/licenses/>.
***/

#define _GNU_SOURCE
#define BUF_SIZE (64*1024)

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

#include "config.h"

#include <pthread.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <spawn.h>
#include <stdint.h>
#include <limits.h>
#include <sys/xattr.h>

ssize_t listxattr(const char *path, char *list, size_t size) {
    errno = ENOTSUP;
    return -1;
}

ssize_t llistxattr(const char *path, char *list, size_t size) {
    errno = ENOTSUP;
    return -1;
}

ssize_t flistxattr(int fd, char *list, size_t size) {
    errno = ENOTSUP;
    return -1;
}

int setxattr(const char *path, const char *name,
             const void *value, size_t size, int flags) {
    errno = ENOTSUP;
    return -1;
}

int lsetxattr(const char *path, const char *name,
              const void *value, size_t size, int flags) {
    errno = ENOTSUP;
    return -1;
}

int fsetxattr(int fd, const char *name,
              const void *value, size_t size, int flags) {
    errno = ENOTSUP;
    return -1;
}

ssize_t getxattr(const char *path, const char *name,
                 void *value, size_t size) {
    errno = ENOTSUP;
    return -1;
}

ssize_t lgetxattr(const char *path, const char *name,
                  void *value, size_t size) {
    errno = ENOTSUP;
    return -1;
}

ssize_t fgetxattr(int fd, const char *name,
                  void *value, size_t size) {
    errno = ENOTSUP;
    return -1;
}
