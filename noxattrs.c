
#define _GNU_SOURCE
#define BUF_SIZE (64*1024)

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

#include "config.h"

#include <errno.h>
#include <stdint.h>
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
