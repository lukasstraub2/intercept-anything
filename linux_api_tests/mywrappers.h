#pragma once

#include <sys/resource.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

static __attribute__((unused))
void mygetrlimit(int resource, struct rlimit *rlim){
        int ret;

        ret = getrlimit(resource, rlim);
        if (ret < 0) {
                fprintf(stderr, "getrlimit(): %s\n", strerror(errno));
                exit(1);
        }
}

static __attribute__((unused))
void mysetrlimit(int resource, const struct rlimit *rlim){
        int ret;

        ret = setrlimit(resource, rlim);
        if (ret < 0) {
                fprintf(stderr, "setrlimit(): %s\n", strerror(errno));
                exit(1);
        }
}

static __attribute__((unused))
int myopen(const char *path, int flags, mode_t mode){
        int ret;

        ret = open(path, flags, mode);
        if (ret < 0) {
                fprintf(stderr, "open(): %s\n", strerror(errno));
                exit(1);
        }

        return ret;
}

static __attribute__((unused))
void *mymmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset){
        void *ret;

        ret = mmap(addr, length, prot, flags, fd, offset);
        if (ret == MAP_FAILED){
                fprintf(stderr, "mmap(): %s\n", strerror(errno));
                exit(1);
        }

        return ret;
}

static __attribute__((unused))
ssize_t myread(int fd, void *buf, size_t count){
        ssize_t ret;

        ret = read(fd, buf, count);
        if (ret < 0) {
                fprintf(stderr, "read(): %s\n", strerror(errno));
                exit(1);
        }

        return ret;
}

static __attribute__((unused))
ssize_t mywrite(int fd, const void *buf, size_t count){
        ssize_t ret;

        ret = write(fd, buf, count);
        if (ret < 0) {
                fprintf(stderr, "write(): %s\n", strerror(errno));
                exit(1);
        }
        if ((size_t)ret != count) {
                fprintf(stderr, "write(): Short write\n");
                exit(1);
        }

        return ret;
}

static __attribute__((unused))
off_t mylseek(int fd, off_t offset, int whence){
        off_t ret;

        ret = lseek(fd, offset, whence);
        if (ret < 0) {
                fprintf(stderr, "lseek(): %s\n", strerror(errno));
                exit(1);
        }

        return ret;
}
