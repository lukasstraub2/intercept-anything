
#include "fastpath_preload.h"

#include <time.h>
#include <sched.h>
#include <syscall.h>
#include <errno.h>

// TODO: 32bit time compat
// Note there are also __NR_clock_gettime AND __NR_clock_gettime64
#undef clock_gettime
#undef clock_gettime64
int clock_gettime(clockid_t clockid, struct timespec* spec) {
    int ret;

    maybe_init();

    ret = entry(__NR_clock_gettime, clockid, (unsigned long)spec, 0, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef sched_getcpu
int sched_getcpu() {
    int ret;
    int cpu;

    maybe_init();

    ret = entry(__NR_getcpu, (unsigned long)&cpu, 0, 0, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return cpu;
}

#ifdef SYS_riscv_flush_icache
int riscv_flush_icache() {
    int ret;

    maybe_init();

    ret = entry(__NR_riscv_flush_icache, 0, 0, 0, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}
#endif