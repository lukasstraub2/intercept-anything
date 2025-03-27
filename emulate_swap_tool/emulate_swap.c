
#include "common.h"

#include "nolibc.h"
#include "emulate_swap.h"
#include "intercept.h"
#include "signalmanager.h"
#include "util.h"
#include "mysys.h"

static int mktemp(unsigned long size) {
    char filename[] = "/var/tmp/.swap-XXXXXX";
    int ret;
    int fd = 0;

    ret = mkostemp(filename, 0, 0700);
    if (ret < 0) {
        return ret;
    }
    fd = ret;

    ret = sys_unlink(filename);
    if (ret < 0) {
        return ret;
    }

    ret = sys_ftruncate(fd, size);
    if (ret < 0) {
        return ret;
    }

    return fd;
}

static unsigned long emulate_swap_mmap(Context* ctx,
                                       const This* this,
                                       const CallMmap* call) {
    unsigned long ret;
    RetUL* _ret = call->ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);

    ret = (unsigned long)sys_mmap((void*)call->addr, call->len, call->prot,
                                  call->flags, call->fd, call->off);

    if (ret >= -4095UL && call->flags & MAP_ANONYMOUS) {
        int fd = mktemp(256UL * 1024 * 1024 * 1024);
        unsigned long flags = call->flags;

        flags &= ~MAP_ANONYMOUS;

        if (flags & MAP_PRIVATE) {
            flags &= ~MAP_PRIVATE;
            flags |= MAP_SHARED;
        }

        ret = (unsigned long)sys_mmap((void*)call->addr, call->len, call->prot,
                                      flags, fd, call->off);
        sys_close(fd);
    }

    _ret->ret = ret;
    return ret;
}

const CallHandler* emulate_swap_init(const CallHandler* next) {
    static int initialized = 0;
    static CallHandler this;

    if (initialized) {
        return NULL;
    }
    initialized = 1;

    this = *next;
    this.mmap = emulate_swap_mmap;
    this.mmap_next = (This*)&this;

    return &this;
}
