
#include "emulate_swap.h"
#include "intercept.h"
#include "signalmanager.h"
#include "util.h"
#include "mysys.h"
#include "callhandler.h"

#include <sys/mman.h>

class EmulateSwap : public CallHandler {
    public:
    EmulateSwap(CallHandler* next) : CallHandler(next) {}
    void next(Context* ctx, const CallMmap* call);
};

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

void EmulateSwap::next(Context* ctx, const CallMmap* call) {
    unsigned long ret;
    unsigned long* _ret = call->ret;

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

    *_ret = ret;
}

CallHandler* emulate_swap_init(CallHandler* const next) {
    return new EmulateSwap(next);
}
