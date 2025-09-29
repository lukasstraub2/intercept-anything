
#include "androidislinux.h"
#include "intercept.h"

struct This {
    CallHandler androidislin;
    const CallHandler* next;
};

static int androidislinux_accept(Context* ctx,
                                 const This* androidislin,
                                 const CallAccept* call) {
    CallAccept _call;
    callaccept_copy(&_call, call);

    if (!call->is4) {
        _call.is4 = 1;
        _call.flags = 0;
    }

    return androidislin->next->accept(ctx, androidislin->next->accept_next,
                                      &_call);
}

const CallHandler* androidislinux_init(const CallHandler* next) {
    static int initialized = 0;
    static This androidislin;

    if (initialized) {
        return nullptr;
    }
    initialized = 1;

    androidislin.next = next;
    androidislin.androidislin = *next;

    androidislin.androidislin.accept = androidislinux_accept;
    androidislin.androidislin.accept_next = &androidislin;

    return &androidislin.androidislin;
}
