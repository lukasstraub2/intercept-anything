
#include "noxattrs.h"
#include "intercept.h"

static ssize_t noxattrs_xattr(Context* ctx,
                              const This* noxattrs,
                              const CallXattr* call) {
    call->ret->ret = -EOPNOTSUPP;
    return -EOPNOTSUPP;
}

const CallHandler* noxattrs_init(const CallHandler* next) {
    static int initialized = 0;
    static CallHandler noxattrs;

    if (initialized) {
        return nullptr;
    }
    initialized = 1;

    noxattrs = *next;
    noxattrs.xattr = noxattrs_xattr;
    noxattrs.xattr_next = (This*)&noxattrs;

    return &noxattrs;
}
