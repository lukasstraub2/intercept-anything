
#include "intercept.h"
#include "noxattrs.h"
#include "androidislinux.h"
#include "workarounds.h"

CallHandler* main_init(CallHandler* bottom, int recursing) {
    CallHandler* noxattrs = noxattrs_init(bottom);
    CallHandler* androidislinux = androidislinux_init(noxattrs);
    CallHandler* workarounds = workarounds_init(androidislinux);
    return workarounds;
}
