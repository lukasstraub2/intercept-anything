
#include "intercept.h"
#include "noxattrs.h"
#include "androidislinux.h"
#include "workarounds.h"

const CallHandler* main_init(const CallHandler* bottom, int recursing) {
    const CallHandler* noxattrs = noxattrs_init(bottom);
    const CallHandler* androidislinux = androidislinux_init(noxattrs);
    const CallHandler* workarounds = workarounds_init(androidislinux);
    return workarounds;
}
