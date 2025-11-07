
#include "intercept.h"
#include "noxattrs.h"
#include "hardlinkshim.h"
#include "rootlink.h"
#include "rootshim.h"
#include "androidislinux.h"
#include "workarounds.h"
#include "util.h"

CallHandler* main_init(CallHandler* const bottom, int recursing) {
    tmpdir = PREFIX "/tmp";
    CallHandler* const noxattrs = noxattrs_init(bottom);
    CallHandler* const hardlinkshim =
        hardlinkshim_init(noxattrs, bottom, recursing);
    CallHandler* const rootlink = rootlink_init(hardlinkshim);
    CallHandler* const rootshim = rootshim_init(rootlink);
    CallHandler* const androidislinux = androidislinux_init(rootshim);
    CallHandler* const workarounds = workarounds_init(androidislinux);
    return workarounds;
}
