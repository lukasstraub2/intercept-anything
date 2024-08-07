
#include "common.h"

#include "intercept.h"
#include "noxattrs.h"
#include "hardlinkshim.h"
#include "rootlink.h"
#include "rootshim.h"
#include "androidislinux.h"

const CallHandler *main_init(const CallHandler *bottom, int recursing) {
	const CallHandler *noxattrs = noxattrs_init(bottom);
	const CallHandler *hardlinkshim = hardlinkshim_init(noxattrs, bottom, recursing);
	const CallHandler *rootlink = rootlink_init(hardlinkshim);
	const CallHandler *rootshim = rootshim_init(rootlink);
	const CallHandler *androidislinux = androidislinux_init(rootshim);
	return androidislinux;
}
