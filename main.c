
#include "common.h"

#include "intercept.h"
#include "hardlinkshim.h"
#include "signalshim.h"
#include "noxattrs.h"
#include "rootlink.h"
#include "rootshim.h"

const CallHandler *main_init(const CallHandler *bottom) {
	const CallHandler *hardlinkshim = hardlinkshim_init(bottom, bottom);
	const CallHandler *signalshim = signalshim_init(hardlinkshim);
	const CallHandler *noxattrs = noxattrs_init(signalshim);
	const CallHandler *rootlink = rootlink_init(noxattrs);
	const CallHandler *rootshim = rootshim_init(rootlink);
	return rootshim;
}
