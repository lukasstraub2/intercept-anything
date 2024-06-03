
#include "intercept.h"
#include "signalshim.h"
#include "noxattrs.h"
#include "rootlink.h"
#include "rootshim.h"

const CallHandler *main_init(const CallHandler *bottom) {
	const CallHandler *signalshim = signalshim_init(bottom);
	const CallHandler *noxattrs = noxattrs_init(signalshim);
	const CallHandler *rootlink = rootlink_init(noxattrs);
	const CallHandler *rootshim = rootshim_init(rootlink);
	return rootshim;
}
