
#include "intercept.h"
#include "noxattrs.h"
#include "rootlink.h"
#include "rootshim.h"

const CallHandler *main_init(const CallHandler *bottom) {
	const CallHandler *noxattrs = noxattrs_init(bottom);
	const CallHandler *rootlink = rootlink_init(noxattrs);
	const CallHandler *rootshim = rootshim_init(rootlink);
	return rootshim;
}
