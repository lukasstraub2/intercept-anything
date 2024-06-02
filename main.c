
#include "intercept.h"
#include "noxattrs.h"
#include "rootlink.h"

const CallHandler *main_init(const CallHandler *bottom) {
	const CallHandler *noxattrs = noxattrs_init(bottom);
	const CallHandler *rootlink = rootlink_init(noxattrs);
	return rootlink;
}
