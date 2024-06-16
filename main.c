
#include "intercept.h"
#include "rootlink.h"
#include "rootshim.h"

const CallHandler *main_init(const CallHandler *bottom) {
	//const CallHandler *hardlinkshim = hardlinkshim_init(bottom, bottom);
	//const CallHandler *noxattrs = noxattrs_init(hardlinkshim);
	const CallHandler *rootlink = rootlink_init(bottom);
	const CallHandler *rootshim = rootshim_init(rootlink);
	return rootshim;
}
