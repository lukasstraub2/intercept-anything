
#include "intercept.h"
#include "rootlink.h"

const CallHandler *main_init(const CallHandler *bottom) {
	//return bottom;
	return rootlink_init(bottom);
}
