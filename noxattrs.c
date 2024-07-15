
#include "common.h"

#include "noxattrs.h"
#include "intercept.h"

static ssize_t noxattrs_xattr(Context *ctx, const This *this,
							  const CallXattr *call) {
	call->ret->ret = -EOPNOTSUPP;
	return -EOPNOTSUPP;
}

const CallHandler *noxattrs_init(const CallHandler *next) {
	static int initialized = 0;
	static CallHandler this;

	if (initialized) {
		return NULL;
	}
	initialized = 1;

	this = *next;
	this.xattr = noxattrs_xattr;
	this.xattr_next = (This *) &this;

	return &this;
}
