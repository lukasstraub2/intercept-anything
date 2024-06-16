
#include "noxattrs.h"
#include "intercept.h"

#include <errno.h>

static ssize_t noxattrs_xattr(Context *ctx, const This *this,
							  const CallXattr *call) {
	call->ret->_errno = EOPNOTSUPP;
	call->ret->ret = -1;
	return -1;
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
