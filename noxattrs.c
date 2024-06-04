
#include "common.h"

#include "noxattrs.h"
#include "intercept.h"

#include <errno.h>

static ssize_t noxattrs_listxattr(Context *ctx, const This *this,
								  const CallListXattr *call) {
	call->ret->_errno = ENOTSUP;
	call->ret->ret = -1;
	return -1;
}

static int noxattrs_setxattr(Context *ctx, const This *this,
							 const CallSetXattr *call) {
	call->ret->_errno = ENOTSUP;
	call->ret->ret = -1;
	return -1;
}

static ssize_t noxattrs_getxattr(Context *ctx, const This *this,
								 const CallGetXattr *call) {
	call->ret->_errno = ENOTSUP;
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
	this.listxattr = noxattrs_listxattr;
	this.listxattr_next = (This *) &this;
	this.setxattr = noxattrs_setxattr;
	this.setxattr_next = (This *) &this;
	this.getxattr = noxattrs_getxattr;
	this.getxattr_next = (This *) &this;

	return &this;
}
