
#include "common.h"

#include "androidislinux.h"
#include "intercept.h"

struct This {
	CallHandler this;
	const CallHandler *next;
};

static int androidislinux_accept(Context *ctx, const This *this,
								 const CallAccept *call) {
	CallAccept _call;
	callaccept_copy(&_call, call);

	if (!call->is4) {
		_call.is4 = 1;
		_call.flags = 0;
	}

	return this->next->accept(ctx, this->next->accept_next, &_call);
}

const CallHandler *androidislinux_init(const CallHandler *next) {
	static int initialized = 0;
	static This this;

	if (initialized) {
		return NULL;
	}
	initialized = 1;

	this.next = next;
	this.this = *next;

	this.this.accept = androidislinux_accept;
	this.this.accept_next = &this;

	return &this.this;
}
