#pragma once

#include "intercept.h"

const CallHandler *workarounds_init(const CallHandler *next);
int workarounds_rethrow_signal(Tls *tls, int signum);
