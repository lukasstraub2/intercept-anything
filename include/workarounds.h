#pragma once

#include "intercept.h"

CallHandler* workarounds_init(CallHandler* next);
int workarounds_rethrow_signal(Tls* tls, int signum);
