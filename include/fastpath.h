#pragma once

#include "callhandler.h"

CallHandler* fastpath_init(CallHandler* next, int vdso_fastpath);