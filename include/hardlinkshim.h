#pragma once

#include "intercept.h"

CallHandler* hardlinkshim_init(CallHandler* next,
                               CallHandler* bottom,
                               int recursing,
                               const char* prefix,
                               const char* hardlink_prefix);
