#pragma once

#include "intercept.h"

const CallHandler *hardlinkshim_init(const CallHandler *next,
									 const CallHandler *bottom);
