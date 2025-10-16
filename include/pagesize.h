#pragma once

#include <unistd.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE getpagesize()
#endif
