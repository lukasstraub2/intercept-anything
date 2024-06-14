#pragma once

#include "parent.h"

#include <stdio.h>

def_parent(int, close, int)
def_parent(int, fclose, FILE*)

#ifdef _INTERCEPT_GLIBC
static void parent_close_load() {
	load_close_func();
	load_fclose_func();
}
#endif
