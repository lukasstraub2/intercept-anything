#pragma once

#define PRELOAD_ENTRY_FILE "/intercept-anything/preload_entry.bin"

typedef unsigned long (*fastpath_entry_t)(unsigned long num,
                                          unsigned long arg1,
                                          unsigned long arg2,
                                          unsigned long arg3,
                                          unsigned long arg4,
                                          unsigned long arg5,
                                          unsigned long arg6);