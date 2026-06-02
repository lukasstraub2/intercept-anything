#pragma once

#include "mysys.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

static void trace(const char* format, ...)
    __attribute__((format(printf, 1, 2)));

__attribute__((unused)) static void trace(const char* format, ...) {
    va_list ap;
    const char* dlevel_s;
    int dlevel;

    dlevel_s = getenv("LOADER_TRACE");
    if (!dlevel_s)
        return;

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

static void exit_error(const char* format, ...)
    __attribute__((format(printf, 1, 2)));

__attribute__((noreturn, unused)) static void exit_error(const char* format,
                                                         ...) {
    va_list ap;

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
    fputc('\n', stderr);

    sys_exit_group(1);
}
