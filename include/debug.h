#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

static void debug(int level, const char *format, ...) __attribute__((format (printf, 2, 3)));

#define DEBUG_LEVEL_ALWAYS                0
#define DEBUG_LEVEL_NORMAL                1
#define DEBUG_LEVEL_VERBOSE               2

__attribute__((unused))
static void debug(int level, const char *format, ...) {
    va_list ap;
    const char *dlevel_s;
    int dlevel;

    dlevel_s = getenv(DEBUG_ENV);
    if (!dlevel_s)
        return;

    dlevel = atoi(dlevel_s);

    if (dlevel < level)
        return;

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

static void exit_error(const char *format, ...) __attribute__((format (printf, 1, 2)));

__attribute__((unused))
static void exit_error(const char *format, ...) {
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);

	exit(1);
}
