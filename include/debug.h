#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

static void debug(const char *format, ...) __attribute__((format (printf, 1, 2)));

__attribute__((unused))
static void debug(const char *format, ...) {
    va_list ap;
	const char *dlevel_s;

    dlevel_s = getenv(DEBUG_ENV);
    if (!dlevel_s)
        return;

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

static void trace(const char *format, ...) __attribute__((format (printf, 1, 2)));

__attribute__((unused))
static void trace(const char *format, ...) {
	va_list ap;
	const char *dlevel_s;
	int dlevel;

	dlevel_s = getenv(DEBUG_ENV);
	if (!dlevel_s)
		return;

	dlevel = atoi(dlevel_s);

	if (dlevel < 1)
		return;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

__attribute__((unused))
static void trace_plus(const char *format, ...) {
	va_list ap;
	const char *dlevel_s;
	int dlevel;

	dlevel_s = getenv(DEBUG_ENV);
	if (!dlevel_s)
		return;

	dlevel = atoi(dlevel_s);

	if (dlevel < 2)
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
	fputc('\n', stderr);

	exit(1);
}
