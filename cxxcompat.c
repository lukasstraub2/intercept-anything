#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void* __memcpy_chk(void* restrict dest,
                   const void* restrict src,
                   size_t n,
                   size_t destlen) {
    if (n > destlen) {
        abort();
    }

    return memcpy(dest, src, n);
}

void* __memmove_chk(void* restrict dest,
                    const void* restrict src,
                    size_t n,
                    size_t destlen) {
    if (n > destlen) {
        abort();
    }

    return memmove(dest, src, n);
}

void* __memset_chk(void* dest, int c, size_t n, size_t destlen) {
    if (n > destlen) {
        abort();
    }

    return memset(dest, c, n);
}

int __sprintf_chk(char* s, int flag, size_t slen, const char* format, ...) {
    int ret;
    va_list ap;

    if (slen == 0) {
        abort();
    }

    va_start(ap, format);
    ret = vsnprintf(s, slen, format, ap);
    va_end(ap);

    if (ret > slen) {
        abort();
    }

    return ret;
}

unsigned long __isoc23_strtoul(const char* restrict nptr,
                               char** restrict endptr,
                               int base) {
    return strtoul(nptr, endptr, base);
}

int __isoc23_sscanf(const char* restrict str,
                    const char* restrict format,
                    ...) {
    int ret;
    va_list ap;

    va_start(ap, format);
    ret = vsscanf(str, format, ap);
    va_end(ap);

    return ret;
}

int _dl_find_object(void* pc1, struct dl_find_object* result) {
    return -1;
}