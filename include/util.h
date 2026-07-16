#pragma once

#include "stdint.h"
#include "tls.h"

#define max(a, b)               \
    ({                          \
        __typeof__(a) _a = (a); \
        __typeof__(b) _b = (b); \
        _a > _b ? _a : _b;      \
    })

#define min(a, b)               \
    ({                          \
        __typeof__(a) _a = (a); \
        __typeof__(b) _b = (b); \
        _a < _b ? _a : _b;      \
    })

#define assert(cond) \
    if (!(cond)) {   \
        abort();     \
    }

#define alloca __builtin_alloca

__attribute__((unused)) static const char* or_null(const char* str) {
    if (str) {
        return str;
    } else {
        return "nullptr";
    }
}

extern const char* tmpdir;

void randchar6(char* buf);
int mkostemp(char* templ, int flags, mode_t mode);

int is_tid_dead(pid_t tid);
int is_pid_dead(pid_t pid);

size_t concat(char* out, size_t out_len, const char* a, const char* b);
size_t concat3(char* out,
               size_t out_len,
               const char* a,
               const char* b,
               const char* c);
int strcmp_prefix(const char* a, const char* b);

ssize_t _getcwd(char scratch[SCRATCH_SIZE], char** out);
ssize_t _readlinkat(char scratch[SCRATCH_SIZE],
                    int dirfd,
                    const char* path,
                    char** out);
ssize_t concatat(char scratch[SCRATCH_SIZE],
                 int dirfd,
                 const char* path,
                 char** out);

int env_is_true(const char* env);
