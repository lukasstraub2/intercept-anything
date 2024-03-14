#pragma once

#include <pthread.h>
#include <dlfcn.h>

static pthread_mutex_t func_mutex = PTHREAD_MUTEX_INITIALIZER;

/* dlsym() violates ISO C, so confide the breakage into this function to
 * avoid warnings. */
typedef void (*fnptr)(void);
static inline fnptr dlsym_fn(void *handle, const char *symbol) {
    return (fnptr) (long) dlsym(handle, symbol);
}

#define _quote(arg) #arg

#define def_parent(RET, FUNC, ...) \
typedef RET (*_ ## FUNC ## _t)(__VA_ARGS__); \
static _ ## FUNC ## _t _ ## FUNC = NULL; \
static void load_ ## FUNC ## _func() { \
    pthread_mutex_lock(&func_mutex); \
    if (!_ ## FUNC) \
        _ ## FUNC = (_ ## FUNC ## _t) dlsym_fn(RTLD_NEXT, _quote(FUNC)); \
    pthread_mutex_unlock(&func_mutex); \
}
