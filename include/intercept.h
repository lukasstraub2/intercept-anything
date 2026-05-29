#pragma once

#include "base_types.h"
#include "callhandler.h"

#include <sys/types.h>

struct Context {
    Tls* tls;
    sigset_t* saved_mask;
    void* ucontext;
    int trampo_armed;
};

extern const char* self_exe;
extern __thread Tls _tls;
extern CallHandler* intercept_entrypoint;

void intercept_init(int recursing, const char* exe);
CallHandler* main_init(CallHandler* const bottom, int recursing);
void thread_exit(Tls* tls);
void thread_exit_exec(Tls* tls);

int pc_in_our_code(void* ucontext);

unsigned long fastpath_entry(unsigned long num,
                             unsigned long arg1,
                             unsigned long arg2,
                             unsigned long arg3,
                             unsigned long arg4,
                             unsigned long arg5,
                             unsigned long arg6);