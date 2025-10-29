#pragma once

#include "base_types.h"
#include "myseccomp.h"

struct CallExec {
    int at;
    int final;
    int dirfd;
    const char* path;
    char* const* argv;
    char* const* envp;
    int flags;
    int* ret;
};
typedef struct CallExec CallExec;

__attribute__((unused)) static void callexec_copy(CallExec* dst,
                                                  const CallExec* call) {
    dst->at = call->at;
    dst->final = call->final;

    if (call->at) {
        dst->dirfd = call->dirfd;
        dst->flags = call->flags;
    }

    dst->path = call->path;
    dst->argv = call->argv;
    dst->envp = call->envp;
    dst->ret = call->ret;
}

unsigned long handle_execve(Context* ctx, SysArgs* args);
unsigned long handle_execveat(Context* ctx, SysArgs* args);

void syscalls_exec_fill_bottom(CallHandler* bottom);