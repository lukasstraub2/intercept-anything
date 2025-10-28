#pragma once

#include "base_types.h"
#include "syscalls_a.h"
#include "syscalls_b.h"
#include "syscalls_c.h"
#include "syscalls_exec.h"

#include <sys/types.h>

struct Context {
    Tls* tls;
    void* ucontext;
    int signalmanager_masked;
    int trampo_armed;
};

// clang-format off
struct CallHandler {
    int (*open)(Context *ctx, const This *data, const CallOpen *call);
    const This *open_next;
    int (*stat)(Context *ctx, const This *data, const CallStat *call);
    const This *stat_next;
    ssize_t (*readlink)(Context *ctx, const This *data, const CallReadlink *call);
    const This *readlink_next;
    int (*access)(Context *ctx, const This *data, const CallAccess *call);
    const This *access_next;
    int (*exec)(Context *ctx, const This *data, const CallExec *call);
    const This *exec_next;
    int (*link)(Context *ctx, const This *data, const CallLink *call);
    const This *link_next;
    int (*symlink)(Context *ctx, const This *data, const CallLink *call);
    const This *symlink_next;
    int (*unlink)(Context *ctx, const This *data, const CallUnlink *call);
    const This *unlink_next;
    ssize_t (*xattr)(Context *ctx, const This *data, const CallXattr *call);
    const This *xattr_next;
    int (*rename)(Context *ctx, const This *data, const CallRename *call);
    const This *rename_next;
    int (*chdir)(Context *ctx, const This *data, const CallChdir *call);
    const This *chdir_next;
    int (*chmod)(Context *ctx, const This *data, const CallChmod *call);
    const This *chmod_next;
    int (*truncate)(Context *ctx, const This *data, const CallTruncate *call);
    const This *truncate_next;
    int (*mkdir)(Context *ctx, const This *data, const CallMkdir *call);
    const This *mkdir_next;
    ssize_t (*getdents)(Context *ctx, const This *data, const CallGetdents *call);
    const This *getdents_next;
    int (*mknod)(Context *ctx, const This *data, const CallMknod *call);
    const This *mknod_next;
    int (*accept)(Context *ctx, const This *data, const CallAccept *call);
    const This *accept_next;
    int (*connect)(Context *ctx, const This *data, const CallConnect *call);
    const This *connect_next;
    int (*fanotify_mark)(Context *ctx, const This *data, const CallFanotifyMark *call);
    const This *fanotify_mark_next;
    int (*inotify_add_watch)(Context *ctx, const This *data, const CallInotifyAddWatch *call);
    const This *inotify_add_watch_next;
    int (*rlimit)(Context *ctx, const This *data, const CallRlimit *call);
    const This *rlimit_next;
    int (*sigprocmask)(Context *ctx, const This *data, const CallSigprocmask *call);
    const This *sigprocmask_next;
    int (*sigaction)(Context *ctx, const This *data, const CallSigaction *call);
    const This *sigaction_next;
    long (*ptrace)(Context *ctx, const This *data, const CallPtrace *call);
    const This *ptrace_next;
    int (*kill)(Context *ctx, const This *data, const CallKill *call);
    const This *kill_next;
    int (*close)(Context *ctx, const This *data, const CallClose *call);
    const This *close_next;
    unsigned long (*misc)(Context *ctx, const This *data, const CallMisc *call);
    const This *misc_next;
    unsigned long (*mmap)(Context *ctx, const This *data, const CallMmap *call);
    const This *mmap_next;
    int (*clone)(Context *ctx, const This *data, const CallClone *call);
    const This *clone_next;
};
// clang-format on

typedef struct CallHandler CallHandler;

extern const char* self_exe;
extern __thread Tls _tls;
extern const CallHandler* _next;

void intercept_init(int recursing, const char* exe);
const CallHandler* main_init(const CallHandler* bottom, int recursing);
void thread_exit(Tls* tls);
void thread_exit_exec(Tls* tls);

int pc_in_our_code(void* ucontext);
