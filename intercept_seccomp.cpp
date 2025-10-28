#include "mysignal.h"
#include "myseccomp.h"
#include "mysys.h"
#include "intercept.h"
#include "loader.h"
#include "config.h"
#include "signalmanager.h"
#include "tls.h"
#include "util.h"
#include "pagesize.h"
#include "syscall_trampo.h"
#include "syscalls.h"

#define DEBUG_ENV "DEBUG_INTERCEPT"
#include "debug.h"

#include "linux/audit.h"
#include "linux/bpf.h"
#include "linux/filter.h"
#include "linux/seccomp.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

extern "C" {
int __main_prepare_threaded();
int __external_thread_register_maybe();
}

static int initialized = 0;

const CallHandler* _next = nullptr;

static char _self_exe[SCRATCH_SIZE];
const char* self_exe = _self_exe;

static void start_text_init();

__thread Tls _tls = {};
static void handler(int sig, siginfo_t* info, void* ucontext) {
    int reti = __external_thread_register_maybe();
    if (reti < 0) {
        abort();
    }

    __asm volatile("" ::: "memory");
    Tls* tls = &_tls;
    if (!tls->pid) {
        tls->pid = getpid();
        tls->tid = gettid();
    }

    Context ctx = {tls, ucontext, 0, 0};
    ssize_t ret;
    SysArgs args;

    (void)sig;

    if (info->si_errno) {
        exit_error("Invalid arch, terminating");
    }

    fill_sysargs(&args, ucontext);
    ret = handle_syscall(&ctx, &args);

    if (!ctx.trampo_armed) {
        set_return(ucontext, ret);
    }
}

int loader_open(const char* path, int flags, mode_t mode) {
    Tls* tls = &_tls;
    if (!initialized) {
        return sys_open(path, flags, mode);
    }

    if (!tls->pid) {
        tls->pid = getpid();
        tls->tid = gettid();
    }

    Context ctx = {tls, nullptr, 0};
    SysArgs args = {};
    args.arg1 = AT_FDCWD;
    args.arg2 = (long)path;
    args.arg3 = flags;
    args.arg4 = mode;
    return handle_openat(&ctx, &args);
}

static char* start_text;
extern char __etext;

static void start_text_init() {
    unsigned long addr = (unsigned long)&__etext;
    addr &= -PAGE_SIZE;  // round down

    while (1) {
        int ret = sys_access((char*)addr, F_OK);
        if (ret != -EFAULT) {
            addr -= PAGE_SIZE;
            continue;
        }

        break;
    }

    addr += PAGE_SIZE;
    start_text = (char*)addr;
}

int pc_in_our_code(void* ucontext) {
    char* pc = (char*)get_pc(ucontext);
    return pc >= start_text && pc < &__etext;
}

static int install_filter() {
    int ret;

    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
                 (__u32)(offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_CURRENT, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP | (1 & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
                 (__u32)(offsetof(struct seccomp_data, nr))),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_clone3, 69, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_clone, 68, 0),
#ifdef __NR_vfork
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_vfork, 67, 0),
#else
        BPF_JUMP(BPF_JMP + BPF_JA, 0, 0, 0),
#endif
#ifdef __NR_fork
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fork, 66, 0),
#else
        BPF_JUMP(BPF_JMP + BPF_JA, 0, 0, 0),
#endif
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_mmap, 65, 0),
#ifdef __NR_close_range
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_close_range, 64, 0),
#else
        BPF_JUMP(BPF_JMP + BPF_JA, 0, 0, 0),
#endif
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_close, 63, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_kill, 62, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_ptrace, 61, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getrlimit, 60, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_setrlimit, 59, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_prlimit64, 58, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fanotify_mark, 57, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_inotify_add_watch, 56, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_connect, 55, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_bind, 54, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_accept, 53, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_accept4, 52, 0),
#ifdef __NR_mknod
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_mknod, 51, 0),
#else
        BPF_JUMP(BPF_JMP + BPF_JA, 0, 0, 0),
#endif
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_mknodat, 50, 0),
#ifdef __NR_getdents
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getdents, 49, 0),
#else
        BPF_JUMP(BPF_JMP + BPF_JA, 0, 0, 0),
#endif
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getdents64, 48, 0),
#ifdef __NR_mkdir
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_mkdir, 47, 0),
#else
        BPF_JUMP(BPF_JMP + BPF_JA, 0, 0, 0),
#endif
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_mkdirat, 46, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_truncate, 45, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_ftruncate, 44, 0),
#ifdef __NR_chmod
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_chmod, 43, 0),
#else
        BPF_JUMP(BPF_JMP + BPF_JA, 0, 0, 0),
#endif
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fchmod, 42, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fchmodat, 41, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_exit, 40, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_exit_group, 39, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_chdir, 38, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fchdir, 37, 0),
#ifdef __NR_open
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_open, 36, 0),
#else
        BPF_JUMP(BPF_JMP + BPF_JA, 0, 0, 0),
#endif
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 35, 0),
#ifdef __NR_stat
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_stat, 34, 0),
#else
        BPF_JUMP(BPF_JMP + BPF_JA, 0, 0, 0),
#endif
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fstat, 33, 0),
#ifdef __NR_lstat
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_lstat, 32, 0),
#else
        BPF_JUMP(BPF_JMP + BPF_JA, 0, 0, 0),
#endif
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_newfstatat, 31, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_statx, 30, 0),
#ifdef __NR_readlink
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_readlink, 29, 0),
#else
        BPF_JUMP(BPF_JMP + BPF_JA, 0, 0, 0),
#endif
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_readlinkat, 28, 0),
#ifdef __NR_access
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_access, 27, 0),
#else
        BPF_JUMP(BPF_JMP + BPF_JA, 0, 0, 0),
#endif
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_faccessat, 26, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_execve, 25, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_execveat, 24, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rt_sigprocmask, 23, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rt_sigaction, 22, 0),
#ifdef __NR_link
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_link, 21, 0),
#else
        BPF_JUMP(BPF_JMP + BPF_JA, 0, 0, 0),
#endif
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_linkat, 20, 0),
#ifdef __NR_symlink
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_symlink, 19, 0),
#else
        BPF_JUMP(BPF_JMP + BPF_JA, 0, 0, 0),
#endif
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_symlinkat, 18, 0),
#ifdef __NR_unlink
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_unlink, 17, 0),
#else
        BPF_JUMP(BPF_JMP + BPF_JA, 0, 0, 0),
#endif
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_unlinkat, 16, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_setxattr, 15, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_lsetxattr, 14, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fsetxattr, 13, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getxattr, 12, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_lgetxattr, 11, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fgetxattr, 10, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_listxattr, 9, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_llistxattr, 8, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_flistxattr, 7, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_removexattr, 6, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_lremovexattr, 5, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fremovexattr, 4, 0),
#ifdef __NR_rename
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rename, 3, 0),
#else
        BPF_JUMP(BPF_JMP + BPF_JA, 0, 0, 0),
#endif
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_renameat, 2, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_renameat2, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(
            BPF_LD + BPF_W + BPF_ABS,
            (__u32)(offsetof(struct seccomp_data, instruction_pointer) + 4)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
                 (__u32)(((unsigned long)start_text) >> 32), 0, 3),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
                 (__u32)(offsetof(struct seccomp_data, instruction_pointer))),
        BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, (__u32)(uintptr_t)start_text, 0, 1),
        BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, (__u32)(uintptr_t)&__etext, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    /* First try without dropping privileges */
    ret = sys_prctl(PR_SET_SECCOMP, 2, (unsigned long)&prog, 0, 0);
    if (ret == 0) {
        return 0;
    }

    ret = sys_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (ret < 0) {
        exit_error("prctl(NO_NEW_PRIVS)");
        return 1;
    }

    ret = sys_prctl(PR_SET_SECCOMP, 2, (unsigned long)&prog, 0, 0);
    if (ret < 0) {
        exit_error("prctl(PR_SET_SECCOMP)");
        return 1;
    }

    return 0;
}

void thread_exit(Tls* tls) {
    vfork_exit_callback();
}

void thread_exit_exec(Tls* tls) {
    // No locks shall be held, since exec inherits tid of parent
    // and then locks can't be detected as dead
    assert(!tls->my_robust_mutex_list.pending);
    assert(RLIST_EMPTY(&tls->my_robust_mutex_list.head));
    assert(!tls->my_rwlock_list.pending);
    assert(RLIST_EMPTY(&tls->my_rwlock_list.head));

    mutex_recover(tls);
    vfork_exit_callback();
}

static int handle_exit(Context* ctx, SysArgs* args) {
    int status = args->arg1;
    trace("exit(%u)\n", status);

    thread_exit(ctx->tls);

    pthread_exit(NULL);
    return 0;
}

static int handle_exit_group(Context* ctx, SysArgs* args) {
    int status = args->arg1;
    trace("exit_group(%u)\n", status);

    thread_exit(ctx->tls);

    sys_exit_group(status);
    return 0;
}

static int bottom_open(Context* ctx, const This* data, const CallOpen* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->at) {
        ret = sys_openat(call->dirfd, call->path, call->flags, call->mode);
    } else {
        ret = sys_open(call->path, call->flags, call->mode);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
    return ret;
}

static int bottom_stat(Context* ctx, const This* data, const CallStat* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    switch (call->type) {
        case STATTYPE_PLAIN:
            ret = sys_stat(call->path, call->statbuf);
            break;

        case STATTYPE_F:
            ret = sys_fstat(call->dirfd, call->statbuf);
            break;

        case STATTYPE_L:
            ret = sys_lstat(call->path, call->statbuf);
            break;

        case STATTYPE_AT:
            ret = sys_newfstatat(call->dirfd, call->path, call->statbuf,
                                 call->flags);
            break;

        case STATTYPE_X:
            ret = sys_statx(call->dirfd, call->path, call->flags, call->mask,
                            (struct statx*)call->statbuf);
            break;

        default:
            abort();
            break;
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
    return ret;
}

static ssize_t bottom_readlink(Context* ctx,
                               const This* data,
                               const CallReadlink* call) {
    ssize_t ret;
    ssize_t* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->at) {
        ret = sys_readlinkat(call->dirfd, call->path, call->buf, call->bufsiz);
    } else {
        ret = sys_readlink(call->path, call->buf, call->bufsiz);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
    return ret;
}

static int bottom_access(Context* ctx,
                         const This* data,
                         const CallAccess* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->at) {
        ret = sys_faccessat(call->dirfd, call->path, call->mode);
    } else {
        ret = sys_access(call->path, call->mode);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
    return ret;
}

static int bottom_link(Context* ctx, const This* data, const CallLink* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->at) {
        ret = sys_linkat(call->olddirfd, call->oldpath, call->newdirfd,
                         call->newpath, call->flags);
    } else {
        ret = sys_link(call->oldpath, call->newpath);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
    return ret;
}

static int bottom_symlink(Context* ctx,
                          const This* data,
                          const CallLink* call) {
    int ret;

    signalmanager_enable_signals(ctx);
    if (call->at) {
        ret = sys_symlinkat(call->oldpath, call->newdirfd, call->newpath);
    } else {
        ret = sys_symlink(call->oldpath, call->newpath);
    }
    signalmanager_disable_signals(ctx);

    *call->ret = ret;
    return ret;
}

static int bottom_unlink(Context* ctx,
                         const This* data,
                         const CallUnlink* call) {
    int ret;

    signalmanager_enable_signals(ctx);
    if (call->at) {
        ret = sys_unlinkat(call->dirfd, call->path, call->flags);
    } else {
        ret = sys_unlink(call->path);
    }
    signalmanager_disable_signals(ctx);

    *call->ret = ret;
    return ret;
}

static int bottom_setxattr(Context* ctx,
                           const This* data,
                           const CallXattr* call) {
    int ret;

    switch (call->type2) {
        case XATTRTYPE_PLAIN:
            ret = sys_setxattr(call->path, call->name, call->value, call->size,
                               call->flags);
            break;

        case XATTRTYPE_L:
            ret = sys_lsetxattr(call->path, call->name, call->value, call->size,
                                call->flags);
            break;

        case XATTRTYPE_F:
            ret = sys_fsetxattr(call->fd, call->name, call->value, call->size,
                                call->flags);
            break;

        default:
            abort();
            break;
    }

    *call->ret = ret;
    return ret;
}

static ssize_t bottom_getxattr(Context* ctx,
                               const This* data,
                               const CallXattr* call) {
    ssize_t ret;

    switch (call->type2) {
        case XATTRTYPE_PLAIN:
            ret = sys_getxattr(call->path, call->name, call->value, call->size);
            break;

        case XATTRTYPE_L:
            ret =
                sys_lgetxattr(call->path, call->name, call->value, call->size);
            break;

        case XATTRTYPE_F:
            ret = sys_fgetxattr(call->fd, call->name, call->value, call->size);
            break;

        default:
            abort();
            break;
    }

    *call->ret = ret;
    return ret;
}

static ssize_t bottom_listxattr(Context* ctx,
                                const This* data,
                                const CallXattr* call) {
    ssize_t ret;

    switch (call->type2) {
        case XATTRTYPE_PLAIN:
            ret = sys_listxattr(call->path, call->list, call->size);
            break;

        case XATTRTYPE_L:
            ret = sys_llistxattr(call->path, call->list, call->size);
            break;

        case XATTRTYPE_F:
            ret = sys_flistxattr(call->fd, call->list, call->size);
            break;

        default:
            abort();
            break;
    }

    *call->ret = ret;
    return ret;
}

static int bottom_removexattr(Context* ctx,
                              const This* data,
                              const CallXattr* call) {
    int ret;

    switch (call->type2) {
        case XATTRTYPE_PLAIN:
            ret = sys_removexattr(call->path, call->name);
            break;

        case XATTRTYPE_L:
            ret = sys_lremovexattr(call->path, call->name);
            break;

        case XATTRTYPE_F:
            ret = sys_fremovexattr(call->fd, call->name);
            break;

        default:
            abort();
            break;
    }

    *call->ret = ret;
    return ret;
}

static ssize_t bottom_xattr(Context* ctx,
                            const This* data,
                            const CallXattr* call) {
    signalmanager_enable_signals(ctx);
    switch (call->type) {
        case XATTRTYPE_SET:
            return bottom_setxattr(ctx, data, call);
            break;

        case XATTRTYPE_GET:
            return bottom_getxattr(ctx, data, call);
            break;

        case XATTRTYPE_LIST:
            return bottom_listxattr(ctx, data, call);
            break;

        case XATTRTYPE_REMOVE:
            return bottom_removexattr(ctx, data, call);
            break;

        default:
            abort();
            break;
    }
    signalmanager_disable_signals(ctx);
}

static int bottom_rename(Context* ctx,
                         const This* data,
                         const CallRename* call) {
    int ret;

    signalmanager_enable_signals(ctx);
    switch (call->type) {
        case RENAMETYPE_PLAIN:
            ret = sys_rename(call->oldpath, call->newpath);
            break;

        case RENAMETYPE_AT:
            ret = sys_renameat(call->olddirfd, call->oldpath, call->newdirfd,
                               call->newpath);
            break;

        case RENAMETYPE_AT2:
            ret = sys_renameat2(call->olddirfd, call->oldpath, call->newdirfd,
                                call->newpath, call->flags);
            break;

        default:
            abort();
            break;
    }
    signalmanager_disable_signals(ctx);

    *call->ret = ret;
    return ret;
}

static int bottom_chdir(Context* ctx, const This* data, const CallChdir* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->f) {
        ret = sys_fchdir(call->fd);
    } else {
        ret = sys_chdir(call->path);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
    return ret;
}

static int bottom_chmod(Context* ctx, const This* data, const CallChmod* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    switch (call->type) {
        case CHMODTYPE_PLAIN:
            ret = sys_chmod(call->path, call->mode);
            break;

        case CHMODTYPE_F:
            ret = sys_fchmod(call->fd, call->mode);
            break;

        case CHMODTYPE_AT:
            ret = sys_fchmodat(call->dirfd, call->path, call->mode);
            break;

        default:
            abort();
            break;
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
    return ret;
}

static int bottom_truncate(Context* ctx,
                           const This* data,
                           const CallTruncate* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->f) {
        ret = sys_ftruncate(call->fd, call->length);
    } else {
        ret = sys_truncate(call->path, call->length);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
    return ret;
}

static int bottom_mkdir(Context* ctx, const This* data, const CallMkdir* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->at) {
        ret = sys_mkdirat(call->dirfd, call->path, call->mode);
    } else {
        ret = sys_mkdir(call->path, call->mode);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
    return ret;
}

static ssize_t bottom_getdents(Context* ctx,
                               const This* data,
                               const CallGetdents* call) {
    ssize_t ret;
    ssize_t* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->is64) {
        ret =
            sys_getdents64(call->fd, (linux_dirent64*)call->dirp, call->count);
    } else {
        ret = sys_getdents(call->fd, call->dirp, call->count);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
    return ret;
}

static int bottom_mknod(Context* ctx, const This* data, const CallMknod* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->at) {
        ret = sys_mknodat(call->dirfd, call->path, call->mode, call->dev);
    } else {
        ret = sys_mknod(call->path, call->mode, call->dev);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
    return ret;
}

static int bottom_accept(Context* ctx,
                         const This* data,
                         const CallAccept* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->is4) {
        ret = sys_accept4(call->fd, call->addr, call->addrlen, call->flags);
    } else {
        ret = sys_accept(call->fd, call->addr, call->addrlen);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
    return ret;
}

static int bottom_connect(Context* ctx,
                          const This* data,
                          const CallConnect* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->is_bind) {
        ret = sys_bind(call->fd, call->addr, call->addrlen);
    } else {
        ret = sys_connect(call->fd, call->addr, call->addrlen);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
    return ret;
}

static int bottom_fanotify_mark(Context* ctx,
                                const This* data,
                                const CallFanotifyMark* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    ret = sys_fanotify_mark(call->fd, call->flags, call->mask, call->dirfd,
                            call->path);
    signalmanager_disable_signals(ctx);

    *_ret = ret;
    return ret;
}

static int bottom_inotify_add_watch(Context* ctx,
                                    const This* data,
                                    const CallInotifyAddWatch* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    ret = sys_inotify_add_watch(call->fd, call->path, call->mask);
    signalmanager_disable_signals(ctx);

    *_ret = ret;
    return ret;
}

static int bottom_rlimit(Context* ctx,
                         const This* data,
                         const CallRlimit* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    switch (call->type) {
        case RLIMITTYPE_GET:
            ret = sys_getrlimit(call->resource, call->old_rlim);
            break;

        case RLIMITTYPE_SET:
            ret = sys_setrlimit(call->resource, call->new_rlim);
            break;

        case RLIMITTYPE_PR:
            ret = sys_prlimit64(call->pid, call->resource,
                                (const rlimit64*)call->new_rlim,
                                (rlimit64*)call->old_rlim);
            break;

        default:
            abort();
            break;
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
    return ret;
}

static long bottom_ptrace(Context* ctx,
                          const This* data,
                          const CallPtrace* call) {
    long ret;
    long* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    ret = sys_ptrace(call->request, call->pid, call->addr, call->data);
    signalmanager_disable_signals(ctx);

    *_ret = ret;
    return ret;
}

static int bottom_kill(Context* ctx, const This* data, const CallKill* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    ret = sys_kill(call->pid, call->sig);
    signalmanager_disable_signals(ctx);

    *_ret = ret;
    return ret;
}

static int bottom_close(Context* ctx, const This* data, const CallClose* call) {
    int ret;

    signalmanager_enable_signals(ctx);
    if (call->is_range) {
        ret = sys_close_range(call->fd, call->max_fd, call->flags);
    } else {
        ret = sys_close(call->fd);
    }
    signalmanager_disable_signals(ctx);

    *call->ret = ret;
    return ret;
}

static unsigned long bottom_misc(Context* ctx,
                                 const This* data,
                                 const CallMisc* call) {
    debug("Unhandled syscall no. %lu\n", call->args.num);

    *call->ret = -ENOSYS;
    return *call->ret;
}

static unsigned long bottom_mmap(Context* ctx,
                                 const This* data,
                                 const CallMmap* call) {
    unsigned long ret;
    unsigned long* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    ret = (unsigned long)sys_mmap((void*)call->addr, call->len, call->prot,
                                  call->flags, call->fd, call->off);
    signalmanager_disable_signals(ctx);

    *_ret = ret;
    return ret;
}

static const CallHandler bottom = {
    bottom_open,
    nullptr,
    bottom_stat,
    nullptr,
    bottom_readlink,
    nullptr,
    bottom_access,
    nullptr,
    bottom_exec,
    nullptr,
    bottom_link,
    nullptr,
    bottom_symlink,
    nullptr,
    bottom_unlink,
    nullptr,
    bottom_xattr,
    nullptr,
    bottom_rename,
    nullptr,
    bottom_chdir,
    nullptr,
    bottom_chmod,
    nullptr,
    bottom_truncate,
    nullptr,
    bottom_mkdir,
    nullptr,
    bottom_getdents,
    nullptr,
    bottom_mknod,
    nullptr,
    bottom_accept,
    nullptr,
    bottom_connect,
    nullptr,
    bottom_fanotify_mark,
    nullptr,
    bottom_inotify_add_watch,
    nullptr,
    bottom_rlimit,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    bottom_ptrace,
    nullptr,
    bottom_kill,
    nullptr,
    bottom_close,
    nullptr,
    bottom_misc,
    nullptr,
    bottom_mmap,
    nullptr,
    nullptr,
    nullptr,
};

void intercept_init(int recursing, const char* exe) {
    size_t exe_len = strlen(exe) + 1;

    if (initialized) {
        return;
    }
    initialized = 1;

    if (exe_len > SCRATCH_SIZE) {
        abort();
    }
    memcpy(_self_exe, exe, exe_len);

    int ret = __main_prepare_threaded();
    if (ret != 0) {
        abort();
    }
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
    tls_init();
    mutex_init();
    start_text_init();

    const CallHandler* signalmanager = signalmanager_init(&bottom);
    _next = main_init(signalmanager, recursing);

    signalmanager_install_sigsys(handler);

    if (!recursing) {
        install_filter();
    }
}
