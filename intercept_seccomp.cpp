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
#include "handle_syscall.h"
#include "bottomhandler.h"

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

CallHandler* intercept_entrypoint = nullptr;

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
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_write, 77, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_pwrite64, 76, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_pwritev, 75, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_pwritev2, 74, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_read, 73, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_pread64, 72, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_preadv, 71, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_preadv2, 70, 0),
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

    CallHandler* const bottom = new BottomHandler();
    CallHandler* const signalmanager = signalmanager_init(bottom);
    intercept_entrypoint = main_init(signalmanager, recursing);

    signalmanager_install_sigsys(handler);

    if (!recursing) {
        install_filter();
    }
}
