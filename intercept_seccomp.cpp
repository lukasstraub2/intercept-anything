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
static Tls* get_tls() {
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

    return tls;
}

static void handler(int sig, siginfo_t* info, void* ucontext) {
    Tls* tls = get_tls();

    struct ucontext* uctx = (struct ucontext*)ucontext;
    sigset_t* uctx_set = &uctx->uc_sigmask;
    Context ctx = {tls, uctx_set, ucontext, 0};
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

unsigned long fastpath_entry(unsigned long num,
                             unsigned long arg1,
                             unsigned long arg2,
                             unsigned long arg3,
                             unsigned long arg4,
                             unsigned long arg5,
                             unsigned long arg6) {
    sigset_t saved_mask;
    ssize_t ret, ret2;

    ret2 = sys_rt_sigprocmask(SIG_SETMASK, full_mask(), &saved_mask);
    if (ret2 < 0) {
        abort();
    }
    __asm volatile("" ::: "memory");

    Tls* tls = get_tls();
    SysArgs args = {num, arg1, arg2, arg3, arg4, arg5, arg6};
    Context ctx = {tls, &saved_mask, nullptr, 0};

    ret = handle_syscall(&ctx, &args);
    if (ctx.trampo_armed) {
        abort();
    }

    __asm volatile("" ::: "memory");
    ret2 = sys_rt_sigprocmask(SIG_SETMASK, &saved_mask, nullptr);
    if (ret2 < 0) {
        abort();
    }

    return ret;
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

    Context ctx = {tls, nullptr, nullptr, 0};
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

// clang-format off

const struct sock_filter filter_head[] = {
    BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
             (__u32)(offsetof(struct seccomp_data, arch))),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_CURRENT, 1, 0),
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP | (1 & SECCOMP_RET_DATA)),
};

const struct sock_filter filter_tail[] = {
    BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
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

const long syscall_sendrecv[] = {
    __NR_recvmmsg,
    __NR_sendmmsg,
    __NR_recvmsg,
    __NR_sendmsg,
    __NR_recvfrom,
    __NR_sendto,
};

const long syscall_socket[] = {
    __NR_getsockopt,
    __NR_setsockopt,
    __NR_socketpair,
    __NR_getpeername,
    __NR_getsockname,
    __NR_listen,
    __NR_shutdown,
    __NR_socket,
    __NR_connect,
    __NR_bind,
    __NR_accept,
    __NR_accept4,
};

const long syscall_readwrite[] = {
    __NR_write,
    __NR_writev,
    __NR_pwrite64,
    __NR_pwritev,
    __NR_pwritev2,
    __NR_read,
    __NR_readv,
    __NR_pread64,
    __NR_preadv,
    __NR_preadv2,
};

const long syscall_file[] = {
#ifdef __NR_close_range
    __NR_close_range,
#endif
    __NR_close,
    __NR_fanotify_mark,
    __NR_inotify_add_watch,
#ifdef __NR_mknod
    __NR_mknod,
#endif
    __NR_mknodat,
#ifdef __NR_getdents
    __NR_getdents,
#endif
    __NR_getdents64,
#ifdef __NR_mkdir
    __NR_mkdir,
#endif
    __NR_mkdirat,
    __NR_truncate,
    __NR_ftruncate,
#ifdef __NR_chmod
    __NR_chmod,
#endif
    __NR_fchmod,
    __NR_fchmodat,
    __NR_chdir,
    __NR_fchdir,
#ifdef __NR_open
    __NR_open,
#endif
    __NR_openat,
#ifdef __NR_stat
    __NR_stat,
#endif
    __NR_fstat,
#ifdef __NR_lstat
    __NR_lstat,
#endif
    __NR_newfstatat,
    __NR_statx,
#ifdef __NR_readlink
    __NR_readlink,
#endif
    __NR_readlinkat,
#ifdef __NR_access
    __NR_access,
#endif
    __NR_faccessat,
    __NR_execve,
    __NR_execveat,
#ifdef __NR_link
    __NR_link,
#endif
    __NR_linkat,
#ifdef __NR_symlink
    __NR_symlink,
#endif
    __NR_symlinkat,
#ifdef __NR_unlink
    __NR_unlink,
#endif
    __NR_unlinkat,
    __NR_setxattr,
    __NR_lsetxattr,
    __NR_fsetxattr,
    __NR_getxattr,
    __NR_lgetxattr,
    __NR_fgetxattr,
    __NR_listxattr,
    __NR_llistxattr,
    __NR_flistxattr,
    __NR_removexattr,
    __NR_lremovexattr,
    __NR_fremovexattr,
#ifdef __NR_rename
    __NR_rename,
#endif
    __NR_renameat,
    __NR_renameat2,
};

const long syscall_mem[] = {
    __NR_mmap,
};

const long syscall_process[] = {
    __NR_clone3,
    __NR_clone,
#ifdef __NR_vfork
    __NR_vfork,
#endif
#ifdef __NR_fork
    __NR_fork,
#endif
    __NR_kill,
    __NR_ptrace,
    __NR_getrlimit,
    __NR_setrlimit,
    __NR_prlimit64,
    __NR_exit,
    __NR_exit_group,
    __NR_rt_sigprocmask,
    __NR_rt_sigaction,
    // Don't intercept __NR_rt_sigreturn by default, it can be intercepted
    // with FILTER_ALL
    //__NR_rt_sigreturn,
};
// clang-format on

const int filter_head_len = sizeof(filter_head) / sizeof(filter_head[0]);
const int filter_tail_len = sizeof(filter_tail) / sizeof(filter_tail[0]);
const int syscall_process_len = sizeof(syscall_process) / sizeof(long);
const int syscall_mem_len = sizeof(syscall_mem) / sizeof(long);
const int syscall_file_len = sizeof(syscall_file) / sizeof(long);
const int syscall_readwrite_len = sizeof(syscall_readwrite) / sizeof(long);
const int syscall_socket_len = sizeof(syscall_socket) / sizeof(long);
const int syscall_sendrecv_len = sizeof(syscall_sendrecv) / sizeof(long);

static struct sock_filter* fill_jump_cmp(struct sock_filter* ptr,
                                         const long* list,
                                         int len,
                                         int* idx,
                                         int syscall_len) {
    assert(syscall_len < 128);
    for (int i = 0; i < len; i++) {
        __u8 jump = syscall_len - *idx;
        (*idx)++;
        struct sock_filter instr =
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (__u32)list[i], jump, 0);
        memcpy(ptr, &instr, sizeof(instr));
        ptr++;
    }
    return ptr;
}

static void build_filter_selective(struct sock_fprog* prog, int flags) {
    int len = 0;
    int idx = 0;

    if (flags & FILTER_PROCESS) {
        len += syscall_process_len;
    }
    if (flags & FILTER_MEM) {
        len += syscall_mem_len;
    }
    if (flags & FILTER_FILE) {
        len += syscall_file_len;
    }
    if (flags & FILTER_READWRITE) {
        len += syscall_readwrite_len;
    }
    if (flags & FILTER_SOCKET) {
        len += syscall_socket_len;
    }
    if (flags & FILTER_SENDRECV) {
        len += syscall_sendrecv_len;
    }

    int syscall_len = len;
    len += filter_head_len + 1 + 1 + filter_tail_len;

    struct sock_filter* filter = new struct sock_filter[len];
    struct sock_filter* ptr = filter;

    memcpy(ptr, filter_head, filter_head_len * sizeof(struct sock_filter));
    ptr += filter_head_len;

    *ptr = BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
                    (__u32)(offsetof(struct seccomp_data, nr)));
    ptr++;

    if (flags & FILTER_PROCESS) {
        ptr = fill_jump_cmp(ptr, syscall_process, syscall_process_len, &idx,
                            syscall_len);
    }
    if (flags & FILTER_MEM) {
        ptr =
            fill_jump_cmp(ptr, syscall_mem, syscall_mem_len, &idx, syscall_len);
    }
    if (flags & FILTER_FILE) {
        ptr = fill_jump_cmp(ptr, syscall_file, syscall_file_len, &idx,
                            syscall_len);
    }
    if (flags & FILTER_READWRITE) {
        ptr = fill_jump_cmp(ptr, syscall_readwrite, syscall_readwrite_len, &idx,
                            syscall_len);
    }
    if (flags & FILTER_SOCKET) {
        ptr = fill_jump_cmp(ptr, syscall_socket, syscall_socket_len, &idx,
                            syscall_len);
    }
    if (flags & FILTER_SENDRECV) {
        ptr = fill_jump_cmp(ptr, syscall_sendrecv, syscall_sendrecv_len, &idx,
                            syscall_len);
    }

    *ptr = BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW);
    ptr++;

    memcpy(ptr, filter_tail, filter_tail_len * sizeof(struct sock_filter));
    ptr += filter_tail_len;

    assert(ptr == filter + len);

    prog->len = len;
    prog->filter = filter;
}

static void build_filter_all(struct sock_fprog* prog, int flags) {
    int len = filter_head_len + filter_tail_len;
    struct sock_filter* filter = new struct sock_filter[len];
    struct sock_filter* ptr = filter;

    memcpy(ptr, filter_head, filter_head_len * sizeof(struct sock_filter));
    ptr += filter_head_len;
    memcpy(ptr, filter_tail, filter_tail_len * sizeof(struct sock_filter));
    ptr += filter_tail_len;

    assert(ptr == filter + len);

    prog->len = len;
    prog->filter = filter;
}

static int install_filter(int flags) {
    int ret;
    struct sock_fprog prog{};

    if (flags & FILTER_ALL) {
        build_filter_all(&prog, flags);
    } else {
        build_filter_selective(&prog, flags);
    }

    /* First try without dropping privileges */
    ret = sys_prctl(PR_SET_SECCOMP, 2, (unsigned long)&prog, 0, 0);
    if (ret == 0) {
        delete[] prog.filter;
        return 0;
    }

    ret = sys_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (ret < 0) {
        delete[] prog.filter;
        exit_error("prctl(NO_NEW_PRIVS)");
        return 1;
    }

    ret = sys_prctl(PR_SET_SECCOMP, 2, (unsigned long)&prog, 0, 0);
    if (ret < 0) {
        delete[] prog.filter;
        exit_error("prctl(PR_SET_SECCOMP)");
        return 1;
    }

    delete[] prog.filter;
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
        install_filter(intercept_entrypoint->get_filter_flags());
    }
}
