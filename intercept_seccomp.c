
#include "common.h"

#include "nolibc.h"
#include "mysignal.h"
#include "myseccomp.h"
#include "mysys.h"
#include "intercept.h"
#include "loader.h"
#include "mytypes.h"
#include "config.h"
#include "signalmanager.h"
#include "tls.h"
#include "util.h"

#include <asm/siginfo.h>

#define DEBUG_ENV "DEBUG_INTERCEPT"
#include "debug.h"

#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

static int initialized = 0;

static const CallHandler bottom;
static const CallHandler* _next = NULL;

static char _self_exe[SCRATCH_SIZE];
const char* self_exe = _self_exe;
size_t page_size;

static int install_filter();
static void handler(int sig, siginfo_t* info, void* ucontext);
static unsigned long handle_syscall(Context* ctx, SysArgs* args);
static void start_text_init();
static void page_size_init();

__attribute__((weak)) const CallHandler* main_init(const CallHandler* bottom,
                                                   int recursing) {
    return bottom;
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

    tls_init();
    mutex_init();
    page_size_init();
    start_text_init();

    const CallHandler* signalmanager = signalmanager_init(&bottom);
    _next = main_init(signalmanager, recursing);

    signalmanager_install_sigsys(handler);

    if (!recursing) {
        install_filter();
    }
}

__attribute__((noinline)) static void __handler(Tls* tls,
                                                int sig,
                                                siginfo_t* info,
                                                void* ucontext) {
    (void)sig;

    Context ctx = {tls, ucontext, 0};
    ssize_t ret;
    SysArgs args;
    fill_sysargs(&args, ucontext);
    ret = handle_syscall(&ctx, &args);

    set_return(ucontext, ret);
}

__attribute__((noinline, section("signal_entry"))) static int _handler(
    Tls* tls,
    MyJumpbuf** _jumpbuf,
    int sig,
    siginfo_t* info,
    void* ucontext) {
    MyJumpbuf jumpbuf = {JUMPBUF_MAGIC, {0}};

    if (__builtin_setjmp(jumpbuf.jumpbuf)) {
        return 1;
    }
    __asm volatile("" ::: "memory");
    WRITE_ONCE(*_jumpbuf, &jumpbuf);
    __asm volatile("" ::: "memory");

    __handler(tls, sig, info, ucontext);

    __asm volatile("" ::: "memory");
    WRITE_ONCE(*_jumpbuf, NULL);
    __asm volatile("" ::: "memory");

    return 0;
}

__attribute__((noinline, section("signal_entry"))) static void
handler(int sig, siginfo_t* info, void* ucontext) {
    const pid_t tid = gettid();
    trace_plus("gettid(): %u\n", tid);
    Tls* tls = _tls_get(tid);
    signalmanager_please_callback(tls);

    if (info->si_errno) {
        exit_error("Invalid arch, terminating");
    }

    MyJumpbuf* sp = get_sp(ucontext);
    MyJumpbuf** jumpbuf;
    for (int i = 0; i < jumpbuf_alloc; i++) {
        jumpbuf = tls->jumpbuf + i;
        if (!*jumpbuf) {
            break;
        }
#ifdef stack_grows_down
        if (*jumpbuf < sp) {
            break;
        }
#else
#error Unsupported Architecture
#endif
    }

    __asm volatile("" ::: "memory");
    signalmanager_sigsys_unmask(ucontext);
    __asm volatile("" ::: "memory");

    while (_handler(tls, jumpbuf, sig, info, ucontext))
        ;
}

static char* start_text;
extern char __etext;

extern char __start_signal_entry;
extern char __stop_signal_entry;

static void page_size_init() {
    size_t sizes[] = {(4 * 1024), (16 * 1024), (64 * 1024)};

    size_t size;
    for (int i = 0; i < (int)(sizeof(sizes) / sizeof(sizes[0])); i++) {
        size = sizes[i];
        unsigned long ret = (unsigned long)sys_mmap(
            NULL, size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (ret >= -4095UL) {
            continue;
        }

        sys_munmap((void*)ret, size);
        break;
    }

    page_size = size;
}

static void start_text_init() {
    unsigned long addr = (unsigned long)&__etext;
    addr &= -page_size;  // round down

    while (1) {
        int ret = sys_access((char*)addr, F_OK);
        if (ret != -EFAULT) {
            addr -= page_size;
            continue;
        }

        break;
    }

    addr += page_size;
    start_text = (char*)addr;
}

int pc_in_our_code(void* ucontext) {
    char* pc = get_pc(ucontext);
    int in_text = pc >= start_text && pc < &__etext;
    int in_signal_entry =
        pc >= &__start_signal_entry && pc < &__stop_signal_entry;
    return in_text && !in_signal_entry;
}

static int install_filter() {
    int ret;

    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
                 (offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_CURRENT, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP | (1 & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
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
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
                 (offsetof(struct seccomp_data, instruction_pointer) + 4)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ((unsigned long)start_text) >> 32,
                 0, 3),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
                 (offsetof(struct seccomp_data, instruction_pointer))),
        BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, (unsigned long)start_text, 0, 1),
        BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, (unsigned long)&__etext, 0, 1),
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

static int64_t array_len(char* const array[]) {
    int64_t len;

    for (len = 0; array[len]; len++) {
        if (len == INT_MAX) {
            return -1;
        }
    }

    return len;
}

static void array_copy(char* dest[], char* const source[], int64_t len) {
    memcpy(dest, source, len * sizeof(char*));
}

static int cmdline_argc(char* buf, ssize_t size) {
    int argc = 0;
    int whitespace = 1;

    for (int i = 2; i < size; i++) {
        if (buf[i] == '\r' || buf[i] == '\n') {
            return argc;
        } else if (buf[i] != ' ' && buf[i] != '\t') {
            if (whitespace) {
                argc++;
                whitespace = 0;
            }
        } else {
            whitespace = 1;
        }
    }

    return argc;
}

static void cmdline_extract(char* buf, ssize_t size, char** dest) {
    int argc = 0;
    int whitespace = 1;

    for (int i = 2; i < size; i++) {
        if (buf[i] == '\r' || buf[i] == '\n') {
            buf[i] = '\0';
            return;
        } else if (buf[i] != ' ' && buf[i] != '\t') {
            if (whitespace) {
                dest[argc] = buf + i;
                argc++;
                whitespace = 0;
            }
        } else {
            buf[i] = '\0';
            whitespace = 1;
        }
    }

    buf[size - 1] = '\0';
    return;
}

static void debug_exec(const char* pathname,
                       char* const argv[],
                       char* const envp[]) {
    int64_t i;

    trace(": recurse execve(%s, [ ", pathname ? pathname : "NULL");

    for (i = 0; argv[i]; i++) {
        trace("%s, ", argv[i]);
    }

    trace("], envp)\n");
}

static ssize_t read_full(int fd, char* buf, size_t count) {
    ssize_t ret = 0;
    ssize_t total = 0;

    while (count) {
        ret = sys_read(fd, buf, count);
        if (ret < 0) {
            if (ret == -EINTR)
                continue;
            return ret;
        } else if (ret == 0) {
            break;
        }

        count -= ret;
        buf += ret;
        total += ret;
    }

    return total;
}

static void thread_exit(Tls* tls) {
    signalmanager_clean_dead(tls);
    tls_free();
}

static void thread_exit_exec(Tls* tls) {
    // No locks shall be held, since exec inherits tid of parent
    // and then locks can't be detected as dead
    assert(!tls->my_robust_mutex_list.pending);
    assert(RLIST_EMPTY(&tls->my_robust_mutex_list.head));
    assert(!tls->my_rwlock_list.pending);
    assert(RLIST_EMPTY(&tls->my_rwlock_list.head));

    mutex_recover(tls);
    signalmanager_clean_dead(tls);
    tls_free();
}

static const char* or_null(const char* str) {
    if (str) {
        return str;
    } else {
        return "NULL";
    }
}

__attribute__((unused)) static int handle_open(Context* ctx,
                                               const char* path,
                                               int flags,
                                               mode_t mode) {
    trace("open(%s)\n", or_null(path));

    RetInt ret = {0};
    CallOpen call = {
        .at = 0, .path = path, .flags = flags, .mode = mode, .ret = &ret};

    _next->open(ctx, _next->open_next, &call);

    return ret.ret;
}

static int handle_openat(Context* ctx,
                         int dirfd,
                         const char* path,
                         int flags,
                         mode_t mode) {
    trace("openat(%s)\n", or_null(path));

    RetInt ret = {0};
    CallOpen call = {.at = 1,
                     .dirfd = dirfd,
                     .path = path,
                     .flags = flags,
                     .mode = mode,
                     .ret = &ret};

    _next->open(ctx, _next->open_next, &call);

    return ret.ret;
}

int loader_open(const char* path, int flags, mode_t mode) {
    if (!initialized) {
        return sys_open(path, flags, mode);
    }

    Context ctx = {tls_get(), NULL, 0};
    return handle_openat(&ctx, AT_FDCWD, path, flags, mode);
}

__attribute__((unused)) static int handle_stat(Context* ctx,
                                               const char* path,
                                               void* statbuf) {
    trace("stat(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallStat call = {
        .type = STATTYPE_PLAIN, .path = path, .statbuf = statbuf, .ret = &ret};

    _next->stat(ctx, _next->stat_next, &call);

    return ret.ret;
}

static int handle_fstat(Context* ctx, int fd, void* statbuf) {
    trace("fstat()\n");

    RetInt ret = {0};
    CallStat call = {
        .type = STATTYPE_F, .dirfd = fd, .statbuf = statbuf, .ret = &ret};

    _next->stat(ctx, _next->stat_next, &call);

    return ret.ret;
}

__attribute__((unused)) static int handle_lstat(Context* ctx,
                                                const char* path,
                                                void* statbuf) {
    trace("lstat(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallStat call = {
        .type = STATTYPE_L, .path = path, .statbuf = statbuf, .ret = &ret};

    _next->stat(ctx, _next->stat_next, &call);

    return ret.ret;
}

static int handle_newfstatat(Context* ctx,
                             int dirfd,
                             const char* path,
                             void* statbuf,
                             int flags) {
    trace("newfstatat(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallStat call = {.type = STATTYPE_AT,
                     .dirfd = dirfd,
                     .path = path,
                     .statbuf = statbuf,
                     .flags = flags,
                     .ret = &ret};

    _next->stat(ctx, _next->stat_next, &call);

    return ret.ret;
}

static int handle_statx(Context* ctx,
                        int dirfd,
                        const char* path,
                        int flags,
                        unsigned int mask,
                        void* statbuf) {
    trace("statx(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallStat call = {.type = STATTYPE_X,
                     .dirfd = dirfd,
                     .path = path,
                     .flags = flags,
                     .mask = mask,
                     .statbuf = statbuf,
                     .ret = &ret};

    _next->stat(ctx, _next->stat_next, &call);

    return ret.ret;
}

__attribute__((unused)) static ssize_t handle_readlink(Context* ctx,
                                                       const char* path,
                                                       char* buf,
                                                       size_t bufsiz) {
    trace("readlink(%s)\n", or_null(path));

    if (!bufsiz) {
        return -EINVAL;
    } else if (!path) {
        return -EFAULT;
    }
    // Not a symlink: -EINVAL
    // buf NULL: -EFAULT

    RetSSize ret = {0};
    CallReadlink call = {
        .at = 0, .path = path, .buf = buf, .bufsiz = bufsiz, .ret = &ret};

    _next->readlink(ctx, _next->readlink_next, &call);

    return ret.ret;
}

static ssize_t handle_readlinkat(Context* ctx,
                                 int dirfd,
                                 const char* path,
                                 char* buf,
                                 size_t bufsiz) {
    trace("readlinkat(%s)\n", or_null(path));

    if (!bufsiz) {
        return -EINVAL;
    } else if (!path) {
        return -EFAULT;
    }

    RetSSize ret = {0};
    CallReadlink call = {.at = 1,
                         .dirfd = dirfd,
                         .path = path,
                         .buf = buf,
                         .bufsiz = bufsiz,
                         .ret = &ret};

    _next->readlink(ctx, _next->readlink_next, &call);

    return ret.ret;
}

__attribute__((unused)) static int handle_access(Context* ctx,
                                                 const char* path,
                                                 int mode) {
    trace("access(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallAccess call = {.at = 0, .path = path, .mode = mode, .ret = &ret};

    _next->access(ctx, _next->access_next, &call);

    return ret.ret;
}

static int handle_faccessat(Context* ctx,
                            int dirfd,
                            const char* path,
                            int mode) {
    trace("accessat(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallAccess call = {
        .at = 1, .dirfd = dirfd, .path = path, .mode = mode, .ret = &ret};

    _next->access(ctx, _next->access_next, &call);

    return ret.ret;
}

static int handle_execve(Context* ctx,
                         const char* path,
                         char* const argv[],
                         char* const envp[]) {
    trace("execve(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallExec call = {
        .at = 0, .path = path, .argv = argv, .envp = envp, .ret = &ret};

    _next->exec(ctx, _next->exec_next, &call);

    return ret.ret;
}

static int handle_execveat(Context* ctx,
                           int dirfd,
                           const char* path,
                           char* const argv[],
                           char* const envp[],
                           int flags) {
    trace("exeveat(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallExec call = {.at = 1,
                     .dirfd = dirfd,
                     .path = path,
                     .argv = argv,
                     .envp = envp,
                     .flags = flags,
                     .ret = &ret};

    _next->exec(ctx, _next->exec_next, &call);

    return ret.ret;
}

static int handle_rt_sigprocmask(Context* ctx,
                                 int how,
                                 const sigset_t* set,
                                 sigset_t* oldset,
                                 size_t sigsetsize) {
    trace("rt_sigprocmask()\n");

    RetInt ret = {0};
    CallSigprocmask call = {.how = how,
                            .set = set,
                            .oldset = oldset,
                            .sigsetsize = sigsetsize,
                            .ret = &ret};

    _next->sigprocmask(ctx, _next->sigprocmask_next, &call);

    return ret.ret;
}

static int handle_rt_sigaction(Context* ctx,
                               int signum,
                               const struct sigaction* act,
                               struct sigaction* oldact,
                               size_t sigsetsize) {
    trace("rt_sigaction(%d)\n", signum);

    RetInt ret = {0};
    CallSigaction call = {.signum = signum,
                          .act = act,
                          .oldact = oldact,
                          .sigsetsize = sigsetsize,
                          .ret = &ret};

    _next->sigaction(ctx, _next->sigaction_next, &call);

    return ret.ret;
}

__attribute__((unused)) static int handle_link(Context* ctx,
                                               const char* oldpath,
                                               const char* newpath) {
    trace("link(%s, %s)\n", or_null(oldpath), or_null(newpath));

    if (!oldpath || !newpath) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallLink call = {
        .at = 0, .oldpath = oldpath, .newpath = newpath, .ret = &ret};

    _next->link(ctx, _next->link_next, &call);

    return ret.ret;
}

static int handle_linkat(Context* ctx,
                         int olddirfd,
                         const char* oldpath,
                         int newdirfd,
                         const char* newpath,
                         int flags) {
    trace("linkat(%s, %s)\n", or_null(oldpath), or_null(newpath));

    if (!oldpath || !newpath) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallLink call = {.at = 1,
                     .olddirfd = olddirfd,
                     .oldpath = oldpath,
                     .newdirfd = newdirfd,
                     .newpath = newpath,
                     .flags = flags,
                     .ret = &ret};

    _next->link(ctx, _next->link_next, &call);

    return ret.ret;
}

__attribute__((unused)) static int handle_symlink(Context* ctx,
                                                  const char* oldpath,
                                                  const char* newpath) {
    trace("symlink(%s, %s)\n", or_null(oldpath), or_null(newpath));

    if (!oldpath || !newpath) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallLink call = {
        .at = 0, .oldpath = oldpath, .newpath = newpath, .ret = &ret};

    _next->symlink(ctx, _next->symlink_next, &call);

    return ret.ret;
}

static int handle_symlinkat(Context* ctx,
                            const char* oldpath,
                            int newdirfd,
                            const char* newpath) {
    trace("symlinkat(%s, %s)\n", or_null(oldpath), or_null(newpath));

    if (!oldpath || !newpath) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallLink call = {.at = 1,
                     .oldpath = oldpath,
                     .newdirfd = newdirfd,
                     .newpath = newpath,
                     .ret = &ret};

    _next->symlink(ctx, _next->symlink_next, &call);

    return ret.ret;
}

__attribute__((unused)) static int handle_unlink(Context* ctx,
                                                 const char* pathname) {
    trace("unlink(%s)\n", or_null(pathname));

    if (!pathname) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallUnlink call = {.at = 0, .path = pathname, .ret = &ret};

    _next->unlink(ctx, _next->unlink_next, &call);

    return ret.ret;
}

static int handle_unlinkat(Context* ctx,
                           int dirfd,
                           const char* pathname,
                           int flags) {
    trace("unlinkat(%s)\n", or_null(pathname));

    if (!pathname) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallUnlink call = {
        .at = 1, .dirfd = dirfd, .path = pathname, .flags = flags, .ret = &ret};

    _next->unlink(ctx, _next->unlink_next, &call);

    return ret.ret;
}

static int handle_setxattr(Context* ctx,
                           const char* path,
                           const char* name,
                           const void* value,
                           size_t size,
                           int flags) {
    trace("setxattr(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetSSize ret = {0};
    CallXattr call = {.type = XATTRTYPE_SET,
                      .type2 = XATTRTYPE_PLAIN,
                      .path = path,
                      .name = name,
                      .value = (void*)value,
                      .size = size,
                      .flags = flags,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

    return ret.ret;
}

static int handle_lsetxattr(Context* ctx,
                            const char* path,
                            const char* name,
                            const void* value,
                            size_t size,
                            int flags) {
    trace("lsetxattr(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetSSize ret = {0};
    CallXattr call = {.type = XATTRTYPE_SET,
                      .type2 = XATTRTYPE_L,
                      .path = path,
                      .name = name,
                      .value = (void*)value,
                      .size = size,
                      .flags = flags,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

    return ret.ret;
}

static int handle_fsetxattr(Context* ctx,
                            int fd,
                            const char* name,
                            const void* value,
                            size_t size,
                            int flags) {
    trace("fsetxattr(%d)\n", fd);

    RetSSize ret = {0};
    CallXattr call = {.type = XATTRTYPE_SET,
                      .type2 = XATTRTYPE_F,
                      .fd = fd,
                      .name = name,
                      .value = (void*)value,
                      .size = size,
                      .flags = flags,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

    return ret.ret;
}

static ssize_t handle_getxattr(Context* ctx,
                               const char* path,
                               const char* name,
                               void* value,
                               size_t size) {
    trace("getxattr(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetSSize ret = {0};
    CallXattr call = {.type = XATTRTYPE_GET,
                      .type2 = XATTRTYPE_PLAIN,
                      .path = path,
                      .name = name,
                      .value = value,
                      .size = size,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

    return ret.ret;
}

static ssize_t handle_lgetxattr(Context* ctx,
                                const char* path,
                                const char* name,
                                void* value,
                                size_t size) {
    trace("lgetxattr(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetSSize ret = {0};
    CallXattr call = {.type = XATTRTYPE_GET,
                      .type2 = XATTRTYPE_L,
                      .path = path,
                      .name = name,
                      .value = value,
                      .size = size,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

    return ret.ret;
}

static ssize_t handle_fgetxattr(Context* ctx,
                                int fd,
                                const char* name,
                                void* value,
                                size_t size) {
    trace("fgetxattr(%d)\n", fd);

    RetSSize ret = {0};
    CallXattr call = {.type = XATTRTYPE_GET,
                      .type2 = XATTRTYPE_F,
                      .fd = fd,
                      .name = name,
                      .value = value,
                      .size = size,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

    return ret.ret;
}

static ssize_t handle_listxattr(Context* ctx,
                                const char* path,
                                char* list,
                                size_t size) {
    trace("listxattr(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetSSize ret = {0};
    CallXattr call = {.type = XATTRTYPE_LIST,
                      .type2 = XATTRTYPE_PLAIN,
                      .path = path,
                      .list = list,
                      .size = size,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

    return ret.ret;
}

static ssize_t handle_llistxattr(Context* ctx,
                                 const char* path,
                                 char* list,
                                 size_t size) {
    trace("llistxattr(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetSSize ret = {0};
    CallXattr call = {.type = XATTRTYPE_LIST,
                      .type2 = XATTRTYPE_L,
                      .path = path,
                      .list = list,
                      .size = size,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

    return ret.ret;
}

static ssize_t handle_flistxattr(Context* ctx,
                                 int fd,
                                 char* list,
                                 size_t size) {
    trace("flistxattr(%d)\n", fd);

    RetSSize ret = {0};
    CallXattr call = {.type = XATTRTYPE_LIST,
                      .type2 = XATTRTYPE_F,
                      .fd = fd,
                      .list = list,
                      .size = size,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

    return ret.ret;
}

static int handle_removexattr(Context* ctx,
                              const char* path,
                              const char* name) {
    trace("removexattr(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetSSize ret = {0};
    CallXattr call = {.type = XATTRTYPE_REMOVE,
                      .type2 = XATTRTYPE_PLAIN,
                      .path = path,
                      .name = name,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

    return ret.ret;
}

static int handle_lremovexattr(Context* ctx,
                               const char* path,
                               const char* name) {
    trace("lremovexattr(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetSSize ret = {0};
    CallXattr call = {.type = XATTRTYPE_REMOVE,
                      .type2 = XATTRTYPE_L,
                      .path = path,
                      .name = name,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

    return ret.ret;
}

static int handle_fremovexattr(Context* ctx, int fd, const char* name) {
    trace("fremovexattr(%d)\n", fd);

    RetSSize ret = {0};
    CallXattr call = {.type = XATTRTYPE_REMOVE,
                      .type2 = XATTRTYPE_F,
                      .fd = fd,
                      .name = name,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

    return ret.ret;
}

__attribute__((unused)) static int handle_rename(Context* ctx,
                                                 const char* oldpath,
                                                 const char* newpath) {
    trace("rename(%s, %s)\n", or_null(oldpath), or_null(newpath));

    if (!oldpath || !newpath) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallRename call = {.type = RENAMETYPE_PLAIN,
                       .oldpath = oldpath,
                       .newpath = newpath,
                       .ret = &ret};

    _next->rename(ctx, _next->rename_next, &call);

    return ret.ret;
}

static int handle_renameat(Context* ctx,
                           int olddirfd,
                           const char* oldpath,
                           int newdirfd,
                           const char* newpath) {
    trace("renameat(%s, %s)\n", or_null(oldpath), or_null(newpath));

    if (!oldpath || !newpath) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallRename call = {.type = RENAMETYPE_AT,
                       .olddirfd = olddirfd,
                       .oldpath = oldpath,
                       .newdirfd = newdirfd,
                       .newpath = newpath,
                       .ret = &ret};

    _next->rename(ctx, _next->rename_next, &call);

    return ret.ret;
}

static int handle_renameat2(Context* ctx,
                            int olddirfd,
                            const char* oldpath,
                            int newdirfd,
                            const char* newpath,
                            unsigned int flags) {
    trace("renameat2(%s, %s)\n", or_null(oldpath), or_null(newpath));

    if (!oldpath || !newpath) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallRename call = {.type = RENAMETYPE_AT2,
                       .olddirfd = olddirfd,
                       .oldpath = oldpath,
                       .newdirfd = newdirfd,
                       .newpath = newpath,
                       .flags = flags,
                       .ret = &ret};

    _next->rename(ctx, _next->rename_next, &call);

    return ret.ret;
}

static int handle_chdir(Context* ctx, const char* path) {
    trace("chdir(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallChdir call = {.f = 0, .path = path, .ret = &ret};

    _next->chdir(ctx, _next->chdir_next, &call);

    return ret.ret;
}

static int handle_fchdir(Context* ctx, int fd) {
    trace("fchdir(%d)\n", fd);

    RetInt ret = {0};
    CallChdir call = {.f = 1, .fd = fd, .ret = &ret};

    _next->chdir(ctx, _next->chdir_next, &call);

    return ret.ret;
}

static int handle_exit(Context* ctx, int status) {
    trace("exit(%u)\n", status);

    thread_exit(ctx->tls);

    sys_exit(status);
    return 0;
}

static int handle_exit_group(Context* ctx, int status) {
    trace("exit_group(%u)\n", status);

    thread_exit(ctx->tls);

    sys_exit_group(status);
    return 0;
}

__attribute__((unused)) static int handle_chmod(Context* ctx,
                                                const char* path,
                                                mode_t mode) {
    trace("chmod(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallChmod call = {
        .type = CHMODTYPE_PLAIN, .path = path, .mode = mode, .ret = &ret};

    _next->chmod(ctx, _next->chmod_next, &call);

    return ret.ret;
}

static int handle_fchmod(Context* ctx, int fd, mode_t mode) {
    trace("fchmod(%d)\n", fd);

    RetInt ret = {0};
    CallChmod call = {.type = CHMODTYPE_F, .fd = fd, .mode = mode, .ret = &ret};

    _next->chmod(ctx, _next->chmod_next, &call);

    return ret.ret;
}

static int handle_fchmodat(Context* ctx,
                           int dirfd,
                           const char* path,
                           mode_t mode) {
    trace("fchmodat(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallChmod call = {.type = CHMODTYPE_AT,
                      .dirfd = dirfd,
                      .path = path,
                      .mode = mode,
                      .ret = &ret};

    _next->chmod(ctx, _next->chmod_next, &call);

    return ret.ret;
}

static int handle_truncate(Context* ctx, const char* path, off_t length) {
    trace("truncate(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallTruncate call = {.f = 0, .path = path, .length = length, .ret = &ret};

    _next->truncate(ctx, _next->truncate_next, &call);

    return ret.ret;
}

static int handle_ftruncate(Context* ctx, int fd, off_t length) {
    trace("ftruncate(%d)\n", fd);

    RetInt ret = {0};
    CallTruncate call = {.f = 1, .fd = fd, .length = length, .ret = &ret};

    _next->truncate(ctx, _next->truncate_next, &call);

    return ret.ret;
}

__attribute__((unused)) static int handle_mkdir(Context* ctx,
                                                const char* path,
                                                mode_t mode) {
    trace("mkdir(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallMkdir call = {.at = 0, .path = path, .mode = mode, .ret = &ret};

    _next->mkdir(ctx, _next->mkdir_next, &call);

    return ret.ret;
}

static int handle_mkdirat(Context* ctx,
                          int dirfd,
                          const char* path,
                          mode_t mode) {
    trace("mkdirat(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallMkdir call = {
        .at = 1, .dirfd = dirfd, .path = path, .mode = mode, .ret = &ret};

    _next->mkdir(ctx, _next->mkdir_next, &call);

    return ret.ret;
}

__attribute__((unused)) static ssize_t handle_getdents(Context* ctx,
                                                       int fd,
                                                       void* dirp,
                                                       size_t count) {
    trace("getdents(%d)\n", fd);

    RetSSize ret = {0};
    CallGetdents call = {
        .is64 = 0, .fd = fd, .dirp = dirp, .count = count, .ret = &ret};

    _next->getdents(ctx, _next->getdents_next, &call);

    return ret.ret;
}

static ssize_t handle_getdents64(Context* ctx,
                                 int fd,
                                 void* dirp,
                                 size_t count) {
    trace("getdents64(%d)\n", fd);

    RetSSize ret = {0};
    CallGetdents call = {
        .is64 = 1, .fd = fd, .dirp = dirp, .count = count, .ret = &ret};

    _next->getdents(ctx, _next->getdents_next, &call);

    return ret.ret;
}

__attribute__((unused)) static int handle_mknod(Context* ctx,
                                                const char* path,
                                                mode_t mode,
                                                unsigned int dev) {
    trace("mknod(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallMknod call = {
        .at = 0, .path = path, .mode = mode, .dev = dev, .ret = &ret};

    _next->mknod(ctx, _next->mknod_next, &call);

    return ret.ret;
}

static int handle_mknodat(Context* ctx,
                          int dirfd,
                          const char* path,
                          mode_t mode,
                          unsigned int dev) {
    trace("mknodat(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallMknod call = {.at = 1,
                      .dirfd = dirfd,
                      .path = path,
                      .mode = mode,
                      .dev = dev,
                      .ret = &ret};

    _next->mknod(ctx, _next->mknod_next, &call);

    return ret.ret;
}

static int handle_accept(Context* ctx, int fd, void* addr, int* addrlen) {
    trace("accept()\n");

    RetInt ret = {0};
    CallAccept call = {
        .is4 = 0, .fd = fd, .addr = addr, .addrlen = addrlen, .ret = &ret};

    _next->accept(ctx, _next->accept_next, &call);

    return ret.ret;
}

static int handle_accept4(Context* ctx,
                          int fd,
                          void* addr,
                          int* addrlen,
                          int flags) {
    trace("accept4()\n");

    RetInt ret = {0};
    CallAccept call = {.is4 = 1,
                       .fd = fd,
                       .addr = addr,
                       .addrlen = addrlen,
                       .flags = flags,
                       .ret = &ret};

    _next->accept(ctx, _next->accept_next, &call);

    return ret.ret;
}

int handle_bind(Context* ctx, int fd, void* addr, int addrlen) {
    trace("bind()\n");

    RetInt ret = {0};
    CallConnect call = {
        .is_bind = 1, .fd = fd, .addr = addr, .addrlen = addrlen, .ret = &ret};

    _next->connect(ctx, _next->connect_next, &call);

    return ret.ret;
}

int handle_connect(Context* ctx, int fd, void* addr, int addrlen) {
    trace("connect()\n");

    RetInt ret = {0};
    CallConnect call = {
        .is_bind = 0, .fd = fd, .addr = addr, .addrlen = addrlen, .ret = &ret};

    _next->connect(ctx, _next->connect_next, &call);

    return ret.ret;
}

static int handle_fanotify_mark(Context* ctx,
                                int fanotify_fd,
                                unsigned int flags,
                                __u64 mask,
                                int dfd,
                                const char* pathname) {
    trace("fanotify_mark(%s)\n", or_null(pathname));

    if (!pathname) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallFanotifyMark call = {.fd = fanotify_fd,
                             .flags = flags,
                             .mask = mask,
                             .dirfd = dfd,
                             .path = pathname,
                             .ret = &ret};

    _next->fanotify_mark(ctx, _next->fanotify_mark_next, &call);

    return ret.ret;
}

static int handle_inotify_add_watch(Context* ctx,
                                    int fd,
                                    const char* pathname,
                                    __u32 mask) {
    trace("inotify_add_watch(%s)\n", or_null(pathname));

    if (!pathname) {
        return -EFAULT;
    }

    RetInt ret = {0};
    CallInotifyAddWatch call = {
        .fd = fd, .path = pathname, .mask = mask, .ret = &ret};

    _next->inotify_add_watch(ctx, _next->inotify_add_watch_next, &call);

    return ret.ret;
}

int handle_getrlimit(Context* ctx, unsigned int resource, void* old_rlim) {
    trace("getrlimit()\n");

    RetInt ret = {0};
    CallRlimit call = {.type = RLIMITTYPE_GET,
                       .resource = resource,
                       .old_rlim = old_rlim,
                       .ret = &ret};

    _next->rlimit(ctx, _next->rlimit_next, &call);

    return ret.ret;
}

int handle_setrlimit(Context* ctx,
                     unsigned int resource,
                     const void* new_rlim) {
    trace("setrlimit()\n");

    RetInt ret = {0};
    CallRlimit call = {.type = RLIMITTYPE_SET,
                       .resource = resource,
                       .new_rlim = new_rlim,
                       .ret = &ret};

    _next->rlimit(ctx, _next->rlimit_next, &call);

    return ret.ret;
}

int handle_prlimit64(Context* ctx,
                     pid_t pid,
                     unsigned int resource,
                     const void* new_rlim,
                     void* old_rlim) {
    trace("prlimit64()\n");

    RetInt ret = {0};
    CallRlimit call = {.type = RLIMITTYPE_PR,
                       .pid = pid,
                       .resource = resource,
                       .new_rlim = new_rlim,
                       .old_rlim = old_rlim,
                       .ret = &ret};

    _next->rlimit(ctx, _next->rlimit_next, &call);

    return ret.ret;
}

static long handle_ptrace(Context* ctx,
                          long request,
                          long pid,
                          void* addr,
                          void* data) {
    trace("ptrace()\n");

    RetLong ret = {0};
    CallPtrace call = {.request = request,
                       .pid = pid,
                       .addr = addr,
                       .data = data,
                       .ret = &ret};

    _next->ptrace(ctx, _next->ptrace_next, &call);

    return ret.ret;
}

int handle_kill(Context* ctx, pid_t pid, int sig) {
    trace("kill()\n");

    RetInt ret = {0};
    CallKill call = {.pid = pid, .sig = sig, .ret = &ret};

    _next->kill(ctx, _next->kill_next, &call);

    return ret.ret;
}

static int handle_close(Context* ctx, unsigned int fd) {
    trace("close(%u)\n", fd);

    RetInt ret = {0};
    CallClose call = {.is_range = 0, .fd = fd, .ret = &ret};

    _next->close(ctx, _next->close_next, &call);

    return ret.ret;
}

__attribute__((unused)) static int handle_close_range(Context* ctx,
                                                      unsigned int first,
                                                      unsigned int last,
                                                      unsigned int flags) {
    trace("close_range(%u, %u)\n", first, last);

    RetInt ret = {0};
    CallClose call = {.is_range = 1,
                      .fd = first,
                      .max_fd = last,
                      .flags = flags,
                      .ret = &ret};

    _next->close(ctx, _next->close_next, &call);

    return ret.ret;
}

static unsigned long handle_misc(Context* ctx, SysArgs* args) {
    trace("misc(%lu)\n", args->num);

    RetUL ret = {0};
    CallMisc call = {.args = *args, .ret = &ret};

    _next->misc(ctx, _next->misc_next, &call);

    return ret.ret;
}

static unsigned long handle_mmap(Context* ctx,
                                 unsigned long addr,
                                 unsigned long len,
                                 unsigned long prot,
                                 unsigned long flags,
                                 unsigned long fd,
                                 unsigned long off) {
    trace("mmap()\n");

    RetUL ret = {0};
    CallMmap call = {
        .addr = addr,
        .len = len,
        .prot = prot,
        .flags = flags,
        .fd = fd,
        .off = off,
        .ret = &ret,
    };

    _next->mmap(ctx, _next->mmap_next, &call);

    return ret.ret;
}

static unsigned long handle_syscall(Context* ctx, SysArgs* args) {
    ssize_t ret;

    switch (args->num) {
#ifdef __NR_open
        case __NR_open:
            ret = handle_open(ctx, (const char*)args->arg1, args->arg2,
                              args->arg3);
            break;
#endif

        case __NR_openat:
            ret = handle_openat(ctx, args->arg1, (const char*)args->arg2,
                                args->arg3, args->arg4);
            break;

#ifdef __NR_stat
        case __NR_stat:
            ret = handle_stat(ctx, (const char*)args->arg1, (void*)args->arg2);
            break;
#endif

        case __NR_fstat:
            ret = handle_fstat(ctx, args->arg1, (void*)args->arg2);
            break;

#ifdef __NR_lstat
        case __NR_lstat:
            ret = handle_lstat(ctx, (const char*)args->arg1, (void*)args->arg2);
            break;
#endif

        case __NR_newfstatat:
            ret = handle_newfstatat(ctx, args->arg1, (const char*)args->arg2,
                                    (void*)args->arg3, args->arg4);
            break;

        case __NR_statx:
            ret = handle_statx(ctx, args->arg1, (const char*)args->arg2,
                               args->arg3, args->arg4, (void*)args->arg5);
            break;

#ifdef __NR_readlink
        case __NR_readlink:
            ret = handle_readlink(ctx, (const char*)args->arg1,
                                  (char*)args->arg2, args->arg3);
            break;
#endif

        case __NR_readlinkat:
            ret = handle_readlinkat(ctx, args->arg1, (const char*)args->arg2,
                                    (char*)args->arg3, args->arg4);
            break;

#ifdef __NR_access
        case __NR_access:
            ret = handle_access(ctx, (const char*)args->arg1, args->arg2);
            break;
#endif

        case __NR_faccessat:
            ret = handle_faccessat(ctx, args->arg1, (const char*)args->arg2,
                                   args->arg3);
            break;

        case __NR_execve:
            ret = handle_execve(ctx, (const char*)args->arg1,
                                (char* const*)args->arg2,
                                (char* const*)args->arg3);
            break;

        case __NR_execveat:
            ret = handle_execveat(ctx, args->arg1, (const char*)args->arg2,
                                  (char* const*)args->arg3,
                                  (char* const*)args->arg4, args->arg5);
            break;

        case __NR_rt_sigprocmask:
            ret = handle_rt_sigprocmask(ctx, args->arg1,
                                        (const sigset_t*)args->arg2,
                                        (sigset_t*)args->arg3, args->arg4);
            break;

        case __NR_rt_sigaction:
            ret = handle_rt_sigaction(
                ctx, args->arg1, (const struct sigaction*)args->arg2,
                (struct sigaction*)args->arg3, args->arg4);
            break;

#ifdef __NR_link
        case __NR_link:
            ret = handle_link(ctx, (const char*)args->arg1,
                              (const char*)args->arg2);
            break;
#endif

        case __NR_linkat:
            ret =
                handle_linkat(ctx, args->arg1, (const char*)args->arg2,
                              args->arg3, (const char*)args->arg4, args->arg5);
            break;

#ifdef __NR_symlink
        case __NR_symlink:
            ret = handle_symlink(ctx, (const char*)args->arg1,
                                 (const char*)args->arg2);
            break;
#endif

        case __NR_symlinkat:
            ret = handle_symlinkat(ctx, (const char*)args->arg1, args->arg2,
                                   (const char*)args->arg3);
            break;

#ifdef __NR_unlink
        case __NR_unlink:
            ret = handle_unlink(ctx, (const char*)args->arg1);
            break;
#endif

        case __NR_unlinkat:
            ret = handle_unlinkat(ctx, args->arg1, (const char*)args->arg2,
                                  args->arg3);
            break;

        case __NR_setxattr:
            ret = handle_setxattr(
                ctx, (const char*)args->arg1, (const char*)args->arg2,
                (const void*)args->arg3, args->arg4, args->arg5);
            break;

        case __NR_lsetxattr:
            ret = handle_lsetxattr(
                ctx, (const char*)args->arg1, (const char*)args->arg2,
                (const void*)args->arg3, args->arg4, args->arg5);
            break;

        case __NR_fsetxattr:
            ret = handle_fsetxattr(ctx, args->arg1, (const char*)args->arg2,
                                   (const void*)args->arg3, args->arg4,
                                   args->arg5);
            break;

        case __NR_getxattr:
            ret = handle_getxattr(ctx, (const char*)args->arg1,
                                  (const char*)args->arg2, (void*)args->arg3,
                                  args->arg4);
            break;

        case __NR_lgetxattr:
            ret = handle_lgetxattr(ctx, (const char*)args->arg1,
                                   (const char*)args->arg2, (void*)args->arg3,
                                   args->arg4);
            break;

        case __NR_fgetxattr:
            ret = handle_fgetxattr(ctx, args->arg1, (const char*)args->arg2,
                                   (void*)args->arg3, args->arg4);
            break;

        case __NR_listxattr:
            ret = handle_listxattr(ctx, (const char*)args->arg1,
                                   (char*)args->arg2, args->arg3);
            break;

        case __NR_llistxattr:
            ret = handle_llistxattr(ctx, (const char*)args->arg1,
                                    (char*)args->arg2, args->arg3);
            break;

        case __NR_flistxattr:
            ret = handle_flistxattr(ctx, args->arg1, (char*)args->arg2,
                                    args->arg3);
            break;

        case __NR_removexattr:
            ret = handle_removexattr(ctx, (const char*)args->arg1,
                                     (const char*)args->arg2);
            break;

        case __NR_lremovexattr:
            ret = handle_lremovexattr(ctx, (const char*)args->arg1,
                                      (const char*)args->arg2);
            break;

        case __NR_fremovexattr:
            ret = handle_fremovexattr(ctx, args->arg1, (const char*)args->arg2);
            break;

#ifdef __NR_rename
        case __NR_rename:
            ret = handle_rename(ctx, (const char*)args->arg1,
                                (const char*)args->arg2);
            break;
#endif

        case __NR_renameat:
            ret = handle_renameat(ctx, args->arg1, (const char*)args->arg2,
                                  args->arg3, (const char*)args->arg4);
            break;

        case __NR_renameat2:
            ret = handle_renameat2(ctx, args->arg1, (const char*)args->arg2,
                                   args->arg3, (const char*)args->arg4,
                                   args->arg5);
            break;

        case __NR_chdir:
            ret = handle_chdir(ctx, (const char*)args->arg1);
            break;

        case __NR_fchdir:
            ret = handle_fchdir(ctx, args->arg1);
            break;

        case __NR_exit:
            ret = handle_exit(ctx, args->arg1);
            break;

        case __NR_exit_group:
            ret = handle_exit_group(ctx, args->arg1);
            break;

#ifdef __NR_chmod
        case __NR_chmod:
            ret = handle_chmod(ctx, (const char*)args->arg1, args->arg2);
            break;
#endif

        case __NR_fchmod:
            ret = handle_fchmod(ctx, args->arg1, args->arg2);
            break;

        case __NR_fchmodat:
            ret = handle_fchmodat(ctx, args->arg1, (const char*)args->arg2,
                                  args->arg3);
            break;

        case __NR_truncate:
            ret = handle_truncate(ctx, (const char*)args->arg1, args->arg2);
            break;

        case __NR_ftruncate:
            ret = handle_ftruncate(ctx, args->arg1, args->arg2);
            break;

#ifdef __NR_mkdir
        case __NR_mkdir:
            ret = handle_mkdir(ctx, (const char*)args->arg1, args->arg2);
            break;
#endif

        case __NR_mkdirat:
            ret = handle_mkdirat(ctx, args->arg1, (const char*)args->arg2,
                                 args->arg3);
            break;

#ifdef __NR_getdents
        case __NR_getdents:
            ret =
                handle_getdents(ctx, args->arg1, (void*)args->arg2, args->arg3);
            break;
#endif

        case __NR_getdents64:
            ret = handle_getdents64(ctx, args->arg1, (void*)args->arg2,
                                    args->arg3);
            break;

#ifdef __NR_mknod
        case __NR_mknod:
            ret = handle_mknod(ctx, (const char*)args->arg1, args->arg2,
                               args->arg3);
            break;
#endif

        case __NR_mknodat:
            ret = handle_mknodat(ctx, args->arg1, (const char*)args->arg2,
                                 args->arg3, args->arg4);
            break;

        case __NR_accept:
            ret = handle_accept(ctx, args->arg1, (void*)args->arg2,
                                (int*)args->arg3);
            break;

        case __NR_accept4:
            ret = handle_accept4(ctx, args->arg1, (void*)args->arg2,
                                 (int*)args->arg3, args->arg4);
            break;

        case __NR_bind:
            ret = handle_bind(ctx, args->arg1, (void*)args->arg2, args->arg3);
            break;

        case __NR_connect:
            ret =
                handle_connect(ctx, args->arg1, (void*)args->arg2, args->arg3);
            break;

        case __NR_fanotify_mark:
            ret = handle_fanotify_mark(ctx, args->arg1, args->arg2, args->arg3,
                                       args->arg4, (const char*)args->arg5);
            break;

        case __NR_inotify_add_watch:
            ret = handle_inotify_add_watch(ctx, args->arg1,
                                           (const char*)args->arg2, args->arg3);
            break;

        case __NR_getrlimit:
            ret = handle_getrlimit(ctx, args->arg1, (void*)args->arg2);
            break;

        case __NR_setrlimit:
            ret = handle_setrlimit(ctx, args->arg1, (const void*)args->arg2);
            break;

        case __NR_prlimit64:
            ret = handle_prlimit64(ctx, args->arg1, args->arg2,
                                   (const void*)args->arg3, (void*)args->arg4);
            break;

        case __NR_ptrace:
            ret = handle_ptrace(ctx, args->arg1, args->arg2, (void*)args->arg3,
                                (void*)args->arg4);
            break;

        case __NR_kill:
            ret = handle_kill(ctx, args->arg1, args->arg2);
            break;

        case __NR_close:
            ret = handle_close(ctx, args->arg1);
            break;

#ifdef __NR_close_range
        case __NR_close_range:
            ret = handle_close_range(ctx, args->arg1, args->arg2, args->arg3);
            break;
#endif

        case __NR_mmap:
            ret = handle_mmap(ctx, args->arg1, args->arg2, args->arg3,
                              args->arg4, args->arg5, args->arg6);
            break;

        default:
            ret = handle_misc(ctx, args);
            break;
    }

    return ret;
}

static int bottom_open(Context* ctx, const This* this, const CallOpen* call) {
    int ret;
    RetInt* _ret = call->ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    if (call->at) {
        ret = sys_openat(call->dirfd, call->path, call->flags, call->mode);
    } else {
        ret = sys_open(call->path, call->flags, call->mode);
    }

    _ret->ret = ret;
    return ret;
}

static int bottom_stat(Context* ctx, const This* this, const CallStat* call) {
    int ret;
    RetInt* _ret = call->ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
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
                            call->statbuf);
            break;

        default:
            abort();
            break;
    }

    _ret->ret = ret;
    return ret;
}

static ssize_t bottom_readlink(Context* ctx,
                               const This* this,
                               const CallReadlink* call) {
    ssize_t ret;
    RetSSize* _ret = call->ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    if (call->at) {
        ret = sys_readlinkat(call->dirfd, call->path, call->buf, call->bufsiz);
    } else {
        ret = sys_readlink(call->path, call->buf, call->bufsiz);
    }

    _ret->ret = ret;
    return ret;
}

static int bottom_access(Context* ctx,
                         const This* this,
                         const CallAccess* call) {
    int ret;
    RetInt* _ret = call->ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    if (call->at) {
        ret = sys_faccessat(call->dirfd, call->path, call->mode);
    } else {
        ret = sys_access(call->path, call->mode);
    }

    _ret->ret = ret;
    return ret;
}

static int _bottom_exec(Context* ctx, const This* this, CallExec* call) {
    ssize_t ret;
    int64_t argc;
    int dirfd = (call->at ? call->dirfd : AT_FDCWD);

    argc = array_len(call->argv);
    if (argc < 0) {
        return -E2BIG;
    }

    ret = concatat(&ctx->tls->cache, NULL, 0, dirfd, call->path);
    if (ret < 0) {
        return ret;
    }
    if (ret > SCRATCH_SIZE) {
        return -ENAMETOOLONG;
    }

    char fullpath[ret];
    ret = concatat(&ctx->tls->cache, fullpath, ret, dirfd, call->path);
    if (ret < 0) {
        abort();
    }

    if (call->at && call->flags & AT_EMPTY_PATH) {
        fullpath[ret - 2] = '\0';
    }

    char* new_argv[argc > 1 ? 2 + argc : 3];
    new_argv[0] = (char*)"loader_recurse";
    new_argv[1] = (char*)fullpath;
    if (argc > 1) {
        array_copy(new_argv + 2, call->argv + 1, argc);
    } else {
        new_argv[2] = NULL;
    }
    call->path = "/proc/self/exe";
    call->argv = new_argv;

    // TODO: What if execve fails?
    thread_exit_exec(ctx->tls);
    ctx->tls = NULL;

    ret = sys_execve(call->path, call->argv, call->envp);

    call->ret->ret = ret;
    return ret;
}

static int line_size(char* buf, ssize_t size) {
    for (int i = 0; i < size; i++) {
        if (buf[i] == '\r' || buf[i] == '\n') {
            return i + 1;
        }
    }

    return -ENOEXEC;
}

static int read_header(char* out, size_t out_len, int fd) {
    ssize_t ret;
    const size_t scratch_size = (12 * 1024);
    char scratch[scratch_size];

    if (out && !out_len) {
        abort();
    }

    ret = sys_lseek(fd, 0, SEEK_SET);
    if (ret < 0) {
        return ret;
    }

    if (out) {
        ret = read_full(fd, out, out_len);
        if (ret < 0) {
            return ret;
        }

        out[ret - 1] = '\0';
        return ret;
    } else {
        ret = read_full(fd, scratch, scratch_size);
        if (ret < 0) {
            return ret;
        }

        if (ret < 2) {
            return -ENOEXEC;
        }

        if (scratch[0] == '#' && scratch[1] == '!') {
            ret = line_size(scratch, scratch_size);
            if (ret < 0) {
                return ret;
            }
        } else {
            ret = 0;
        }

        return max(ret, (ssize_t)sizeof(Elf_Ehdr)) + 1;
    }
}

static int open_fullpath_execveat(Context* ctx, const CallExec* call) {
    ssize_t ret;
    int flags = 0;
    int dirfd = (call->at ? call->dirfd : AT_FDCWD);

    ret = concatat(&ctx->tls->cache, NULL, 0, dirfd, call->path);
    if (ret < 0) {
        return ret;
    }
    if (ret > SCRATCH_SIZE) {
        return -ENAMETOOLONG;
    }

    char fullpath[ret];
    ret = concatat(&ctx->tls->cache, fullpath, ret, dirfd, call->path);
    if (ret < 0) {
        abort();
    }

    if (call->at && call->flags & AT_EMPTY_PATH) {
        fullpath[ret - 2] = '\0';
    }
    if (call->at && call->flags & AT_SYMLINK_NOFOLLOW) {
        flags |= O_NOFOLLOW;
    }

    ret = sys_faccessat(dirfd, call->path, X_OK);
    if (ret < 0) {
        return ret;
    }

    ret = sys_openat(dirfd, call->path, flags | O_RDONLY | O_CLOEXEC, 0);
    if (ret < 0) {
        return ret;
    }

    return ret;
}

static int bottom_exec(Context* ctx, const This* this, const CallExec* call) {
    int fd;
    ssize_t ret, size;
    RetInt* _ret = call->ret;
    int64_t exec_argc;
    CallExec _call;
    callexec_copy(&_call, call);

    if (0) {
    out:
        return _ret->ret;
    }

    if (call->final) {
        return _bottom_exec(ctx, this, &_call);
    }

    exec_argc = array_len(call->argv);
    if (exec_argc < 0) {
        _ret->ret = -E2BIG;
        goto out;
    }

    ret = open_fullpath_execveat(ctx, call);
    if (ret < 0) {
        _ret->ret = ret;
        goto out;
    }
    fd = ret;

    ret = read_header(NULL, 0, fd);
    if (ret < 0) {
        _ret->ret = ret;
        sys_close(fd);
        goto out;
    }
    size = ret;

    char header[size];
    ret = read_header(header, size, fd);
    if (ret < 0) {
        _ret->ret = ret;
        sys_close(fd);
        goto out;
    }
    sys_close(fd);

    if (header[0] == '#' && header[1] == '!') {
        int sh_argc = cmdline_argc(header, size);
        if (sh_argc == 0) {
            _ret->ret = -ENOEXEC;
            goto out;
        }

        int64_t argc = exec_argc + sh_argc;
        char* argv[argc + 1];

        cmdline_extract(header, size, argv);
        array_copy(argv + sh_argc, call->argv, exec_argc);
        argv[sh_argc] = (char*)call->path;
        argv[argc] = NULL;
        const char* pathname = argv[0];

        debug_exec(pathname, argv, call->envp);

        _call.path = pathname;
        _call.argv = argv;

        return _next->exec(ctx, _next->exec_next, &_call);
    }

    if ((size_t)size < sizeof(Elf_Ehdr) || !check_ehdr((Elf_Ehdr*)header)) {
        _ret->ret = -ENOEXEC;
        goto out;
    }

    _call.final = 1;
    _next->exec(ctx, _next->exec_next, &_call);

    return _ret->ret;
}

static int bottom_link(Context* ctx, const This* this, const CallLink* call) {
    int ret;
    RetInt* _ret = call->ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    if (call->at) {
        ret = sys_linkat(call->olddirfd, call->oldpath, call->newdirfd,
                         call->newpath, call->flags);
    } else {
        ret = sys_link(call->oldpath, call->newpath);
    }

    _ret->ret = ret;
    return ret;
}

static int bottom_symlink(Context* ctx,
                          const This* this,
                          const CallLink* call) {
    int ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    if (call->at) {
        ret = sys_symlinkat(call->oldpath, call->newdirfd, call->newpath);
    } else {
        ret = sys_symlink(call->oldpath, call->newpath);
    }

    call->ret->ret = ret;
    return ret;
}

static int bottom_unlink(Context* ctx,
                         const This* this,
                         const CallUnlink* call) {
    int ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    if (call->at) {
        ret = sys_unlinkat(call->dirfd, call->path, call->flags);
    } else {
        ret = sys_unlink(call->path);
    }

    call->ret->ret = ret;
    return ret;
}

static int bottom_setxattr(Context* ctx,
                           const This* this,
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

    call->ret->ret = ret;
    return ret;
}

static ssize_t bottom_getxattr(Context* ctx,
                               const This* this,
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

    call->ret->ret = ret;
    return ret;
}

static ssize_t bottom_listxattr(Context* ctx,
                                const This* this,
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

    call->ret->ret = ret;
    return ret;
}

static int bottom_removexattr(Context* ctx,
                              const This* this,
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

    call->ret->ret = ret;
    return ret;
}

static ssize_t bottom_xattr(Context* ctx,
                            const This* this,
                            const CallXattr* call) {
    signalmanager_sigsys_mask_until_sigreturn(ctx);
    switch (call->type) {
        case XATTRTYPE_SET:
            return bottom_setxattr(ctx, this, call);
            break;

        case XATTRTYPE_GET:
            return bottom_getxattr(ctx, this, call);
            break;

        case XATTRTYPE_LIST:
            return bottom_listxattr(ctx, this, call);
            break;

        case XATTRTYPE_REMOVE:
            return bottom_removexattr(ctx, this, call);
            break;

        default:
            abort();
            break;
    }
}

static int bottom_rename(Context* ctx,
                         const This* this,
                         const CallRename* call) {
    int ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
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

    call->ret->ret = ret;
    return ret;
}

static int bottom_chdir(Context* ctx, const This* this, const CallChdir* call) {
    int ret;
    RetInt* _ret = call->ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    if (call->f) {
        ret = sys_fchdir(call->fd);
    } else {
        ret = sys_chdir(call->path);
    }

    _ret->ret = ret;
    return ret;
}

static int bottom_chmod(Context* ctx, const This* this, const CallChmod* call) {
    int ret;
    RetInt* _ret = call->ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
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

    _ret->ret = ret;
    return ret;
}

static int bottom_truncate(Context* ctx,
                           const This* this,
                           const CallTruncate* call) {
    int ret;
    RetInt* _ret = call->ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    if (call->f) {
        ret = sys_ftruncate(call->fd, call->length);
    } else {
        ret = sys_truncate(call->path, call->length);
    }

    _ret->ret = ret;
    return ret;
}

static int bottom_mkdir(Context* ctx, const This* this, const CallMkdir* call) {
    int ret;
    RetInt* _ret = call->ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    if (call->at) {
        ret = sys_mkdirat(call->dirfd, call->path, call->mode);
    } else {
        ret = sys_mkdir(call->path, call->mode);
    }

    _ret->ret = ret;
    return ret;
}

static ssize_t bottom_getdents(Context* ctx,
                               const This* this,
                               const CallGetdents* call) {
    ssize_t ret;
    RetSSize* _ret = call->ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    if (call->is64) {
        ret = sys_getdents64(call->fd, call->dirp, call->count);
    } else {
        ret = sys_getdents(call->fd, call->dirp, call->count);
    }

    _ret->ret = ret;
    return ret;
}

static int bottom_mknod(Context* ctx, const This* this, const CallMknod* call) {
    int ret;
    RetInt* _ret = call->ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    if (call->at) {
        ret = sys_mknodat(call->dirfd, call->path, call->mode, call->dev);
    } else {
        ret = sys_mknod(call->path, call->mode, call->dev);
    }

    _ret->ret = ret;
    return ret;
}

static int bottom_accept(Context* ctx,
                         const This* this,
                         const CallAccept* call) {
    int ret;
    RetInt* _ret = call->ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    if (call->is4) {
        ret = sys_accept4(call->fd, call->addr, call->addrlen, call->flags);
    } else {
        ret = sys_accept(call->fd, call->addr, call->addrlen);
    }

    _ret->ret = ret;
    return ret;
}

static int bottom_connect(Context* ctx,
                          const This* this,
                          const CallConnect* call) {
    int ret;
    RetInt* _ret = call->ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    if (call->is_bind) {
        ret = sys_bind(call->fd, call->addr, call->addrlen);
    } else {
        ret = sys_connect(call->fd, call->addr, call->addrlen);
    }

    _ret->ret = ret;
    return ret;
}

static int bottom_fanotify_mark(Context* ctx,
                                const This* this,
                                const CallFanotifyMark* call) {
    int ret;
    RetInt* _ret = call->ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    ret = sys_fanotify_mark(call->fd, call->flags, call->mask, call->dirfd,
                            call->path);

    _ret->ret = ret;
    return ret;
}

static int bottom_inotify_add_watch(Context* ctx,
                                    const This* this,
                                    const CallInotifyAddWatch* call) {
    int ret;
    RetInt* _ret = call->ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    ret = sys_inotify_add_watch(call->fd, call->path, call->mask);

    _ret->ret = ret;
    return ret;
}

static int bottom_rlimit(Context* ctx,
                         const This* this,
                         const CallRlimit* call) {
    int ret;
    RetInt* _ret = call->ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    switch (call->type) {
        case RLIMITTYPE_GET:
            ret = sys_getrlimit(call->resource, call->old_rlim);
            break;

        case RLIMITTYPE_SET:
            ret = sys_setrlimit(call->resource, call->new_rlim);
            break;

        case RLIMITTYPE_PR:
            ret = sys_prlimit64(call->pid, call->resource, call->new_rlim,
                                call->old_rlim);
            break;

        default:
            abort();
            break;
    }

    _ret->ret = ret;
    return ret;
}

static long bottom_ptrace(Context* ctx,
                          const This* this,
                          const CallPtrace* call) {
    long ret;
    RetLong* _ret = call->ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    ret = sys_ptrace(call->request, call->pid, call->addr, call->data);

    _ret->ret = ret;
    return ret;
}

static int bottom_kill(Context* ctx, const This* this, const CallKill* call) {
    int ret;
    RetInt* _ret = call->ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    ret = sys_kill(call->pid, call->sig);

    _ret->ret = ret;
    return ret;
}

static int bottom_close(Context* ctx, const This* this, const CallClose* call) {
    int ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    if (call->is_range) {
        ret = sys_close_range(call->fd, call->max_fd, call->flags);
    } else {
        ret = sys_close(call->fd);
    }

    call->ret->ret = ret;
    return ret;
}

static unsigned long bottom_misc(Context* ctx,
                                 const This* this,
                                 const CallMisc* call) {
    debug("Unhandled syscall no. %lu\n", call->args.num);

    call->ret->ret = -ENOSYS;
    return call->ret->ret;
}

static unsigned long bottom_mmap(Context* ctx,
                                 const This* this,
                                 const CallMmap* call) {
    unsigned long ret;
    RetUL* _ret = call->ret;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    ret = (unsigned long)sys_mmap((void*)call->addr, call->len, call->prot,
                                  call->flags, call->fd, call->off);

    _ret->ret = ret;
    return ret;
}

static const CallHandler bottom = {
    bottom_open,
    NULL,
    bottom_stat,
    NULL,
    bottom_readlink,
    NULL,
    bottom_access,
    NULL,
    bottom_exec,
    NULL,
    bottom_link,
    NULL,
    bottom_symlink,
    NULL,
    bottom_unlink,
    NULL,
    bottom_xattr,
    NULL,
    bottom_rename,
    NULL,
    bottom_chdir,
    NULL,
    bottom_chmod,
    NULL,
    bottom_truncate,
    NULL,
    bottom_mkdir,
    NULL,
    bottom_getdents,
    NULL,
    bottom_mknod,
    NULL,
    bottom_accept,
    NULL,
    bottom_connect,
    NULL,
    bottom_fanotify_mark,
    NULL,
    bottom_inotify_add_watch,
    NULL,
    bottom_rlimit,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    bottom_ptrace,
    NULL,
    bottom_kill,
    NULL,
    bottom_close,
    NULL,
    bottom_misc,
    NULL,
    bottom_mmap,
    NULL,
};
