#pragma once

#include "base_types.h"
#include "myseccomp.h"
#include "syscalls_a.h"
#include "syscalls_b.h"
#include "syscalls_c.h"
#include "syscalls_exec.h"

#include <syscall.h>

static int handle_exit(Context* ctx, SysArgs* args);
static int handle_exit_group(Context* ctx, SysArgs* args);

__attribute__((unused)) unsigned long handle_syscall(Context* ctx,
                                                     SysArgs* args) {
    unsigned long ret;

    switch (args->num) {
#ifdef __NR_open
        case __NR_open:
            ret = handle_open(ctx, args);
            break;
#endif

        case __NR_openat:
            ret = handle_openat(ctx, args);
            break;

#ifdef __NR_stat
        case __NR_stat:
            ret = handle_stat(ctx, args);
            break;
#endif

        case __NR_fstat:
            ret = handle_fstat(ctx, args);
            break;

#ifdef __NR_lstat
        case __NR_lstat:
            ret = handle_lstat(ctx, args);
            break;
#endif

        case __NR_newfstatat:
            ret = handle_newfstatat(ctx, args);
            break;

        case __NR_statx:
            ret = handle_statx(ctx, args);
            break;

#ifdef __NR_readlink
        case __NR_readlink:
            ret = handle_readlink(ctx, args);
            break;
#endif

        case __NR_readlinkat:
            ret = handle_readlinkat(ctx, args);
            break;

#ifdef __NR_access
        case __NR_access:
            ret = handle_access(ctx, args);
            break;
#endif

        case __NR_faccessat:
            ret = handle_faccessat(ctx, args);
            break;

        case __NR_execve:
            ret = handle_execve(ctx, args);
            break;

        case __NR_execveat:
            ret = handle_execveat(ctx, args);
            break;

        case __NR_rt_sigprocmask:
            ret = handle_rt_sigprocmask(ctx, args);
            break;

        case __NR_rt_sigaction:
            ret = handle_rt_sigaction(ctx, args);
            break;

#ifdef __NR_link
        case __NR_link:
            ret = handle_link(ctx, args);
            break;
#endif

        case __NR_linkat:
            ret = handle_linkat(ctx, args);
            break;

#ifdef __NR_symlink
        case __NR_symlink:
            ret = handle_symlink(ctx, args);
            break;
#endif

        case __NR_symlinkat:
            ret = handle_symlinkat(ctx, args);
            break;

#ifdef __NR_unlink
        case __NR_unlink:
            ret = handle_unlink(ctx, args);
            break;
#endif

        case __NR_unlinkat:
            ret = handle_unlinkat(ctx, args);
            break;

        case __NR_setxattr:
            ret = handle_setxattr(ctx, args);
            break;

        case __NR_lsetxattr:
            ret = handle_lsetxattr(ctx, args);
            break;

        case __NR_fsetxattr:
            ret = handle_fsetxattr(ctx, args);
            break;

        case __NR_getxattr:
            ret = handle_getxattr(ctx, args);
            break;

        case __NR_lgetxattr:
            ret = handle_lgetxattr(ctx, args);
            break;

        case __NR_fgetxattr:
            ret = handle_fgetxattr(ctx, args);
            break;

        case __NR_listxattr:
            ret = handle_listxattr(ctx, args);
            break;

        case __NR_llistxattr:
            ret = handle_llistxattr(ctx, args);
            break;

        case __NR_flistxattr:
            ret = handle_flistxattr(ctx, args);
            break;

        case __NR_removexattr:
            ret = handle_removexattr(ctx, args);
            break;

        case __NR_lremovexattr:
            ret = handle_lremovexattr(ctx, args);
            break;

        case __NR_fremovexattr:
            ret = handle_fremovexattr(ctx, args);
            break;

#ifdef __NR_rename
        case __NR_rename:
            ret = handle_rename(ctx, args);
            break;
#endif

        case __NR_renameat:
            ret = handle_renameat(ctx, args);
            break;

        case __NR_renameat2:
            ret = handle_renameat2(ctx, args);
            break;

        case __NR_chdir:
            ret = handle_chdir(ctx, args);
            break;

        case __NR_fchdir:
            ret = handle_fchdir(ctx, args);
            break;

        case __NR_exit:
            ret = handle_exit(ctx, args);
            break;

        case __NR_exit_group:
            ret = handle_exit_group(ctx, args);
            break;

#ifdef __NR_chmod
        case __NR_chmod:
            ret = handle_chmod(ctx, args);
            break;
#endif

        case __NR_fchmod:
            ret = handle_fchmod(ctx, args);
            break;

        case __NR_fchmodat:
            ret = handle_fchmodat(ctx, args);
            break;

        case __NR_truncate:
            ret = handle_truncate(ctx, args);
            break;

        case __NR_ftruncate:
            ret = handle_ftruncate(ctx, args);
            break;

#ifdef __NR_mkdir
        case __NR_mkdir:
            ret = handle_mkdir(ctx, args);
            break;
#endif

        case __NR_mkdirat:
            ret = handle_mkdirat(ctx, args);
            break;

#ifdef __NR_getdents
        case __NR_getdents:
            ret = handle_getdents(ctx, args);
            break;
#endif

        case __NR_getdents64:
            ret = handle_getdents64(ctx, args);
            break;

#ifdef __NR_mknod
        case __NR_mknod:
            ret = handle_mknod(ctx, args);
            break;
#endif

        case __NR_mknodat:
            ret = handle_mknodat(ctx, args);
            break;

        case __NR_accept:
            ret = handle_accept(ctx, args);
            break;

        case __NR_accept4:
            ret = handle_accept4(ctx, args);
            break;

        case __NR_bind:
            ret = handle_bind(ctx, args);
            break;

        case __NR_connect:
            ret = handle_connect(ctx, args);
            break;

        case __NR_fanotify_mark:
            ret = handle_fanotify_mark(ctx, args);
            break;

        case __NR_inotify_add_watch:
            ret = handle_inotify_add_watch(ctx, args);
            break;

        case __NR_getrlimit:
            ret = handle_getrlimit(ctx, args);
            break;

        case __NR_setrlimit:
            ret = handle_setrlimit(ctx, args);
            break;

        case __NR_prlimit64:
            ret = handle_prlimit64(ctx, args);
            break;

        case __NR_ptrace:
            ret = handle_ptrace(ctx, args);
            break;

        case __NR_kill:
            ret = handle_kill(ctx, args);
            break;

        case __NR_close:
            ret = handle_close(ctx, args);
            break;

#ifdef __NR_close_range
        case __NR_close_range:
            ret = handle_close_range(ctx, args);
            break;
#endif

        case __NR_mmap:
            ret = handle_mmap(ctx, args);
            break;

#ifdef __NR_fork
        case __NR_fork:
            ret = handle_fork(ctx, args);
            break;
#endif

#ifdef __NR_vfork
        case __NR_vfork:
            ret = handle_vfork(ctx, args);
            break;
#endif

        case __NR_clone:
            ret = handle_clone(ctx, args);
            break;

        case __NR_clone3:
            ret = handle_clone3(ctx, args);
            break;

        case __NR_read:
            ret = handle_read(ctx, args);
            break;

        case __NR_pread64:
            ret = handle_pread64(ctx, args);
            break;

        case __NR_preadv:
            ret = handle_preadv(ctx, args);
            break;

        case __NR_preadv2:
            ret = handle_preadv2(ctx, args);
            break;

        default:
            ret = handle_misc(ctx, args);
            break;
    }

    return ret;
}
