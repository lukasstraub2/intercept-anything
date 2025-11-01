#include "intercept.h"
#include "syscalls_exec.h"
#include "util.h"
#include "myelf.h"
#include "loader.h"
#include "signalmanager.h"
#include "bottomhandler.h"

#define DEBUG_ENV "DEBUG_INTERCEPT"
#include "debug.h"

#include <string.h>

unsigned long handle_execve(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    char* const* argv = (char* const*)args->arg2;
    char* const* envp = (char* const*)args->arg3;
    trace("execve(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    int ret = {0};
    CallExec call;
    call.at = 0;
    call.path = path;
    call.argv = argv;
    call.envp = envp;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_execveat(Context* ctx, SysArgs* args) {
    int dirfd = args->arg1;
    const char* path = (const char*)args->arg2;
    char* const* argv = (char* const*)args->arg3;
    char* const* envp = (char* const*)args->arg4;
    int flags = args->arg5;
    trace("exeveat(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    int ret = {0};
    CallExec call;
    call.at = 1;
    call.dirfd = dirfd;
    call.path = path;
    call.argv = argv;
    call.envp = envp;
    call.flags = flags;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
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

    trace(": recurse execve(%s, [ ", pathname ? pathname : "nullptr");

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

static int _bottom_exec(Context* ctx, CallExec* call) {
    ssize_t ret;
    int64_t argc;
    int dirfd = (call->at ? call->dirfd : AT_FDCWD);

    argc = array_len(call->argv);
    if (argc < 0) {
        return -E2BIG;
    }

    ret = concatat(&ctx->tls->cache, nullptr, 0, dirfd, call->path);
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
        new_argv[2] = nullptr;
    }
    call->path = "/proc/self/exe";
    call->argv = new_argv;

    // TODO: What if execve fails?
    thread_exit_exec(ctx->tls);
    ctx->tls = nullptr;

    signalmanager_enable_signals(ctx);
    ret = sys_execve(call->path, call->argv, call->envp);
    signalmanager_disable_signals(ctx);

    *call->ret = ret;
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

    ret = concatat(&ctx->tls->cache, nullptr, 0, dirfd, call->path);
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

void BottomHandler::next(Context* ctx, const CallExec* call) {
    int fd;
    ssize_t ret, size;
    int* _ret = call->ret;
    int64_t exec_argc;
    CallExec _call = *call;

    if (call->final) {
        *_ret = _bottom_exec(ctx, &_call);
        return;
    }

    exec_argc = array_len(call->argv);
    if (exec_argc < 0) {
        *_ret = -E2BIG;
        return;
    }

    ret = open_fullpath_execveat(ctx, call);
    if (ret < 0) {
        *_ret = ret;
        return;
    }
    fd = ret;

    ret = read_header(nullptr, 0, fd);
    if (ret < 0) {
        *_ret = ret;
        sys_close(fd);
        return;
    }
    size = ret;

    char header[size];
    ret = read_header(header, size, fd);
    if (ret < 0) {
        *_ret = ret;
        sys_close(fd);
        return;
    }
    sys_close(fd);

    if (header[0] == '#' && header[1] == '!') {
        int sh_argc = cmdline_argc(header, size);
        if (sh_argc == 0) {
            *_ret = -ENOEXEC;
            return;
        }

        int64_t argc = exec_argc + sh_argc;
        char* argv[argc + 1];

        cmdline_extract(header, size, argv);
        array_copy(argv + sh_argc, call->argv, exec_argc);
        argv[sh_argc] = (char*)(const char*)call->path;
        argv[argc] = nullptr;
        const char* pathname = argv[0];

        debug_exec(pathname, argv, call->envp);

        _call.path = pathname;
        _call.argv = argv;

        intercept_entrypoint->next(ctx, &_call);
    }

    if ((size_t)size < sizeof(Elf_Ehdr) || !check_ehdr((Elf_Ehdr*)header)) {
        *_ret = -ENOEXEC;
        return;
    }

    _call.final = 1;
    intercept_entrypoint->next(ctx, &_call);
}