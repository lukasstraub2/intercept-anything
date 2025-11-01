#pragma once

#include "base_types.h"
#include "myseccomp.h"
#include "syscalls.h"

#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>

class CallSigprocmask {
    public:
    int how{};
    const sigset_t* set{};
    sigset_t* oldset{};
    size_t sigsetsize{};
    int* ret{};
};

class CallSigaction {
    public:
    int signum{};
    const struct k_sigaction* act{};
    struct k_sigaction* oldact{};
    size_t sigsetsize{};
    int* ret{};
};

class CallAccept {
    public:
    int is4{};
    int fd{};
    void* addr{};
    int* addrlen{};
    int flags{};
    int* ret{};

    CallAccept() = default;

    CallAccept(const CallAccept* call) {
        this->is4 = call->is4;
        this->fd = call->fd;
        this->addr = call->addr;
        this->addrlen = call->addrlen;
        if (call->is4) {
            this->flags = call->flags;
        }
        this->ret = call->ret;
    }
};

class CallConnect : public ICallPathConnect {
    public:
    int is_bind{};
    int fd{};
    MyBlob addr{};
    int addrlen{};
    int* ret{};

    sa_family_t get_family() const override {
        return *(sa_family_t*)(void*)this->addr;
    }

    void* get_addr() const override { return this->addr; }

    void set_addr(void* addr, size_t size) override {
        this->addr.dup(addr, size);
    }
};

class CallFanotifyMark : public ICallPathFanotify {
    public:
    int fd{};
    unsigned int flags{};
    uint64_t mask{};
    int dirfd{};
    MyString path{};
    int* ret{};

    int get_dirfd() const override { return this->dirfd; }

    const char* get_path() const override { return this->path; }

    unsigned int get_flags() const override { return this->flags; }

    void set_dirfd(int dirfd) override { this->dirfd = dirfd; }

    void set_path(const char* path) override { this->path.dup(path); }

    void set_flags(unsigned int flags) override { this->flags = flags; }
};

class CallInotifyAddWatch : public ICallPath {
    public:
    int fd{};
    MyString path{};
    uint64_t mask{};
    int* ret{};

    int is_l() const override { return 0; }

    int get_dirfd() const override { return 0; }

    const char* get_path() const override { return this->path; }

    int get_flags() const override { return 0; }

    void clear_l() override {}

    void set_dirfd(int dirfd) override {
        if (dirfd != AT_FDCWD) {
            abort();
        }
    }

    void set_path(const char* path) override { this->path.dup(path); }

    void set_flags(int flags) override {}
};

enum RlimitType { RLIMITTYPE_GET, RLIMITTYPE_SET, RLIMITTYPE_PR };
typedef enum RlimitType RlimitType;

class CallRlimit {
    public:
    RlimitType type{};
    pid_t pid{};
    unsigned int resource{};
    const void* new_rlim{};
    void* old_rlim{};
    int* ret{};

    CallRlimit() = default;

    CallRlimit(const CallRlimit* call) {
        this->type = call->type;

        if (call->type == RLIMITTYPE_PR) {
            this->pid = call->pid;
        }

        this->resource = call->resource;

        if (call->type == RLIMITTYPE_PR || call->type == RLIMITTYPE_SET) {
            this->new_rlim = call->new_rlim;
        }

        if (call->type == RLIMITTYPE_PR || call->type == RLIMITTYPE_GET) {
            this->old_rlim = call->old_rlim;
        }

        this->ret = call->ret;
    }
};

class CallPtrace {
    public:
    long request{};
    long pid{};
    void* addr{};
    void* data{};
    long* ret{};
};

class CallKill {
    public:
    pid_t pid{};
    int sig{};
    int* ret{};
};

class CallMisc {
    public:
    SysArgs args{};
    unsigned long* ret{};
};

class CallMmap {
    public:
    unsigned long addr{};
    unsigned long len{};
    unsigned long prot{};
    unsigned long flags{};
    unsigned long fd{};
    unsigned long off{};
    unsigned long* ret{};
};

enum CloneType {
    CLONETYPE_FORK,
    CLONETYPE_VFORK,
    CLONETYPE_CLONE,
    CLONETYPE_CLONE3
};
typedef CloneType CloneType;

class CallClone {
    public:
    CloneType type{};
    struct clone_args* args{};
    size_t size{};
    int* ret{};

    CallClone() = default;

    CallClone(const CallClone* call) {
        this->type = call->type;
        if (call->type >= CLONETYPE_CLONE) {
            this->args = call->args;
            this->size = call->size;
        }
        this->ret = call->ret;
    }
};

unsigned long handle_rt_sigprocmask(Context* ctx, SysArgs* args);
unsigned long handle_rt_sigaction(Context* ctx, SysArgs* args);
unsigned long handle_accept(Context* ctx, SysArgs* args);
unsigned long handle_accept4(Context* ctx, SysArgs* args);
unsigned long handle_bind(Context* ctx, SysArgs* args);
unsigned long handle_connect(Context* ctx, SysArgs* args);
unsigned long handle_fanotify_mark(Context* ctx, SysArgs* args);
unsigned long handle_inotify_add_watch(Context* ctx, SysArgs* args);
unsigned long handle_getrlimit(Context* ctx, SysArgs* args);
unsigned long handle_setrlimit(Context* ctx, SysArgs* args);
unsigned long handle_prlimit64(Context* ctx, SysArgs* args);
unsigned long handle_ptrace(Context* ctx, SysArgs* args);
unsigned long handle_kill(Context* ctx, SysArgs* args);
unsigned long handle_misc(Context* ctx, SysArgs* args);
unsigned long handle_mmap(Context* ctx, SysArgs* args);
unsigned long handle_fork(Context* ctx, SysArgs* args);
unsigned long handle_vfork(Context* ctx, SysArgs* args);
unsigned long handle_clone(Context* ctx, SysArgs* args);
unsigned long handle_clone3(Context* ctx, SysArgs* args);