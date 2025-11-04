#pragma once

#include "base_types.h"
#include "myseccomp.h"
#include "syscalls.h"

#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>

class CallSigprocmask final : public CallBase {
    public:
    int how{};
    const sigset_t* set{};
    sigset_t* oldset{};
    size_t sigsetsize{};
    int* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

class CallSigaction final : public CallBase {
    public:
    int signum{};
    const struct k_sigaction* act{};
    struct k_sigaction* oldact{};
    size_t sigsetsize{};
    int* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

class CallAccept final : public CallBase {
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

    void set_return(int ret) const override { *this->ret = ret; }
};

class CallConnect final : public ICallPathConnect, public CallBase {
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
        this->addrlen = size;
    }

    void set_return(int ret) const override { *this->ret = ret; }
};

class CallFanotifyMark final : public ICallPathFanotify, public CallBase {
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

    void set_return(int ret) const override { *this->ret = ret; }
};

class CallInotifyAddWatch final : public ICallPath, public CallBase {
    public:
    int fd{};
    MyString path{};
    uint64_t mask{};
    int* ret{};

    int is_l() const override { return 0; }

    int get_dirfd() const override { return AT_FDCWD; }

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

    void set_return(int ret) const override { *this->ret = ret; }
};

enum RlimitType { RLIMITTYPE_GET, RLIMITTYPE_SET, RLIMITTYPE_PR };
typedef enum RlimitType RlimitType;

class CallRlimit final : public CallBase {
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

    void set_return(int ret) const override { *this->ret = ret; }
};

class CallPtrace final : public CallBase {
    public:
    long request{};
    long pid{};
    void* addr{};
    void* data{};
    long* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

class CallKill final : public CallBase {
    public:
    pid_t pid{};
    int sig{};
    int* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

class CallMisc final : public CallBase {
    public:
    SysArgs args{};
    unsigned long* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

class CallMmap final : public CallBase {
    public:
    unsigned long addr{};
    unsigned long len{};
    unsigned long prot{};
    unsigned long flags{};
    unsigned long fd{};
    unsigned long off{};
    unsigned long* ret{};

    void set_return(int ret) const override { *this->ret = (long)ret; }
};

enum CloneType {
    CLONETYPE_FORK,
    CLONETYPE_VFORK,
    CLONETYPE_CLONE,
    CLONETYPE_CLONE3
};
typedef CloneType CloneType;

class CallClone final : public CallBase {
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

    void set_return(int ret) const override { *this->ret = ret; }
};

enum ReadWriteType { READWRITE_PLAIN, READWRITE_64, READWRITE_V, READWRITE_V2 };
typedef CloneType CloneType;

class CallReadWrite final : public CallBase {
    public:
    ReadWriteType type{};
    int is_write{};
    unsigned long fd{};
    const struct iovec* iov{};
    unsigned long iovcnt{};
    unsigned long pos_l{};
    unsigned long pos_h{};
    int flags{};
    ssize_t* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
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
unsigned long handle_read(Context* ctx, SysArgs* args);
unsigned long handle_pread64(Context* ctx, SysArgs* args);
unsigned long handle_preadv(Context* ctx, SysArgs* args);
unsigned long handle_preadv2(Context* ctx, SysArgs* args);
unsigned long handle_write(Context* ctx, SysArgs* args);
unsigned long handle_pwrite64(Context* ctx, SysArgs* args);
unsigned long handle_pwritev(Context* ctx, SysArgs* args);
unsigned long handle_pwritev2(Context* ctx, SysArgs* args);