#pragma once

#include "base_types.h"
#include "myseccomp.h"
#include "syscalls.h"

#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>

class CallOpen final : public ICallPathOpen, public CallBase {
    public:
    int at{};
    int dirfd{AT_FDCWD};
    MyString path{};
    int flags{};
    mode_t mode{};
    int* ret{};

    int get_dirfd() const override { return this->dirfd; }

    const char* get_path() const override { return this->path; }

    int get_flags() const override { return this->flags; }

    void set_dirfd(int dirfd) override {
        if (dirfd != AT_FDCWD) {
            this->at = 1;
        }
        this->dirfd = dirfd;
    }

    void set_path(const char* path) override { this->path.dup(path); }

    void set_flags(int flags) override { this->flags = flags; }

    void set_return(int ret) const override { *this->ret = ret; }
};

enum StatType {
    STATTYPE_PLAIN = 0,
    STATTYPE_F,
    STATTYPE_L,
    STATTYPE_AT,
    STATTYPE_X
};
typedef enum StatType StatType;
__attribute__((unused)) static int stattype_is_at(StatType type) {
    return type >= STATTYPE_AT;
}

class CallStat final : public ICallPathF, public CallBase {
    public:
    StatType type{};
    int dirfd{};
    MyString path{};
    int flags{};
    unsigned int mask{};
    void* statbuf{};
    int* ret{};

    CallStat() = default;

    CallStat(const CallStat* call) {
        this->type = call->type;

        this->dirfd = call->dirfd;
        this->flags = call->flags;

        if (call->type == STATTYPE_F) {
            this->dirfd = call->dirfd;
        } else {
            this->path = call->path;
        }

        if (call->type == STATTYPE_X) {
            this->mask = call->mask;
        }

        this->statbuf = call->statbuf;
        this->ret = call->ret;
    }

    int is_l() const override { return this->type == STATTYPE_L; }

    int is_f() const override { return this->type == STATTYPE_F; }

    int get_dirfd() const override { return this->dirfd; }

    const char* get_path() const override { return this->path; }

    int get_flags() const override { return this->flags; }

    void clear_l() override {
        if (!is_l()) {
            abort();
        }
        this->type = STATTYPE_PLAIN;
    }

    void set_dirfd(int dirfd) override {
        if (dirfd != AT_FDCWD && !stattype_is_at(this->type)) {
            if (this->type != STATTYPE_PLAIN) {
                abort();
            }
            this->type = STATTYPE_AT;
        }
        this->dirfd = dirfd;
    }

    void set_path(const char* path) override { this->path.dup(path); }

    void set_flags(int flags) override { this->flags = flags; }

    void set_return(int ret) const override { *this->ret = ret; }
};

class CallReadlink final : public ICallPath, public CallBase {
    public:
    int at{};
    int dirfd{AT_FDCWD};
    MyString path{};
    char* buf{};
    size_t bufsiz{};
    ssize_t* ret{};

    int is_l() const override { return 0; }

    int get_dirfd() const override { return this->dirfd; }

    const char* get_path() const override { return this->path; }

    int get_flags() const override { return 0; }

    void clear_l() override {}

    void set_dirfd(int dirfd) override {
        if (dirfd != AT_FDCWD) {
            this->at = 1;
        }
        this->dirfd = dirfd;
    }

    void set_path(const char* path) override { this->path.dup(path); }

    void set_flags(int flags) override {}

    void set_return(int ret) const override { *this->ret = ret; }
};

class CallAccess final : public ICallPath, public CallBase {
    public:
    int at{};
    int dirfd{AT_FDCWD};
    MyString path{};
    int mode{};
    int* ret{};

    int is_l() const override { return 0; }

    int get_dirfd() const override { return this->dirfd; }

    const char* get_path() const override { return this->path; }

    int get_flags() const override { return 0; }

    void clear_l() override {}

    void set_dirfd(int dirfd) override {
        if (dirfd != AT_FDCWD) {
            this->at = 1;
        }
        this->dirfd = dirfd;
    }

    void set_path(const char* path) override { this->path.dup(path); }

    void set_flags(int flags) override {}

    void set_return(int ret) const override { *this->ret = ret; }
};

enum XattrType {
    XATTRTYPE_SET,
    XATTRTYPE_GET,
    XATTRTYPE_LIST,
    XATTRTYPE_REMOVE
};
typedef enum XattrType XattrType;

enum XattrType2 { XATTRTYPE_PLAIN, XATTRTYPE_L, XATTRTYPE_F };
typedef enum XattrType2 XattrType2;

class CallXattr final : public ICallPathF, public CallBase {
    public:
    XattrType type{};
    XattrType2 type2{};
    int fd{};
    MyString path{};
    char* list{};
    const char* name{};
    void* value{};
    size_t size{};
    int flags{};
    ssize_t* ret{};

    CallXattr() = default;

    CallXattr(const CallXattr* call) {
        this->type = call->type;
        this->type2 = call->type2;

        if (call->type2 == XATTRTYPE_F) {
            this->fd = call->fd;
        } else {
            this->path = call->path;
        }

        switch (call->type) {
            case XATTRTYPE_SET:
                this->flags = call->flags;
            /*fallthrough*/
            case XATTRTYPE_GET:
                this->name = call->name;
                this->value = call->value;
                this->size = call->size;
                break;

            case XATTRTYPE_LIST:
                this->list = call->list;
                this->size = call->size;
                break;

            case XATTRTYPE_REMOVE:
                this->name = call->name;
                break;
        }

        this->ret = call->ret;
    }

    int is_l() const override { return this->type2 == XATTRTYPE_L; }

    int is_f() const override { return this->type2 == XATTRTYPE_F; }

    int get_dirfd() const override { return AT_FDCWD; }

    const char* get_path() const override { return this->path; }

    int get_flags() const override { return 0; }

    void clear_l() override {
        if (!is_l()) {
            abort();
        }
        this->type2 = XATTRTYPE_PLAIN;
    }

    void set_dirfd(int dirfd) override {
        if (dirfd != AT_FDCWD) {
            abort();
        }
    }

    void set_path(const char* path) override { this->path.dup(path); }

    void set_flags(int flags) override {}

    void set_return(int ret) const override { *this->ret = ret; }
};

class CallChdir final : public ICallPathF, public CallBase {
    public:
    int f{};
    int fd{};
    MyString path{};
    int* ret{};

    CallChdir() = default;

    CallChdir(CallChdir* call) {
        this->f = call->f;
        if (call->f) {
            this->fd = call->fd;
        } else {
            this->path = call->path;
        }
        this->ret = call->ret;
    }

    int is_f() const override { return this->f; }

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

class CallGetdents final : public CallBase {
    public:
    int is64{};
    int fd{};
    void* dirp{};
    size_t count{};
    ssize_t* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

class CallClose final : public CallBase {
    public:
    int is_range{};
    unsigned int fd{};
    unsigned int max_fd{};  // Only used for close_range
    unsigned int flags{};   // Only used for close_range
    int* ret{};

    CallClose() = default;

    CallClose(CallClose* call) {
        this->is_range = call->is_range;
        this->fd = call->fd;
        if (call->is_range) {
            this->max_fd = call->max_fd;
            this->flags = call->flags;
        }
        this->ret = call->ret;
    }

    void set_return(int ret) const override { *this->ret = ret; }
};

unsigned long handle_open(Context* ctx, SysArgs* args);
unsigned long handle_openat(Context* ctx, SysArgs* args);
unsigned long handle_stat(Context* ctx, SysArgs* args);
unsigned long handle_fstat(Context* ctx, SysArgs* args);
unsigned long handle_lstat(Context* ctx, SysArgs* args);
unsigned long handle_newfstatat(Context* ctx, SysArgs* args);
unsigned long handle_statx(Context* ctx, SysArgs* args);
unsigned long handle_readlink(Context* ctx, SysArgs* args);
unsigned long handle_readlinkat(Context* ctx, SysArgs* args);
unsigned long handle_access(Context* ctx, SysArgs* args);
unsigned long handle_faccessat(Context* ctx, SysArgs* args);
unsigned long handle_setxattr(Context* ctx, SysArgs* args);
unsigned long handle_lsetxattr(Context* ctx, SysArgs* args);
unsigned long handle_fsetxattr(Context* ctx, SysArgs* args);
unsigned long handle_getxattr(Context* ctx, SysArgs* args);
unsigned long handle_lgetxattr(Context* ctx, SysArgs* args);
unsigned long handle_fgetxattr(Context* ctx, SysArgs* args);
unsigned long handle_listxattr(Context* ctx, SysArgs* args);
unsigned long handle_llistxattr(Context* ctx, SysArgs* args);
unsigned long handle_flistxattr(Context* ctx, SysArgs* args);
unsigned long handle_removexattr(Context* ctx, SysArgs* args);
unsigned long handle_lremovexattr(Context* ctx, SysArgs* args);
unsigned long handle_fremovexattr(Context* ctx, SysArgs* args);
unsigned long handle_chdir(Context* ctx, SysArgs* args);
unsigned long handle_fchdir(Context* ctx, SysArgs* args);
unsigned long handle_getdents(Context* ctx, SysArgs* args);
unsigned long handle_getdents64(Context* ctx, SysArgs* args);
unsigned long handle_close(Context* ctx, SysArgs* args);
unsigned long handle_close_range(Context* ctx, SysArgs* args);