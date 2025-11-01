#pragma once

#include "base_types.h"
#include "myseccomp.h"
#include "syscalls.h"

#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>

class CallLink : public ICallPathDual {
    public:
    int at{};
    int olddirfd{AT_FDCWD};
    MyString oldpath{};
    int newdirfd{AT_FDCWD};
    MyString newpath{};
    int flags{};
    int* ret{};

    int get_old_dirfd() const override { return this->olddirfd; }

    const char* get_old_path() const override { return this->oldpath; }

    void set_old_dirfd(int dirfd) override {
        if (dirfd != AT_FDCWD) {
            this->at = 1;
        }
        this->olddirfd = dirfd;
    }

    void set_old_path(const char* path) override { this->oldpath.dup(path); }

    int get_new_dirfd() const override { return this->newdirfd; }

    const char* get_new_path() const override { return this->newpath; }

    void set_new_dirfd(int dirfd) override {
        if (dirfd != AT_FDCWD) {
            this->at = 1;
        }
        this->newdirfd = dirfd;
    }

    void set_new_path(const char* path) override { this->newpath.dup(path); }

    int get_flags() const override { return this->flags; }

    void set_flags(int flags) override { this->flags = flags; }
};

class CallSymlink : public ICallPathSymlink {
    public:
    int at{};
    MyString oldpath{};
    int newdirfd{AT_FDCWD};
    MyString newpath{};
    int flags{};
    int* ret{};

    const char* get_old_path() const override { return this->oldpath; }

    void set_old_path(const char* path) override { this->oldpath.dup(path); }

    int get_new_dirfd() const override { return this->newdirfd; }

    const char* get_new_path() const override { return this->newpath; }

    void set_new_dirfd(int dirfd) override {
        if (dirfd != AT_FDCWD) {
            this->at = 1;
        }
        this->newdirfd = dirfd;
    }

    void set_new_path(const char* path) override { this->newpath.dup(path); }

    int get_flags() const override { return this->flags; }

    void set_flags(int flags) override { this->flags = flags; }
};

class CallUnlink : public ICallPath {
    public:
    int at{};
    int dirfd{AT_FDCWD};
    MyString path{};
    int flags{};
    int* ret{};

    int is_l() const override { return 0; }

    int get_dirfd() const override { return this->dirfd; }

    const char* get_path() const override { return this->path; }

    int get_flags() const override { return this->flags; }

    void clear_l() override {}

    void set_dirfd(int dirfd) override {
        if (dirfd != AT_FDCWD) {
            this->at = 1;
        }
        this->dirfd = dirfd;
    }

    void set_path(const char* path) override { this->path.dup(path); }

    void set_flags(int flags) override { this->flags = flags; }
};

enum RenameType { RENAMETYPE_PLAIN, RENAMETYPE_AT, RENAMETYPE_AT2 };
typedef enum RenameType RenameType;

__attribute__((unused)) static int renametype_is_at(RenameType type) {
    return type >= RENAMETYPE_AT;
}

class CallRename : public ICallPathDual {
    public:
    RenameType type{};
    int olddirfd{AT_FDCWD};
    MyString oldpath{};
    int newdirfd{AT_FDCWD};
    MyString newpath{};
    unsigned int flags{};
    int* ret{};

    int get_old_dirfd() const override { return this->olddirfd; }

    const char* get_old_path() const override { return this->oldpath; }

    void set_old_dirfd(int dirfd) override {
        if (dirfd != AT_FDCWD && renametype_is_at(this->type)) {
            this->type = RENAMETYPE_AT2;
        }
        this->olddirfd = dirfd;
    }

    void set_old_path(const char* path) override { this->oldpath.dup(path); }

    int get_new_dirfd() const override { return this->newdirfd; }

    const char* get_new_path() const override { return this->newpath; }

    void set_new_dirfd(int dirfd) override {
        if (dirfd != AT_FDCWD && renametype_is_at(this->type)) {
            this->type = RENAMETYPE_AT2;
        }
        this->newdirfd = dirfd;
    }

    void set_new_path(const char* path) override { this->newpath.dup(path); }

    int get_flags() const override { return this->flags; }

    void set_flags(int flags) override { this->flags = flags; }
};

enum ChmodType {
    CHMODTYPE_PLAIN,
    CHMODTYPE_F,
    CHMODTYPE_AT,
};
typedef enum ChmodType ChmodType;

__attribute__((unused)) static int chmodtype_is_at(ChmodType type) {
    return type == CHMODTYPE_AT;
}

class CallChmod : public ICallPathF {
    public:
    ChmodType type{};
    int fd{};
    int dirfd{AT_FDCWD};
    MyString path{};
    mode_t mode{};
    int* ret{};

    CallChmod() = default;

    CallChmod(const CallChmod* call) {
        this->type = call->type;
        if (chmodtype_is_at(call->type)) {
            this->dirfd = call->dirfd;
        } else if (call->type == CHMODTYPE_F) {
            this->fd = call->fd;
        }
        this->path = call->path;
        this->mode = call->mode;
        this->ret = call->ret;
    }

    int is_l() const override { return 0; }

    int is_f() const override { return this->type == CHMODTYPE_F; }

    int get_dirfd() const override { return this->dirfd; }

    const char* get_path() const override { return this->path; }

    int get_flags() const override { return 0; }

    void clear_l() override {
        if (!is_l()) {
            abort();
        }
        this->type = CHMODTYPE_PLAIN;
    }

    void set_dirfd(int dirfd) override {
        if (dirfd != AT_FDCWD && !chmodtype_is_at(this->type)) {
            if (this->type != CHMODTYPE_PLAIN) {
                abort();
            }
            this->type = CHMODTYPE_AT;
        }
        this->dirfd = dirfd;
    }

    void set_path(const char* path) override { this->path.dup(path); }

    void set_flags(int flags) override {}
};

class CallTruncate : public ICallPathF {
    public:
    int f{};
    int fd{};
    MyString path{};
    off_t length{};
    int* ret{};

    CallTruncate() = default;

    CallTruncate(const CallTruncate* call) {
        this->f = call->f;
        if (call->f) {
            this->fd = call->fd;
        } else {
            this->path = call->path;
        }
        this->length = call->length;
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
};

class CallMkdir : public ICallPath {
    public:
    int at{};
    int dirfd{AT_FDCWD};
    MyString path{};
    mode_t mode{};
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
};

class CallMknod : public ICallPath {
    public:
    int at{};
    int dirfd{AT_FDCWD};
    MyString path{};
    mode_t mode{};
    unsigned int dev{};
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
};

unsigned long handle_link(Context* ctx, SysArgs* args);
unsigned long handle_linkat(Context* ctx, SysArgs* args);
unsigned long handle_symlink(Context* ctx, SysArgs* args);
unsigned long handle_symlinkat(Context* ctx, SysArgs* args);
unsigned long handle_unlink(Context* ctx, SysArgs* args);
unsigned long handle_unlinkat(Context* ctx, SysArgs* args);
unsigned long handle_rename(Context* ctx, SysArgs* args);
unsigned long handle_renameat(Context* ctx, SysArgs* args);
unsigned long handle_renameat2(Context* ctx, SysArgs* args);
unsigned long handle_chmod(Context* ctx, SysArgs* args);
unsigned long handle_fchmod(Context* ctx, SysArgs* args);
unsigned long handle_fchmodat(Context* ctx, SysArgs* args);
unsigned long handle_truncate(Context* ctx, SysArgs* args);
unsigned long handle_ftruncate(Context* ctx, SysArgs* args);
unsigned long handle_mkdir(Context* ctx, SysArgs* args);
unsigned long handle_mkdirat(Context* ctx, SysArgs* args);
unsigned long handle_mknod(Context* ctx, SysArgs* args);
unsigned long handle_mknodat(Context* ctx, SysArgs* args);