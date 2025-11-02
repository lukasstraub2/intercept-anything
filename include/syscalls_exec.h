#pragma once

#include "base_types.h"
#include "myseccomp.h"
#include "syscalls.h"

#include <fcntl.h>

class CallExec final : public ICallPath, public CallBase {
    public:
    int at{};
    int final{};
    int dirfd{AT_FDCWD};
    MyString path{};
    char* const* argv{};
    char* const* envp{};
    int flags{};
    int* ret{};

    int is_l() const override { return 0; }

    int get_dirfd() const override { return this->dirfd; }

    const char* get_path() const override { return this->path; }

    int get_flags() const override { return flags; }

    void clear_l() override {}

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

unsigned long handle_execve(Context* ctx, SysArgs* args);
unsigned long handle_execveat(Context* ctx, SysArgs* args);