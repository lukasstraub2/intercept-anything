#pragma once
#include "manglepaths.h"

typedef struct FileAction FileAction;
struct FileAction {
    int is_symlink;
    mode_t mode;
    size_t len;
    char data[];
};

struct EmulateFileTmp : public ManglePaths {
    public:
    EmulateFileTmp(CallHandler* next) : ManglePaths(next) {}

    private:
    int _mangle_path(char** out,
                     ICallBase* call,
                     int dirfd,
                     const char* path,
                     IDestroyCB** cb);
    int _mangle_path(ICallPathBase* copy, IDestroyCB** cb);

    protected:
    virtual FileAction* _mangle_path(int dirfd, const char* path) = 0;

    int mangle_path(Context* ctx,
                    ICallPath* copy,
                    const ICallPath* call,
                    IDestroyCB** cb) override;
    int mangle_path(Context* ctx,
                    ICallPathOpen* copy,
                    const ICallPathOpen* call,
                    IDestroyCB** cb) override;
    int mangle_path(Context* ctx,
                    ICallPathFanotify* copy,
                    const ICallPathFanotify* call,
                    IDestroyCB** cb) override;
    int mangle_path(Context* ctx,
                    ICallPathF* copy,
                    const ICallPathF* call,
                    IDestroyCB** cb) override;
    int mangle_path(Context* ctx,
                    ICallPathDual* copy,
                    const ICallPathDual* call,
                    IDestroyCB** cb) override;
    int mangle_path(Context* ctx,
                    ICallPathSymlink* copy,
                    const ICallPathSymlink* call,
                    IDestroyCB** cb) override;
    int mangle_path(Context* ctx,
                    ICallPathConnect* copy,
                    const ICallPathConnect* call,
                    IDestroyCB** cb) override;
};