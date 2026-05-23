#include "emulate_file_tmp.h"
#include "mysys.h"
#include "util.h"

class UnlinkFile : public IDestroyCB {
    char* path;

    public:
    UnlinkFile(char* path) { this->path = strdup(path); }

    ~UnlinkFile() {
        sys_unlink(this->path);
        free(this->path);
    }
};

int EmulateFileTmp::_mangle_path(char** out,
                                 ICallBase* copy,
                                 int dirfd,
                                 const char* path,
                                 IDestroyCB** cb) {
    int ret = -EUCLEAN;
    int fd = 0;
    FileAction* action;
    if (dirfd != AT_FDCWD && path[0] != '/') {
        *out = nullptr;
        return 0;
    }

    action = _mangle_path(dirfd, path);
    if (!action) {
        *out = nullptr;
        return 0;
    }

    const char* const suffix = "/emulate_file_tmp.XXXXXX";
    size_t suffix_len = strlen(suffix);
    size_t tmpdir_len = strlen(tmpdir);
    char* new_path = new char[tmpdir_len + suffix_len + 1];
    char* ptr = new_path;

    memcpy(ptr, tmpdir, tmpdir_len);
    ptr += tmpdir_len;
    memcpy(ptr, suffix, suffix_len);
    ptr += suffix_len;
    *ptr = '\0';

    if (action->is_symlink) {
        char* xxxxxx = ptr - 6;
        while (1) {
            randchar6(xxxxxx);

            ret = sys_symlink(action->data, new_path);
            if (ret < 0) {
                if (ret == -EEXIST) {
                    continue;
                } else {
                    goto fail;
                }
            }

            break;
        }
    } else {
        ret = mkostemp(new_path, 0, action->mode);
        if (ret < 0) {
            goto fail;
        }
        fd = ret;

        ret = sys_write(fd, action->data, action->len);
        if (ret < 0) {
            goto fail;
        } else if (ret != action->len) {
            ret = -EUCLEAN;
            goto fail;
        }

        ret = sys_close(fd);
        if (ret < 0) {
            goto fail;
        }
    }

    *cb = new UnlinkFile(new_path);
    *out = new_path;
    return 0;

fail:
    if (fd) {
        sys_close(fd);
    }
    sys_unlink(new_path);
    free(action);
    delete[] new_path;
    copy->set_return(ret);
    return -1;
}

int EmulateFileTmp::_mangle_path(ICallPathBase* copy, IDestroyCB** cb) {
    char* out;

    int ret = _mangle_path(&out, copy, copy->get_dirfd(), copy->get_path(), cb);
    if (ret < 0) {
        return -1;
    } else if (!out) {
        return 0;
    }

    copy->set_path(out);
    delete[] out;
    return 0;
}

int EmulateFileTmp::mangle_path(Context* ctx,
                                ICallPath* copy,
                                const ICallPath* call,
                                IDestroyCB** cb) {
    if (call->get_flags() & AT_EMPTY_PATH && !strlen(call->get_path())) {
        return 0;
    }

    return _mangle_path(copy, cb);
}

int EmulateFileTmp::mangle_path(Context* ctx,
                                ICallPathOpen* copy,
                                const ICallPathOpen* call,
                                IDestroyCB** cb) {
    return _mangle_path(copy, cb);
}

int EmulateFileTmp::mangle_path(Context* ctx,
                                ICallPathFanotify* copy,
                                const ICallPathFanotify* call,
                                IDestroyCB** cb) {
    if (!call->get_path()) {
        return 0;
    }

    char* out;
    int ret = _mangle_path(&out, copy, call->get_dirfd(), call->get_path(), cb);
    if (ret < 0) {
        return -1;
    } else if (!out) {
        return 0;
    }

    copy->set_path(out);
    delete[] out;
    return 0;
}

int EmulateFileTmp::mangle_path(Context* ctx,
                                ICallPathF* copy,
                                const ICallPathF* call,
                                IDestroyCB** cb) {
    if (call->is_f()) {
        return 0;
    }

    if (call->get_flags() & AT_EMPTY_PATH && !strlen(call->get_path())) {
        return 0;
    }

    return _mangle_path(copy, cb);
}

int EmulateFileTmp::mangle_path(Context* ctx,
                                ICallPathDual* copy,
                                const ICallPathDual* call,
                                IDestroyCB** cb) {
    char* oldout = nullptr;
    char* newout = nullptr;
    int ret;

    if (!(call->get_flags() & AT_EMPTY_PATH && !strlen(call->get_old_path()))) {
        ret = _mangle_path(&oldout, copy, call->get_old_dirfd(),
                           call->get_old_path(), cb);
        if (ret < 0) {
            return -1;
        }
    }

    ret = _mangle_path(&newout, copy, call->get_new_dirfd(),
                       call->get_new_path(), cb);
    if (ret < 0) {
        delete[] oldout;
        return -1;
    }

    if (oldout) {
        copy->set_old_path(oldout);
    }
    if (newout) {
        copy->set_new_path(newout);
    }
    delete[] oldout;
    delete[] newout;
    return 0;
}

int EmulateFileTmp::mangle_path(Context* ctx,
                                ICallPathSymlink* copy,
                                const ICallPathSymlink* call,
                                IDestroyCB** cb) {
    char* out;
    int ret = _mangle_path(&out, copy, call->get_new_dirfd(),
                           call->get_new_path(), cb);
    if (ret < 0) {
        return -1;
    } else if (!out) {
        return 0;
    }

    copy->set_new_path(out);
    delete[] out;
    return 0;
}

int EmulateFileTmp::mangle_path(Context* ctx,
                                ICallPathConnect* copy,
                                const ICallPathConnect* call,
                                IDestroyCB** cb) {
    return 0;
}
