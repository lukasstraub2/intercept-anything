
#include "itoa.h"
#include "mylock.h"
#include "signalmanager.h"
#include "callhandler.h"

#define DEBUG_ENV "HARDLINK_DEBUG"
#include "debug.h"
#include "config.h"
#include "util.h"

#include "hardlinkshim.h"
#include "intercept.h"

#include "mysys.h"
#include "mytypes.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <dirent.h>
#include <sys/mman.h>
#include <kstat.h>

#define HARDLINK_PREFIX PREFIX "/tmp/hardlinkshim/"
#define LOCKFILE "lock"

class HardlinkShim : public CallHandler {
    private:
    CallHandler* const bottom;
    struct statx prefix;
    RwLock* mapped_rwlock;

    void lock_read(Tls* tls);
    void unlock_read(Tls* tls);
    void lock_write(Tls* tls);
    void unlock_write(Tls* tls);

    int _is_inside_prefix(const char* component);
    int is_inside_prefix(const char* _file_path);
    int is_inside_prefixat(Context* ctx, int dirfd, const char* path);
    int ab_inside_prefixat(Context* ctx,
                           int dirfda,
                           const char* patha,
                           int dirfdb,
                           const char* pathb);

    public:
    HardlinkShim(CallHandler* next, CallHandler* bottom, int recursing);
    void next(Context* ctx, const CallOpen* call) override;
    void next(Context* ctx, const CallStat* call) override;
    void next(Context* ctx, const CallReadlink* call) override;
    void next(Context* ctx, const CallAccess* call) override;
    void next(Context* ctx, const CallExec* call) override;
    void next(Context* ctx, const CallLink* call) override;
    void next(Context* ctx, const CallSymlink* call) override;
    void next(Context* ctx, const CallUnlink* call) override;
    void next(Context* ctx, const CallXattr* call) override;
    void next(Context* ctx, const CallRename* call) override;
    void next(Context* ctx, const CallGetdents* call) override;
};

void HardlinkShim::lock_read(Tls* tls) {
    rwlock_lock_read(tls, this->mapped_rwlock);
}

void HardlinkShim::unlock_read(Tls* tls) {
    rwlock_unlock_read(tls, this->mapped_rwlock);
}

void HardlinkShim::lock_write(Tls* tls) {
    rwlock_lock_write(tls, this->mapped_rwlock);
}

void HardlinkShim::unlock_write(Tls* tls) {
    rwlock_unlock_write(tls, this->mapped_rwlock);
}

static int changeprefix(char* linkname, const char* newprefix) {
    char* file;
    size_t len, prefix_len;

    prefix_len = strlen(newprefix);
    file = strrchr(linkname, '/');
    if (!file) {
        return -EINVAL;
    }
    file++;

    len = strlen(file);
    if (len < prefix_len + 1) {
        return -EINVAL;
    }

    memcpy(file, newprefix, prefix_len);
    return 0;
}

static int cnt_read(char* linkname) {
    ssize_t ret;
    char cnt_buf[22];
    int cnt;

    ret = changeprefix(linkname, "cnt");
    if (ret < 0) {
        return ret;
    }

    ret = sys_readlink(linkname, cnt_buf, 22);
    if (ret < 0) {
        goto err;
    } else if (ret == 22) {
        ret = -EUCLEAN;
        goto err;
    }
    cnt_buf[ret] = '\0';

    cnt = atoi(cnt_buf);
    if (cnt < 0) {
        ret = -EUCLEAN;
        goto err;
    }

    changeprefix(linkname, "ino");
    return cnt;

err:
    changeprefix(linkname, "ino");
    return ret;
}

static int cnt_write(char* linkname, int cnt) {
    ssize_t ret;
    size_t len = strlen(linkname) + 1;
    char cnt_buf[21];
    char tmpname[len];
    memcpy(tmpname, linkname, len);

    ret = changeprefix(linkname, "cnt");
    if (ret < 0) {
        return ret;
    }
    changeprefix(tmpname, "tmp");

    itoa_r(cnt, cnt_buf);

    sys_unlink(tmpname);
    ret = sys_symlink(cnt_buf, tmpname);
    if (ret < 0) {
        goto err;
    }

    ret = sys_rename(tmpname, linkname);
    if (ret < 0) {
        goto err;
    }

    changeprefix(linkname, "ino");
    return cnt;

err:
    changeprefix(linkname, "ino");
    sys_unlink(tmpname);
    return ret;
}

static int cnt_del(char* linkname) {
    int ret;

    ret = changeprefix(linkname, "cnt");
    if (ret < 0) {
        return ret;
    }

    ret = sys_unlink(linkname);
    changeprefix(linkname, "ino");
    if (ret < 0) {
        return ret;
    }

    return 0;
}

static int cnt_add(char* linkname, int add) {
    int ret;

    ret = cnt_read(linkname);
    if (ret < 0) {
        if (ret == -ENOENT) {
            ret = 0;
        } else {
            return ret;
        }
    }

    ret = cnt_write(linkname, ret + add);
    if (ret < 0) {
        return ret;
    }

    return ret;
}

static int cnt_read_hardlink(Context* ctx, int dirfd, const char* path) {
    int ret;

    ret = readlink_cache(&ctx->tls->cache, nullptr, 0, dirfd, path);
    if (ret < 0) {
        return ret;
    }

    char target[ret];
    ret = readlink_cache(&ctx->tls->cache, target, ret, dirfd, path);
    if (ret < 0) {
        abort();
    }

    ret = cnt_read(target);
    if (ret < 0) {
        return ret;
    }

    return ret;
}

static int is_hardlinkat(Context* ctx, int dirfd, const char* path) {
    ssize_t ret;

    ret = readlink_cache(&ctx->tls->cache, nullptr, 0, dirfd, path);
    if (ret < 0) {
        if (ret == -EINVAL || ret == -ENOENT) {
            return 0;
        } else {
            return ret;
        }
    }

    char target[ret];
    ret = readlink_cache(&ctx->tls->cache, target, ret, dirfd, path);
    if (ret < 0) {
        abort();
    }

    if (!strcmp_prefix(target, HARDLINK_PREFIX)) {
        return 1;
    }

    return 0;
}

int HardlinkShim::_is_inside_prefix(const char* component) {
    struct statx statbuf;
    int ret;

    ret = sys_statx(AT_FDCWD, component, AT_NO_AUTOMOUNT, STATX_BASIC_STATS,
                    &statbuf);
    if (ret < 0) {
        return ret;
    }

    if (statbuf.stx_dev_minor == this->prefix.stx_dev_minor &&
        statbuf.stx_dev_major == this->prefix.stx_dev_major &&
        statbuf.stx_ino == this->prefix.stx_ino) {
        return 1;
    }

    return 0;
}

static int is_dotdot(const char* path) {
    char* last = strrchr(path, '/') + 1;

    return last[0] == '.' && last[1] == '.' && last[2] == '\0';
}

static int is_empty(const char* path) {
    char* last = strrchr(path, '/') + 1;

    return last[0] == '\0' || (last[0] == '.' && last[1] == '\0');
}

int HardlinkShim::is_inside_prefix(const char* _file_path) {
    int ret;
    int inside = 0;
    char* path;
    size_t len = strlen(_file_path) + 1;
    char file_path[len];
    memcpy(file_path, _file_path, len);

    for (path = file_path + len - 2; path >= file_path && *path == '/';
         path--) {
        *path = '\0';
    }

    // Skip the first few components that may match our prefix
    // This reduces the number of stat calls we do later
    int components = -2;
    for (path = strchr(PREFIX, '/'); path; path = strchr(path + 1, '/')) {
        components++;
    }

    for (path = strchr(file_path + 1, '/'); path;
         path = strchr(path + 1, '/')) {
        if (components-- >= 0) {
            continue;
        }
        *path = '\0';

        if (inside) {
            if (is_dotdot(file_path)) {
                inside--;
            } else if (!is_empty(file_path)) {
                inside++;
            }
        } else {
            ret = _is_inside_prefix(file_path);
            if (ret < 0) {
                if (ret == -EACCES || ret == -ENOENT) {
                    return 0;
                } else {
                    return ret;
                }
            }
            if (ret) {
                inside++;
            }
        }

        *path = '/';
    }

    return inside;
}

// Only use hardlinkshim for rename and link
int HardlinkShim::is_inside_prefixat(Context* ctx,
                                     int dirfd,
                                     const char* path) {
    ssize_t ret;
    Cache* cache = &ctx->tls->cache;

    ret = concatat(cache, nullptr, 0, dirfd, path);
    if (ret < 0) {
        return ret;
    }
    if (ret > SCRATCH_SIZE) {
        return -ENAMETOOLONG;
    }

    char fullpath[ret];
    ret = concatat(cache, fullpath, ret, dirfd, path);
    if (ret < 0) {
        abort();
    }

    return is_inside_prefix(fullpath);
}

int HardlinkShim::ab_inside_prefixat(Context* ctx,
                                     int dirfda,
                                     const char* patha,
                                     int dirfdb,
                                     const char* pathb) {
    int ret, a_inprefix, b_inprefix;

    ret = is_inside_prefixat(ctx, dirfda, patha);
    if (ret < 0) {
        return ret;
    }
    a_inprefix = ret;

    ret = is_inside_prefixat(ctx, dirfdb, pathb);
    if (ret < 0) {
        return ret;
    }
    b_inprefix = ret;

    if (!a_inprefix || !b_inprefix) {
        if (a_inprefix == b_inprefix) {
            return -EOPNOTSUPP;
        } else {
            return -EXDEV;
        }
    }

    return 0;
}

static int _copy_symlink(Context* ctx,
                         int olddirfd,
                         const char* oldpath,
                         int newdirfd,
                         const char* newpath) {
    ssize_t ret;

    ret = readlink_cache(&ctx->tls->cache, nullptr, 0, olddirfd, oldpath);
    if (ret < 0) {
        return ret;
    }

    char target[ret];
    ret = readlink_cache(&ctx->tls->cache, target, ret, olddirfd, oldpath);
    if (ret < 0) {
        abort();
    }

    ret = sys_symlinkat(target, newdirfd, newpath);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

static int copy_symlink(Context* ctx, const CallLink* call) {
    if (call->at) {
        return _copy_symlink(ctx, call->olddirfd, call->oldpath, call->newdirfd,
                             call->newpath);
    } else {
        return _copy_symlink(ctx, AT_FDCWD, call->oldpath, AT_FDCWD,
                             call->newpath);
    }
}

static int _add_hardlink(Context* ctx,
                         int olddirfd,
                         const char* oldpath,
                         int newdirfd,
                         const char* newpath) {
    ssize_t ret;

    ret = readlink_cache(&ctx->tls->cache, nullptr, 0, olddirfd, oldpath);
    if (ret < 0) {
        return ret;
    }

    char target[ret];
    ret = readlink_cache(&ctx->tls->cache, target, ret, olddirfd, oldpath);
    if (ret < 0) {
        abort();
    }

    ret = sys_symlinkat(target, newdirfd, newpath);
    if (ret < 0) {
        return ret;
    }

    ret = cnt_add(target, 1);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

static int add_hardlink(Context* ctx, const CallLink* call) {
    if (call->at) {
        return _add_hardlink(ctx, call->olddirfd, call->oldpath, call->newdirfd,
                             call->newpath);
    } else {
        return _add_hardlink(ctx, AT_FDCWD, call->oldpath, AT_FDCWD,
                             call->newpath);
    }
}

static int del_hardlink(char* linkname) {
    int ret;

    ret = cnt_add(linkname, -1);
    if (ret < 0) {
        return ret;
    }

    if (ret) {
        return 0;
    }

    ret = sys_unlink(linkname);
    if (ret < 0) {
        return ret;
    }

    ret = cnt_del(linkname);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

void HardlinkShim::next(Context* ctx, const CallOpen* call) {
    int ret;
    int* _ret = call->ret;

    lock_read(ctx->tls);

    ret = is_hardlinkat(ctx, (call->at ? call->dirfd : AT_FDCWD), call->path);
    if (ret < 0) {
        goto err;
    }

    if (ret) {
        CallOpen _call;
        callopen_copy(&_call, call);

        _call.flags &= ~(O_NOFOLLOW);
        _next->next(ctx, &_call);
    } else {
        _next->next(ctx, call);
    }

    unlock_read(ctx->tls);
    return;

err:
    unlock_read(ctx->tls);
    *_ret = ret;
}

void HardlinkShim::next(Context* ctx, const CallStat* call) {
    int ret;
    int* _ret = call->ret;
    const int dirfd = (stattype_is_at(call->type) ? call->dirfd : AT_FDCWD);

    lock_read(ctx->tls);

    if (call->type == STATTYPE_F) {
        ret = 0;
    } else {
        ret = is_hardlinkat(ctx, dirfd, call->path);
    }
    if (ret < 0) {
        goto err;
    }

    if (ret) {
        int cnt;
        struct kstat* statbuf_plain;
        struct statx* statbuf_x;
        CallStat _call;
        callstat_copy(&_call, call);

        ret = cnt_read_hardlink(ctx, dirfd, call->path);
        if (ret < 0) {
            goto err;
        }
        cnt = ret;

        if (call->type == STATTYPE_L) {
            _call.type = STATTYPE_PLAIN;
        } else if (stattype_is_at(call->type)) {
            _call.flags &= ~AT_SYMLINK_NOFOLLOW;
        }

        _next->next(ctx, &_call);
        if (*_ret < 0 || !_call.statbuf) {
            unlock_read(ctx->tls);
            return;
        }

        switch (_call.type) {
            case STATTYPE_PLAIN:
            case STATTYPE_L:
            case STATTYPE_AT:
                statbuf_plain = (struct kstat*)_call.statbuf;
                statbuf_plain->st_nlink = cnt;
                break;

            case STATTYPE_X:
                statbuf_x = (struct statx*)_call.statbuf;
                statbuf_x->stx_nlink = cnt;
                break;

            default:
                abort();
                break;
        }
    } else {
        _next->next(ctx, call);
    }

    unlock_read(ctx->tls);
    return;

err:
    unlock_read(ctx->tls);
    *_ret = ret;
}

void HardlinkShim::next(Context* ctx, const CallReadlink* call) {
    int ret;
    ssize_t* _ret = call->ret;

    lock_read(ctx->tls);

    ret = is_hardlinkat(ctx, (call->at ? call->dirfd : AT_FDCWD), call->path);
    if (ret < 0) {
        goto err;
    }

    if (ret) {
        *_ret = -EINVAL;
    } else {
        _next->next(ctx, call);
    }

    unlock_read(ctx->tls);
    return;

err:
    unlock_read(ctx->tls);
    *_ret = ret;
}

void HardlinkShim::next(Context* ctx, const CallAccess* call) {
    int* _ret = call->ret;

    lock_read(ctx->tls);

    _next->next(ctx, call);

    unlock_read(ctx->tls);
}

void HardlinkShim::next(Context* ctx, const CallExec* call) {
    int ret;
    int* _ret = call->ret;

    // Do not take lock since exec may recurse
    ret = is_hardlinkat(ctx, (call->at ? call->dirfd : AT_FDCWD), call->path);
    if (ret < 0) {
        *_ret = ret;
        return;
    }

    if (ret) {
        CallExec _call;
        callexec_copy(&_call, call);

        if (call->at) {
            _call.flags &= ~AT_SYMLINK_NOFOLLOW;
        }

        _next->next(ctx, &_call);
    } else {
        _next->next(ctx, call);
    }
}

static size_t make_linkname(char* out, size_t out_len, uint64_t ino) {
    const char* prefix = "ino_";
    const size_t prefix_len = strlen(prefix);
    const size_t hardlink_prefix_len = strlen(HARDLINK_PREFIX);
    const size_t len = hardlink_prefix_len + 21 + 1 + prefix_len + 21;
    const uint64_t ino_hash = ino % 1499;
    size_t pos = 0;

    if (!out) {
        return len;
    }

    if (out_len != len) {
        abort();
    }

    memcpy(out + pos, HARDLINK_PREFIX, hardlink_prefix_len);
    pos += hardlink_prefix_len;

    pos += u64toa_r(ino_hash, out + pos);

    out[pos] = '/';
    pos += 1;

    memcpy(out + pos, prefix, prefix_len);
    pos += prefix_len;

    pos += u64toa_r(ino, out + pos);

    return pos + 1;
}

static int hash_mkdir(char* linkname) {
    int ret;
    char* slash = strrchr(linkname, '/');

    *slash = '\0';
    ret = sys_mkdir(linkname, 0777);
    *slash = '/';

    if (ret < 0) {
        if (ret != -EEXIST) {
            return ret;
        }
    }

    return 0;
}

void HardlinkShim::next(Context* ctx, const CallLink* call) {
    int ret;
    int* _ret = call->ret;
    int olddirfd = (call->at ? call->olddirfd : AT_FDCWD);
    int newdirfd = (call->at ? call->newdirfd : AT_FDCWD);

    ret = ab_inside_prefixat(ctx, olddirfd, call->oldpath, newdirfd,
                             call->newpath);
    if (ret < 0) {
        *_ret = ret;
        return;
    }

    if (call->at && call->flags & (AT_EMPTY_PATH | AT_SYMLINK_FOLLOW)) {
        // TODO: Handle AT_SYMLINK_FOLLOW
        *_ret = -ENOENT;
        return;
    }

    lock_write(ctx->tls);

    ret = is_hardlinkat(ctx, olddirfd, call->oldpath);
    if (ret < 0) {
        goto err;
    }

    if (ret) {
        ret = add_hardlink(ctx, call);
        if (ret < 0) {
            goto err;
        }
    } else {
        struct statx statbuf;
        ret = sys_statx(olddirfd, call->oldpath,
                        AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT,
                        STATX_TYPE | STATX_MODE | STATX_INO, &statbuf);
        if (ret < 0) {
            goto err;
        }

        if ((statbuf.stx_mode & S_IFMT) == S_IFLNK) {
            ret = copy_symlink(ctx, call);
            if (ret < 0) {
                goto err;
            }
        } else if ((statbuf.stx_mode & S_IFMT) == S_IFREG) {
            const size_t linkname_len =
                make_linkname(nullptr, 0, statbuf.stx_ino);

            char linkname[linkname_len];
            make_linkname(linkname, linkname_len, statbuf.stx_ino);

            ret = hash_mkdir(linkname);
            if (ret < 0) {
                goto err;
            }

            ret = sys_access(linkname, F_OK);
            if (ret == 0) {
                ret = -EUCLEAN;
                goto err;
            }

            ret = sys_renameat(olddirfd, call->oldpath, AT_FDCWD, linkname);
            if (ret < 0) {
                goto err;
            }

            ret = sys_symlinkat(linkname, olddirfd, call->oldpath);
            if (ret < 0) {
                goto err;
            }

            ret = cnt_add(linkname, 1);
            if (ret < 0) {
                goto err;
            }

            ret = sys_symlinkat(linkname, newdirfd, call->newpath);
            if (ret < 0) {
                goto err;
            }

            ret = cnt_add(linkname, 1);
            if (ret < 0) {
                goto err;
            }
        } else {
            ret = -EINVAL;
            goto err;
        }
    }

    unlock_write(ctx->tls);
    return;

err:
    unlock_write(ctx->tls);
    *_ret = ret;
}

void HardlinkShim::next(Context* ctx, const CallSymlink* call) {
    int* _ret = call->ret;

    lock_read(ctx->tls);

    _next->next(ctx, call);

    unlock_read(ctx->tls);
}

void HardlinkShim::next(Context* ctx, const CallUnlink* call) {
    ssize_t ret;
    int* _ret = call->ret;
    int dirfd = (call->at ? call->dirfd : AT_FDCWD);

    lock_write(ctx->tls);

    ret = is_hardlinkat(ctx, dirfd, call->path);
    if (ret < 0) {
        goto err;
    }

    if (ret) {
        ret = readlink_cache(&ctx->tls->cache, nullptr, 0, dirfd, call->path);
        if (ret < 0) {
            goto err;
        }

        char target[ret];
        ret = readlink_cache(&ctx->tls->cache, target, ret, dirfd, call->path);
        if (ret < 0) {
            abort();
        }

        _next->next(ctx, call);
        ret = *_ret;
        if (ret < 0) {
            goto err;
        }

        ret = del_hardlink(target);
        if (ret < 0) {
            goto err;
        }
    } else {
        _next->next(ctx, call);
    }

    unlock_write(ctx->tls);
    return;

err:
    unlock_write(ctx->tls);
    *_ret = ret;
}

void HardlinkShim::next(Context* ctx, const CallXattr* call) {
    int ret;
    ssize_t* _ret = call->ret;

    lock_read(ctx->tls);

    if (call->type2 == XATTRTYPE_F) {
        ret = 0;
    } else {
        ret = is_hardlinkat(ctx, AT_FDCWD, call->path);
        if (ret < 0) {
            goto err;
        }
    }

    if (ret) {
        CallXattr _call;
        callxattr_copy(&_call, call);

        if (call->type2 == XATTRTYPE_L) {
            _call.type2 = XATTRTYPE_PLAIN;
        }

        _next->next(ctx, &_call);
    } else {
        _next->next(ctx, call);
    }

    unlock_read(ctx->tls);
    return;

err:
    unlock_read(ctx->tls);
    *_ret = ret;
}

void HardlinkShim::next(Context* ctx, const CallRename* call) {
    ssize_t ret;
    int* _ret = call->ret;
    int olddirfd = (renametype_is_at(call->type) ? call->olddirfd : AT_FDCWD);
    int newdirfd = (renametype_is_at(call->type) ? call->newdirfd : AT_FDCWD);
    Cache* cache = &ctx->tls->cache;

    ret = ab_inside_prefixat(ctx, olddirfd, call->oldpath, newdirfd,
                             call->newpath);
    if (ret < 0) {
        if (ret != -EOPNOTSUPP) {
            *_ret = ret;
            return;
        }
    }

    lock_write(ctx->tls);

    if (call->type == RENAMETYPE_AT2 &&
        call->flags & (RENAME_EXCHANGE | RENAME_NOREPLACE)) {
        ret = 0;
    } else {
        ret = is_hardlinkat(ctx, newdirfd, call->newpath);
        if (ret < 0) {
            goto err;
        }
    }

    if (ret) {
        ret = readlink_cache(cache, nullptr, 0, newdirfd, call->newpath);
        if (ret < 0) {
            goto err;
        }

        char target[ret];
        ret = readlink_cache(cache, target, ret, newdirfd, call->newpath);
        if (ret < 0) {
            abort();
        }

        bottom->next(ctx, call);
        ret = *_ret;
        if (ret < 0) {
            goto err;
        }

        ret = del_hardlink(target);
        if (ret < 0) {
            goto err;
        }
    } else {
        _next->next(ctx, call);
    }

    unlock_write(ctx->tls);
    return;

err:
    unlock_write(ctx->tls);
    *_ret = ret;
}

static int mkpath(const char* _file_path, mode_t mode) {
    char* path;
    size_t len = strlen(_file_path) + 1;
    char file_path[len];
    memcpy(file_path, _file_path, len);

    for (path = strchr(file_path + 1, '/'); path;
         path = strchr(path + 1, '/')) {
        int ret;

        *path = '\0';
        ret = sys_mkdir(file_path, mode);
        if (ret < 0) {
            if (ret != -EEXIST) {
                *path = '/';
                return ret;
            }
        }
        *path = '/';
    }

    return 0;
}

struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[];
};

struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

void HardlinkShim::next(Context* ctx, const CallGetdents* call) {
    ssize_t* _ret = call->ret;

    lock_read(ctx->tls);

    _next->next(ctx, call);

    if (*_ret >= 0) {
        char* buf = (char*)call->dirp;
        ssize_t size = *_ret;
        if (call->is64) {
            for (ssize_t pos = 0; pos < size;) {
                char* ptr = buf + pos;
                struct linux_dirent64* dirp = (struct linux_dirent64*)ptr;
                dirp->d_type = DT_UNKNOWN;

                pos += dirp->d_reclen;
            }
        } else {
            for (ssize_t pos = 0; pos < size;) {
                char* ptr = buf + pos;
                struct linux_dirent* dirp = (struct linux_dirent*)ptr;
                char* d_type = buf + pos + dirp->d_reclen - 1;

                *d_type = DT_UNKNOWN;
                pos += dirp->d_reclen;
            }
        }
    }

    unlock_read(ctx->tls);
}

HardlinkShim::HardlinkShim(CallHandler* const next,
                           CallHandler* const bottom,
                           int recursing)
    : CallHandler(next), bottom(bottom) {
    int ret, fd;

    if (!recursing) {
        ret = mkpath(HARDLINK_PREFIX LOCKFILE, 0777);
        if (ret < 0) {
            exit_error("mkpath(%s): %d", LOCKFILE, ret);
        }
    }

    ret = sys_open(HARDLINK_PREFIX LOCKFILE, O_CREAT | O_RDWR, 0777);
    if (ret < 0) {
        exit_error("open64(%s): %d", HARDLINK_PREFIX LOCKFILE, -ret);
    }
    fd = ret;

    ret = sys_ftruncate(fd, 4096);
    if (ret < 0) {
        exit_error("ftruncate(): %d", ret);
    }

    void* ptr =
        sys_mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if ((unsigned long)ptr >= -4095UL) {
        abort();
    }
    this->mapped_rwlock = (RwLock*)ptr;

    sys_close(fd);

    ret = sys_statx(AT_FDCWD, PREFIX, AT_NO_AUTOMOUNT, STATX_BASIC_STATS,
                    &this->prefix);
    if (ret < 0) {
        exit_error("stat64(%s): %d", PREFIX, ret);
    }
}

CallHandler* hardlinkshim_init(CallHandler* next,
                               CallHandler* bottom,
                               int recursing) {
    return new HardlinkShim(next, bottom, recursing);
}
