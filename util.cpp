
#include "mynolibc.h"

#include "util.h"
#include "tls.h"
#include "mysys.h"

void randchar6(char* buf) {
    int ret;
    const char* table =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789";
    const unsigned int len = strlen(table);
    unsigned char rand[6];

    ret = my_syscall3(__NR_getrandom, rand, 6, 0);
    if (ret < 0) {
        abort();
    }

    for (int i = 0; i < 6; i++) {
        int idx = rand[i] % len;
        buf[i] = table[idx];
    }
}

int mkostemp(char* templ, int flags, mode_t mode) {
    int ret;
    size_t len = strlen(templ);
    char* xxxxxx = templ + len - 6;

    for (int i = 0; i < 6; i++) {
        if (xxxxxx[i] != 'X') {
            abort();
        }
    }

    while (1) {
        randchar6(xxxxxx);
        ret = sys_open(templ, flags | O_RDWR | O_CREAT | O_EXCL, mode);
        if (ret < 0) {
            if (ret == -EEXIST) {
                continue;
            } else {
                return ret;
            }
        }

        return ret;
    }
}

int is_tid_dead(pid_t tid) {
    while (1) {
        int ret = sys_tkill(tid, 0);
        if (ret < 0) {
            if (ret == -EAGAIN) {
                continue;
            } else if (ret == -EPERM) {
                return 0;
            } else if (ret == -ESRCH) {
                return 1;
            } else {
                abort();
            }
        } else {
            return 0;
        }
    }
}

int is_pid_dead(pid_t pid) {
    while (1) {
        int ret = sys_kill(pid, 0);
        if (ret < 0) {
            if (ret == -EAGAIN) {
                continue;
            } else if (ret == -EPERM) {
                return 0;
            } else if (ret == -ESRCH) {
                return 1;
            } else {
                abort();
            }
        } else {
            return 0;
        }
    }
}

size_t concat(char* out, size_t out_len, const char* a, const char* b) {
    const size_t a_len = strlen(a);
    const size_t b_len = strlen(b);

    if (!out) {
        return a_len + b_len + 1;
    }

    if (a_len + 1 > out_len) {
        memcpy(out, a, out_len);
        out[out_len - 1] = '\0';
        return a_len + b_len + 1;
    }

    memcpy(out, a, a_len + 1);
    memcpy(out + a_len, b, min(b_len + 1, out_len - a_len));
    out[out_len - 1] = '\0';

    return a_len + b_len + 1;
}

size_t concat3(char* out,
               size_t out_len,
               const char* a,
               const char* b,
               const char* c) {
    const size_t a_len = strlen(a);
    const size_t b_len = strlen(b);
    const size_t c_len = strlen(c);

    if (!out) {
        return a_len + b_len + c_len + 1;
    }

    if (a_len + 1 > out_len) {
        memcpy(out, a, out_len);
        out[out_len - 1] = '\0';
        return a_len + b_len + c_len + 1;
    }

    if (a_len + b_len + 1 > out_len) {
        memcpy(out, a, a_len + 1);
        memcpy(out + a_len, b, min(b_len + 1, out_len - a_len));
        out[out_len - 1] = '\0';
        return a_len + b_len + c_len + 1;
    }

    memcpy(out, a, a_len + 1);
    memcpy(out + a_len, b, b_len + 1);
    memcpy(out + a_len + b_len, c, min(c_len + 1, out_len - a_len - b_len));
    out[out_len - 1] = '\0';
    return a_len + b_len + c_len + 1;
}

int strcmp_prefix(const char* a, const char* b) {
    return strncmp(a, b, strlen(b));
}

static int getcwd_cache_hit(Cache* cache) {
    return cache->type == CACHETYPE_GETCWD;
}

int getcwd_cache(Cache* cache, char* out, size_t out_len) {
    // This function is reentrant as it accesses global thread data

    if (out && !out_len) {
        abort();
    }

    while (1) {
        uint32_t cnt = TLS_INC_FETCH(cache->reentrant_cnt);
        TLS_BARRIER();

        if (out && getcwd_cache_hit(cache)) {
            unsigned int ret = cache->out_len;

            if (ret > out_len) {
                return -ERANGE;
            }

            memcpy(out, cache->out, min(out_len, ret));

            TLS_BARRIER();
            if (cnt != TLS_READ(cache->reentrant_cnt)) {
                continue;
            }
            return ret;
        }

        if (out) {
            int ret = sys_getcwd(out, out_len);
            if (ret < 0) {
                return ret;
            }
            return ret;
        } else {
            cache->type = CACHETYPE_GETCWD;

            int ret = sys_getcwd(cache->out, SCRATCH_SIZE);
            if (ret < 0) {
                return ret;
            }

            cache->out_len = ret;
            TLS_BARRIER();
            if (cnt != TLS_READ(cache->reentrant_cnt)) {
                continue;
            }
            return ret;
        }
    }
}

static ssize_t _readlinkat(int dirfd,
                           const char* path,
                           char* out,
                           size_t out_len) {
    ssize_t ret;

    ret = sys_readlinkat(dirfd, path, out, out_len);
    if (ret < 0) {
        return ret;
    } else if ((size_t)ret == out_len) {
        return -ERANGE;
    }
    out[ret] = '\0';

    return ret + 1;
}

static int readlink_cache_hit(Cache* cache, int dirfd, const char* path) {
    return cache->type == CACHETYPE_READLINK && dirfd == cache->in_dirfd &&
           !strcmp(path, cache->in_path);
}

ssize_t readlink_cache(Cache* cache,
                       char* out,
                       size_t out_len,
                       int dirfd,
                       const char* path) {
    // This function is reentrant as it accesses global thread data

    if (out && !out_len) {
        abort();
    }

    while (1) {
        uint32_t cnt = TLS_INC_FETCH(cache->reentrant_cnt);
        TLS_BARRIER();

        if (out && readlink_cache_hit(cache, dirfd, path)) {
            size_t ret = cache->out_len;
            memcpy(out, cache->out, min(out_len, ret));

            if (ret > out_len) {
                return -ERANGE;
            }

            TLS_BARRIER();
            if (cnt != TLS_READ(cache->reentrant_cnt)) {
                continue;
            }
            return ret;
        }

        if (out) {
            ssize_t ret = _readlinkat(dirfd, path, out, out_len);
            if (ret < 0) {
                return ret;
            }
            return ret;
        } else {
            size_t path_len = strlen(path) + 1;
            cache->type = CACHETYPE_READLINK;
            cache->in_dirfd = dirfd;
            memcpy(cache->in_path, path, path_len);

            ssize_t ret = _readlinkat(dirfd, path, cache->out, SCRATCH_SIZE);
            if (ret < 0) {
                return ret;
            }

            cache->out_len = ret;
            TLS_BARRIER();
            if (cnt != TLS_READ(cache->reentrant_cnt)) {
                continue;
            }
            return ret;
        }
    }
}

ssize_t concatat(Cache* cache,
                 char* out,
                 size_t out_len,
                 int dirfd,
                 const char* path) {
    ssize_t ret;
    const size_t path_len = strlen(path);
    char dirfd_buf[21];
    itoa_r(dirfd, dirfd_buf);

    if (out && !out_len) {
        abort();
    }

    if (path[0] == '/') {
        if (!out) {
            return path_len + 1;
        } else {
            if (path_len + 1 > out_len) {
                return -ERANGE;
            }

            memcpy(out, path, path_len + 1);
            return path_len + 1;
        }
    }

    const char* prefix = "/proc/self/fd/";
    const ssize_t prefix_len = strlen(prefix) + 1;
    const ssize_t fd_path_len = prefix_len + 21;
    char fd_path[fd_path_len];
    ret = concat(fd_path, fd_path_len, prefix, dirfd_buf);
    if (ret > fd_path_len) {
        abort();
    }

    if (!out) {
        if (dirfd == AT_FDCWD) {
            ret = getcwd_cache(cache, nullptr, 0);
        } else {
            ret = readlink_cache(cache, nullptr, 0, AT_FDCWD, fd_path);
        }
        if (ret < 0) {
            if (ret == -ENOENT) {
                ret = -EBADF;
            }
            return ret;
        }

        return ret + path_len + 1;
    } else {
        size_t fd_target_len = out_len - (path_len + 1);

        if (dirfd == AT_FDCWD) {
            ret = getcwd_cache(cache, out, fd_target_len);
        } else {
            ret = readlink_cache(cache, out, fd_target_len, AT_FDCWD, fd_path);
        }
        if (ret < 0) {
            if (ret == -ENOENT) {
                ret = -EBADF;
            }
            return ret;
        }

        if ((ret + path_len + 1) > out_len) {
            return -ERANGE;
        }

        out[fd_target_len - 1] = '/';
        memcpy(out + fd_target_len, path, path_len + 1);

        return ret + path_len + 1;
    }
}
