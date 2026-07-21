
#include "util.h"
#include "tls.h"
#include "mysys.h"
#include "itoa.h"

#include <string.h>
#include <stdlib.h>

const char* tmpdir = "/tmp";

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

ssize_t _readlinkat(char scratch[SCRATCH_SIZE],
                    int dirfd,
                    const char* path,
                    char** out) {
    ssize_t ret;

    ret = sys_readlinkat(dirfd, path, (char*)scratch, SCRATCH_SIZE);
    if (ret < 0) {
        return ret;
    } else if ((size_t)ret >= SCRATCH_SIZE) {
        return -ELOOP;
    }
    *out = new char[ret + 1];
    memcpy(*out, scratch, ret);
    (*out)[ret] = '\0';

    return ret + 1;
}

ssize_t _getcwd(char scratch[SCRATCH_SIZE], char** out) {
    ssize_t ret;

    ret = sys_getcwd((char*)scratch, SCRATCH_SIZE);
    if (ret < 0) {
        return ret;
    }
    *out = new char[ret];
    memcpy(*out, scratch, ret);

    return ret;
}

ssize_t concatat(char scratch[SCRATCH_SIZE],
                 int dirfd,
                 const char* path,
                 char** out) {
    ssize_t ret;
    char dirfd_buf[21];
    const char* prefix = "/proc/self/fd/";
    const ssize_t prefix_len = strlen(prefix);
    const size_t path_len = strlen(path);

    if (path[0] == '/') {
        *out = new char[path_len + 1];
        memcpy(*out, path, path_len + 1);
        return path_len + 1;
    }

    itoa_r(dirfd, dirfd_buf);
    const ssize_t dirfd_buf_len = strlen(dirfd_buf);

    const ssize_t fd_path_len = prefix_len + 21 + 1;
    char* fd_path = new char[fd_path_len];

    char* ptr = fd_path;
    memcpy(ptr, prefix, prefix_len);
    ptr += prefix_len;
    memcpy(ptr, dirfd_buf, dirfd_buf_len);
    ptr += dirfd_buf_len;
    *ptr = '\0';

    char* dir;
    if (dirfd == AT_FDCWD) {
        ret = _getcwd(scratch, &dir);
    } else {
        ret = _readlinkat(scratch, AT_FDCWD, fd_path, &dir);
    }
    delete[] fd_path;
    if (ret < 0) {
        if (ret == -ENOENT) {
            ret = -EBADF;
        }
        return ret;
    }

    const ssize_t dir_len = ret - 1;
    *out = new char[dir_len + 1 + path_len + 1];
    ptr = *out;
    memcpy(ptr, dir, dir_len);
    ptr += dir_len;
    *ptr = '/';
    ptr++;
    memcpy(ptr, path, path_len + 1);
    delete[] dir;

    return dir_len + 1 + path_len + 1;
}

int env_is_true(const char* env) {
    const char* value = getenv(env);
    if (!value) {
        return 0;
    }
    if (value[0] == '0' && value[1] == '\0') {
        return 0;
    }
    return 1;
}

ssize_t read_full(int fd, char* buf, size_t count) {
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