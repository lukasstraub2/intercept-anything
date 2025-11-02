#pragma once

#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdio.h>

class MyString {
    const char* str = nullptr;
    int alloc = 0;

    public:
    MyString() = default;

    MyString(const MyString& other) {
        this->str = other.str;
        this->alloc = 0;
    }

    MyString(const char* str) { this->str = str; }

    void dup(const char* str) {
        if (this->alloc) {
            free((void*)this->str);
        }
        this->str = strdup(str);
        this->alloc = 1;
    }

    operator const char*() const { return str; }

    ~MyString() {
        if (alloc) {
            free((void*)str);
        }
    }
};

class MyBlob {
    void* blob = nullptr;
    int alloc = 0;

    public:
    MyBlob() = default;

    MyBlob(const MyBlob& other) {
        this->blob = other.blob;
        this->alloc = 0;
    }

    MyBlob(void* blob) { this->blob = blob; }

    void dup(void* blob, size_t size) {
        if (this->alloc) {
            free(this->blob);
        }
        this->blob = malloc(size);
        memcpy(this->blob, blob, size);
        this->alloc = 1;
    }

    operator void*() const { return blob; }

    operator struct sockaddr_un *() const { return (struct sockaddr_un*)blob; }

    ~MyBlob() {
        if (alloc) {
            free((void*)blob);
        }
    }
};

class IReturn {
    public:
    virtual void set_return(int ret) const = 0;
    virtual ~IReturn(){};
};

class IDestroyCB {
    public:
    virtual ~IDestroyCB(){};
};

class ICallBase : public virtual IReturn {
    public:
    virtual void set_destroy_cb(IDestroyCB* cb) = 0;
    virtual ~ICallBase(){};
};

class ICallPathBase : public virtual ICallBase {
    public:
    virtual int get_dirfd() const = 0;
    virtual const char* get_path() const = 0;

    virtual void set_dirfd(int dirfd) = 0;
    virtual void set_path(const char* path) = 0;

    virtual ~ICallPathBase(){};
};

class ICallPath : public virtual ICallPathBase {
    public:
    virtual int is_l() const = 0;
    virtual int get_flags() const = 0;

    virtual void clear_l() = 0;
    virtual void set_flags(int flags) = 0;

    virtual ~ICallPath(){};
};

// Special case for openat, since the flags have different meanings
class ICallPathOpen : public virtual ICallPathBase {
    public:
    virtual int get_flags() const = 0;
    virtual void set_flags(int flags) = 0;

    virtual ~ICallPathOpen(){};
};

// Special case for fanotify_mark
// flags have different meanings
// path can be NULL, then behavour is like AT_EMPTY_PATH
class ICallPathFanotify : public virtual ICallBase {
    public:
    virtual int get_dirfd() const = 0;
    virtual const char* get_path() const = 0;
    virtual unsigned int get_flags() const = 0;

    virtual void set_dirfd(int dirfd) = 0;
    virtual void set_path(const char* path) = 0;
    virtual void set_flags(unsigned int flags) = 0;

    virtual ~ICallPathFanotify(){};
};

// Special case for fstat, f<op>xattr and fchdir
class ICallPathF : public virtual ICallPathBase {
    public:
    virtual int is_l() const = 0;
    virtual int is_f() const = 0;
    virtual int get_flags() const = 0;

    virtual void clear_l() = 0;
    virtual void set_flags(int flags) = 0;

    virtual ~ICallPathF(){};
};

class ICallPathDual : public virtual ICallBase {
    public:
    virtual int get_old_dirfd() const = 0;
    virtual const char* get_old_path() const = 0;
    virtual void set_old_dirfd(int dirfd) = 0;
    virtual void set_old_path(const char* path) = 0;

    virtual int get_new_dirfd() const = 0;
    virtual const char* get_new_path() const = 0;
    virtual void set_new_dirfd(int dirfd) = 0;
    virtual void set_new_path(const char* path) = 0;

    virtual int get_flags() const = 0;
    virtual void set_flags(int flags) = 0;

    virtual ~ICallPathDual(){};
};

class ICallPathSymlink : public virtual ICallBase {
    public:
    virtual const char* get_old_path() const = 0;
    virtual void set_old_path(const char* path) = 0;

    virtual int get_new_dirfd() const = 0;
    virtual const char* get_new_path() const = 0;
    virtual void set_new_dirfd(int dirfd) = 0;
    virtual void set_new_path(const char* path) = 0;

    virtual int get_flags() const = 0;
    virtual void set_flags(int flags) = 0;

    virtual ~ICallPathSymlink(){};
};

class ICallPathConnect : public virtual ICallBase {
    public:
    virtual sa_family_t get_family() const = 0;
    virtual void* get_addr() const = 0;

    virtual void set_addr(void* addr, size_t size) = 0;

    virtual ~ICallPathConnect(){};
};

class CallBase : public virtual ICallBase {
    IDestroyCB* cb{};

    public:
    void set_destroy_cb(IDestroyCB* cb) {
        if (this->cb) {
            abort();
        }
        this->cb = cb;
    }

    virtual ~CallBase() {
        if (cb) {
            delete cb;
        }
    }
};