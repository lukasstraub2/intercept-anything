#undef _FORTIFY_SOURCE

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

#include "fastpath_preload.h"

#include <errno.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/epoll.h>
#include <sys/poll.h>

#ifndef _NSIG
#define _NSIG 65
#endif

#undef epoll_wait
int epoll_wait(int epfd,
               struct epoll_event* events,
               int maxevents,
               int timeout) {
#ifdef __NR_epoll_wait
    int ret;

    maybe_init();

    ret = entry(__NR_epoll_wait, epfd, (unsigned long)events, maxevents,
                timeout, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
#else
    return epoll_pwait(epfd, events, maxevents, timeout, NULL);
#endif
}

#undef epoll_pwait
int epoll_pwait(int epfd,
                struct epoll_event* events,
                int maxevents,
                int timeout,
                const sigset_t* sigmask) {
    int ret;

    maybe_init();

    ret = entry(__NR_epoll_pwait, epfd, (unsigned long)events, maxevents,
                timeout, (unsigned long)sigmask, _NSIG / 8);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef epoll_pwait2
int epoll_pwait2(int epfd,
                 struct epoll_event* events,
                 int maxevents,
                 const struct timespec* timeout,
                 const sigset_t* sigmask) {
    int ret;

    maybe_init();

    ret = entry(__NR_epoll_pwait2, epfd, (unsigned long)events, maxevents,
                (unsigned long)timeout, (unsigned long)sigmask, _NSIG / 8);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef epoll_create
int epoll_create(int size) {
#ifdef __NR_epoll_create
    int ret;

    maybe_init();

    ret = entry(__NR_epoll_create, size, 0, 0, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
#else
    if (size <= 0) {
        errno = EINVAL;
        return -1;
    }

    return epoll_create1(0);
#endif
}

#undef epoll_create1
int epoll_create1(int flags) {
    int ret;

    maybe_init();

    ret = entry(__NR_epoll_create1, flags, 0, 0, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef epoll_ctl
int epoll_ctl(int epfd, int op, int fd, struct epoll_event* event) {
    int ret;

    maybe_init();

    ret = entry(__NR_epoll_ctl, epfd, op, fd, (unsigned long)event, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef poll
int poll(struct pollfd* fds, nfds_t nfds, int timeout) {
#ifdef __NR_poll
    int ret;

    maybe_init();

    ret = entry(__NR_poll, (unsigned long)fds, nfds, timeout, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
#else
    struct timespec timeout_ts;
    struct timespec* timeout_ts_p = NULL;

    if (timeout >= 0) {
        timeout_ts.tv_sec = timeout / 1000;
        timeout_ts.tv_nsec = (timeout % 1000) * 1000000;
        timeout_ts_p = &timeout_ts;
    }

    return ppoll(fds, nfds, timeout_ts_p, NULL);
#endif
}

#undef ppoll
int ppoll(struct pollfd* fds,
          nfds_t nfds,
          const struct timespec* tmo_p,
          const sigset_t* sigmask) {
    int ret;

    maybe_init();

    ret = entry(__NR_ppoll, (unsigned long)fds, nfds, (unsigned long)tmo_p,
                (unsigned long)sigmask, _NSIG / 8, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}