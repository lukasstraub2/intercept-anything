#ifndef _MPROTECT_H
#define _MPROTECT_H

#include "nolibc.h"

static __attribute__((unused))
int sys_mprotect(void *addr, size_t length, int prot)
{
        return my_syscall3(__NR_mprotect, addr, length, prot);
}

#endif /* _MPROTECT_H */
