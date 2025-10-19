
#include "sys.h"
#include "_syscall_trampo.h"
#include "pagesize.h"
#include "myseccomp.h"
#include "syscall_trampo.h"

#include <sys/mman.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

__thread syscall_trampo_data data = {};

static void arm(void* ucontext,
                unsigned long pc,
                unsigned long refcnt1,
                unsigned long refcnt2) {
    SysArgs args;
    fill_sysargs(&args, ucontext);

    while (__atomic_load_n(&data.refcnt1, __ATOMIC_ACQUIRE) ||
           __atomic_load_n(&data.refcnt2, __ATOMIC_ACQUIRE)) {
    }

    data = {};
    data.refcnt1 = refcnt1;
    data.refcnt2 = refcnt2;
    data.jmp_addr = (unsigned long)get_pc(ucontext);
    data.num = args.num;
    data.arg1 = args.arg1;
    data.arg2 = args.arg2;
    data.arg3 = args.arg3;
    data.arg4 = args.arg4;
    data.arg5 = args.arg5;
    data.arg6 = args.arg6;
    data.savedreg = get_savedreg(ucontext);

    set_savedreg(ucontext, (unsigned long)&data);
    set_pc(ucontext, pc);
}

void syscall_trampo_arm(void* ucontext) {
    arm(ucontext, (unsigned long)syscall_trampo_start, 1, 0);
}

void clone_trampo_arm(void* ucontext) {
    arm(ucontext, (unsigned long)clone_trampo_start, 1, 1);
}