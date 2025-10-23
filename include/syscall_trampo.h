#pragma once

struct syscall_trampo_data {
    unsigned long sig_mask;
    unsigned long jmp_addr;
    unsigned long sig_dfl_addr;
    unsigned long sig_sys_addr;
    unsigned long num;
    unsigned long arg1;
    unsigned long arg2;
    unsigned long arg3;
    unsigned long arg4;
    unsigned long arg5;
    unsigned long arg6;
    unsigned long savedreg;
    unsigned long refcnt1;
    unsigned long refcnt2;
    unsigned long vfork;
    unsigned long set_tid_addr;
};
typedef struct syscall_trampo_data syscall_trampo_data;

void syscall_trampo_arm(syscall_trampo_data* data, void* ucontext);
void clone_trampo_arm(syscall_trampo_data* data, void* ucontext);