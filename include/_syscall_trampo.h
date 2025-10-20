#pragma once

#include "mysignal.h"
#include <signal.h>
#include <syscall.h>

#define str(s) xstr(s)
#define xstr(s) #s

extern const char syscall_trampo_start[1], clone_trampo_start[1];
static_assert(sizeof(struct k_sigaction) == 32, "sizeof(struct k_sigaction)");

// clang-format off

__asm__(
".global syscall_trampo_start\n"
".hidden syscall_trampo_start\n"
".global clone_trampo_start\n"
".hidden clone_trampo_start\n"
".set data.sig_mask, 0\n"
".set data.jmp_addr, 8\n"
".set data.sig_dfl_addr, 16\n"
".set data.sig_sys_addr, 24\n"
".set data.num, 32\n"
".set data.arg1, 40\n"
".set data.arg2, 48\n"
".set data.arg3, 56\n"
".set data.arg4, 64\n"
".set data.arg5, 72\n"
".set data.arg6, 80\n"
".set data.savedreg, 88\n"
".set data.refcnt1, 96\n"
".set data.refcnt2, 104\n"
);

#if defined(__x86_64__)
__attribute__((unused)) static unsigned long get_savedreg(void* ucontext) {
    struct ucontext* ctx = (struct ucontext*)ucontext;

    return ctx->uc_mcontext.gregs[REG_R12];
}

__attribute__((unused)) static void set_savedreg(void* ucontext, unsigned long reg) {
    struct ucontext* ctx = (struct ucontext*)ucontext;

    ctx->uc_mcontext.gregs[REG_R12] = reg;
}

// syscall clobbers rcx and r11
// syscall return is in %rax
// data passed into %r12
__asm__(
"syscall_trampo_start:\n\t"
    "syscall\n\t"
    "movq data.arg1(%r12), %rdi\n\t"
    "movq data.arg2(%r12), %rsi\n\t"
    "movq data.arg3(%r12), %rdx\n\t"
    "movq data.arg4(%r12), %r10\n\t"
    "movq data.arg5(%r12), %r8\n\t"
    "movq data.arg6(%r12), %r9\n\t"
    "movq %r12, %rcx\n\t"
    "movq data.savedreg(%rcx), %r12\n\t"
    "movq data.jmp_addr(%rcx), %r11\n\t"
    "decq data.refcnt1(%rcx)\n\t"
    "jmp *%r11\n\t"
    "hlt\n"
);

__asm__(
"clone_trampo_start:\n\t"
    "syscall\n\t"
    "movq %rax, %r9\n\t"
    "test %rax, %rax\n\t"
    "jge clone_success\n\t"
    "decq data.refcnt2(%r12)\n\t"
    "jmp skip_sig_sys\n"
"clone_success:\n\t"
    "jg skip_sig_sys\n\t"
    "movq data.sig_dfl_addr(%r12), %rsi\n\t"
    "test %rsi, %rsi\n\t"
    "jz skip_sig_dfl\n\t"
    "movq $64, %rdi\n\t"
    "movq $0, %rdx\n\t"
    "movq $8, %r10\n"
"sig_dfl_loop:\n\t"
    "movq $" str(__NR_rt_sigaction) ", %rax\n\t"
    "syscall\n\t"
    "test %rax, %rax\n\t"
    "jnz abort\n"
"0:\n\t"
    "add $32, %rsi\n\t"
    "dec %rdi\n\t"
    "cmpq $" str(SIGKILL) ", %rdi\n\t"
    "jz 0b\n\t"
    "cmpq $" str(SIGSTOP) ", %rdi\n\t"
    "jz 0b\n\t"
    "test %rdi, %rdi\n\t"
    "jnz sig_dfl_loop\n"
"skip_sig_dfl:\n\t"
    "movq data.sig_sys_addr(%r12), %rsi\n\t"
    "test %rsi, %rsi\n\t"
    "jz skip_sig_sys\n\t"
    "movq $" str(__NR_rt_sigaction) ", %rax\n\t"
    "movq $" str(SIGSYS) ", %rdi\n\t"
    "movq $0, %rdx\n\t"
    "movq $8, %r10\n\t"
    "syscall\n\t"
    "test %rax, %rax\n\t"
    "jnz abort\n"
"skip_sig_sys:\n\t"
    "movq data.sig_mask(%r12), %rsi\n\t"
    "test %rsi, %rsi\n\t"
    "jz skip_sig_mask\n\t"
    "movq $" str(__NR_rt_sigprocmask) ", %rax\n\t"
    "movq $" str(SIG_SETMASK) ", %rdi\n\t"
    "movq $0, %rdx\n\t"
    "movq $8, %r10\n\t"
    "syscall\n\t"
    "test %rax, %rax\n\t"
    "jnz abort\n"
"skip_sig_mask:\n\t"
    "movq %r9, %rax\n\t"
    "movq data.arg1(%r12), %rdi\n\t"
    "movq data.arg2(%r12), %rsi\n\t"
    "movq data.arg3(%r12), %rdx\n\t"
    "movq data.arg4(%r12), %r10\n\t"
    "movq data.arg5(%r12), %r8\n\t"
    "movq data.arg6(%r12), %r9\n\t"
    "movq %r12, %rcx\n\t"
    "movq data.savedreg(%rcx), %r12\n\t"
    "movq data.jmp_addr(%rcx), %r11\n\t"
    "test %rax, %rax\n\t"
    "jz 1f\n\t"
    "decq data.refcnt1(%rcx)\n\t"
    "jmp *%r11\n\t"
    "hlt\n"
"1:\n\t"
    "decq data.refcnt2(%rcx)\n\t"
    "jmp *%r11\n\t"
    "hlt\n"
"abort:\n\t"
    "movq $" str(__NR_gettid) ", %rax\n\t"
    "syscall\n\t"
    "movq %rax, %rdi\n\t"
    "movq $" str(SIGABRT) ", %rsi\n\t"
    "movq $" str(__NR_tkill) ", %rax\n\t"
    "syscall\n\t"
    "hlt\n"
);
#elif defined(__aarch64__)
// there is no absolute jump on aarch64 and syscalls
// do not clobber any registers.
// hacky, but clobber x8 (syscall number) or x16 (ip0) or x17 (ip1)
__asm__(
"syscall_trampo_start:\n\t"
    "svc 0\n\t"
    "ldr x8, syscall_trampo_addr\n\t"
    "br x8\n\t"
    "wfi\n"
);
#else
#error Unsupported Architecture
#endif
// clang-format on