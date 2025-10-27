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
".set data.vfork_idx_addr, 112\n"
".set data.set_tid_addr, 120\n"
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
    "je child\n\t"
    "xor %rdi, %rdi\n\t"
    "movq data.vfork_idx_addr(%r12), %rsi\n\t"
    "test %rsi, %rsi\n\t"
    "jz 1f\n\t"
    "decq (%rsi)\n"
"1:\n\t"
    "test %rax, %rax\n\t"
    "jg skip_sig_sys\n\t"
    "movq data.set_tid_addr(%r12), %rsi\n\t"
    "test %rsi, %rsi\n\t"
    "jz 1f\n\t"
    "movq %rdi, (%rsi)\n"
"1:\n\t"
    "decq data.refcnt2(%r12)\n\t"
    "jmp skip_sig_sys\n"
"child:\n\t"
    "movq data.set_tid_addr(%r12), %rsi\n\t"
    "test %rsi, %rsi\n\t"
    "jz 1f\n\t"
    "movq $" str(__NR_gettid) ", %rax\n\t"
    "syscall\n\t"
    "movq %rax, (%rsi)\n"
"1:\n\t"
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
__attribute__((unused)) static unsigned long get_savedreg(void* ucontext) {
    struct ucontext* ctx = (struct ucontext*)ucontext;

    return ctx->uc_mcontext.regs[6];
}

__attribute__((unused)) static void set_savedreg(void* ucontext, unsigned long reg) {
    struct ucontext* ctx = (struct ucontext*)ucontext;

    ctx->uc_mcontext.regs[6] = reg;
}

// there is no absolute jump on aarch64 and syscalls
// do not clobber any registers.
// hacky, but clobber x8 (syscall number) or x16 (ip0) or x17 (ip1)
// x18 is platform-specific and should not be used on android
__asm__(
"syscall_trampo_start:\n\t"
    "svc 0\n\t"
    "ldr x1, [x6, data.arg2]\n\t"
    "ldr x2, [x6, data.arg3]\n\t"
    "ldr x3, [x6, data.arg4]\n\t"
    "ldr x4, [x6, data.arg5]\n\t"
    "ldr x5, [x6, data.arg6]\n\t"
    "mov x1, x6\n\t"
    "ldr x6, [x1, data.savedreg]\n\t"
    "ldr x8, [x1, data.jmp_addr]\n\t"
    "str xzr, [x1, data.refcnt1]\n\t"
    "br x8\n\t"
    "wfi\n"
);

__asm__(
"clone_trampo_start:\n\t"
    "svc 0\n\t"
    "mov x5, x0\n\t"
    "cmp x0, #0\n\t"
    "b.eq child\n\t"
    "ldr x1, [x6, data.vfork_idx_addr]\n\t"
    "cmp x1, #0\n\t"
    "b.eq 1f\n\t"
    "ldr x2, [x1]\n\t"
    "sub x2, x2, #1\n\t"
    "str x2, [x1]\n\t"
"1:\n\t"
    "cmp x0, #0\n\t"
    "b.gt skip_sig_sys\n\t"
    "ldr x1, [x6, data.set_tid_addr]\n\t"
    "cmp x1, #0\n\t"
    "b.eq 1f\n\t"
    "str xzr, [x1]\n"
"1:\n\t"
    "str xzr, [x6, data.refcnt2]\n\t"
    "b skip_sig_sys\n"
"child:\n\t"
    "ldr x1, [x6, data.set_tid_addr]\n\t"
    "cmp x1, #0\n\t"
    "b.eq 1f\n\t"
    "mov x8, #" str(__NR_gettid) "\n\t"
    "svc 0\n\t"
    "str x0, [x1]\n"
"1:\n\t"
    "ldr x1, [x6, data.sig_dfl_addr]\n\t"
    "cmp x1, #0\n\t"
    "b.eq skip_sig_dfl\n\t"
    "mov x4, #64\n\t"
    "mov x2, #0\n\t"
    "mov x3, #8\n"
"sig_dfl_loop:\n\t"
    "mov x8, #" str(__NR_rt_sigaction) "\n\t"
    "mov x0, x4\n\t"
    "svc 0\n\t"
    "cmp x0, #0\n\t"
    "b.ne abort\n"
"0:\n\t"
    "add x1, x1, #32\n\t"
    "sub x4, x4, #1\n\t"
    "cmp x4, #" str(SIGKILL) "\n\t"
    "b.eq 0b\n\t"
    "cmp x4, #" str(SIGSTOP) "\n\t"
    "b.eq 0b\n\t"
    "cmp x4, #0\n\t"
    "b.ne sig_dfl_loop\n"
"skip_sig_dfl:\n\t"
    "ldr x1, [x6, data.sig_sys_addr]\n\t"
    "cmp x1, #0\n\t"
    "b.eq skip_sig_sys\n\t"
    "mov x8, #" str(__NR_rt_sigaction) "\n\t"
    "mov x0, #" str(SIGSYS) "\n\t"
    "mov x2, #0\n\t"
    "mov x3, #8\n\t"
    "svc 0\n\t"
    "cmp x0, #0\n\t"
    "b.ne abort\n"
"skip_sig_sys:\n\t"
    "ldr x1, [x6, data.sig_mask]\n\t"
    "cmp x1, #0\n\t"
    "b.eq skip_sig_mask\n\t"
    "mov x8, #" str(__NR_rt_sigprocmask) "\n\t"
    "mov x0, #" str(SIG_SETMASK) "\n\t"
    "mov x2, #0\n\t"
    "mov x3, #8\n\t"
    "svc 0\n\t"
    "cmp x0, #0\n\t"
    "b.ne abort\n"
"skip_sig_mask:\n\t"
    "mov x0, x5\n\t"
    "ldr x2, [x6, data.arg3]\n\t"
    "ldr x3, [x6, data.arg4]\n\t"
    "ldr x4, [x6, data.arg5]\n\t"
    "ldr x5, [x6, data.arg6]\n\t"
    "mov x1, x6\n\t"
    "ldr x6, [x1, data.savedreg]\n\t"
    "ldr x8, [x1, data.jmp_addr]\n\t"
    "cmp x0, #0\n\t"
    "b.eq 1f\n\t"
    "str xzr, [x1, data.refcnt1]\n\t"
    "br x8\n\t"
    "wfi\n"
"1:\n\t"
    "str xzr, [x1, data.refcnt2]\n\t"
    "br x8\n\t"
    "wfi\n"
"abort:\n\t"
    "mov x8, #" str(__NR_gettid) "\n\t"
    "svc 0\n\t"
    "mov x0, x1\n\t"
    "mov x1, #" str(SIGSYS) "\n\t"
    "mov x8, #" str(__NR_tkill) "\n\t"
    "svc 0\n\t"
    "wfi\n"
);

#else
#error Unsupported Architecture
#endif
// clang-format on