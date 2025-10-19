#pragma once

#define AUDIT_ARCH_CURRENT AUDIT_ARCH_X86_64
#define stack_grows_down

__attribute__((unused)) static void fill_sysargs(SysArgs* args,
                                                 void* ucontext) {
    struct ucontext* ctx = (struct ucontext*)ucontext;

    args->num = ctx->uc_mcontext.gregs[REG_RAX];
    args->arg1 = ctx->uc_mcontext.gregs[REG_RDI];
    args->arg2 = ctx->uc_mcontext.gregs[REG_RSI];
    args->arg3 = ctx->uc_mcontext.gregs[REG_RDX];
    args->arg4 = ctx->uc_mcontext.gregs[REG_R10];
    args->arg5 = ctx->uc_mcontext.gregs[REG_R8];
    args->arg6 = ctx->uc_mcontext.gregs[REG_R9];
}

__attribute__((unused)) static void set_return(void* ucontext,
                                               unsigned long ret) {
    struct ucontext* ctx = (struct ucontext*)ucontext;

    ctx->uc_mcontext.gregs[REG_RAX] = ret;
}

__attribute__((unused)) static void* get_pc(void* ucontext) {
    struct ucontext* ctx = (struct ucontext*)ucontext;

    return (void*)ctx->uc_mcontext.gregs[REG_RIP];
}

__attribute__((unused)) static void* get_sp(void* ucontext) {
    struct ucontext* ctx = (struct ucontext*)ucontext;

    return (void*)ctx->uc_mcontext.gregs[REG_RSP];
}

__attribute__((unused)) static void set_pc(void* ucontext, unsigned long pc) {
    struct ucontext* ctx = (struct ucontext*)ucontext;

    ctx->uc_mcontext.gregs[REG_RIP] = pc;
}
