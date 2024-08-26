#pragma once

#include "types.h"
#include "myseccomp.h"

#include <asm/sigcontext.h>
#include <asm/ucontext.h>

#define AUDIT_ARCH_CURRENT AUDIT_ARCH_AARCH64

__attribute__((unused))
static void fill_sysargs(SysArgs *args, void *ucontext) {
	struct ucontext* ctx = (struct ucontext*)ucontext;

	args->num = ctx->uc_mcontext.regs[8];
	args->arg1 = ctx->uc_mcontext.regs[0];
	args->arg2 = ctx->uc_mcontext.regs[1];
	args->arg3 = ctx->uc_mcontext.regs[2];
	args->arg4 = ctx->uc_mcontext.regs[3];
	args->arg5 = ctx->uc_mcontext.regs[4];
	args->arg6 = ctx->uc_mcontext.regs[5];
}

__attribute__((unused))
static void set_return(void *ucontext, unsigned long ret) {
	struct ucontext* ctx = (struct ucontext*)ucontext;

	ctx->uc_mcontext.regs[0] = ret;
}

__attribute__((unused))
static void *get_pc(void *ucontext) {
	struct ucontext* ctx = (struct ucontext*)ucontext;

	return (void *)ctx->uc_mcontext.pc;
}
