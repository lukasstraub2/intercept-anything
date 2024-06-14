#pragma once

#include "types.h"
#include "myseccomp.h"

#include <asm/sigcontext.h>
#include <asm/ucontext.h>

#define AUDIT_ARCH_CURRENT AUDIT_ARCH_X86_64

__attribute__((unused))
static void fill_sysargs(SysArgs *args, void *ucontext) {
	struct ucontext* ctx = (struct ucontext*)ucontext;

	args->num = ctx->uc_mcontext.rax;
	args->arg1 = ctx->uc_mcontext.rdi;
	args->arg2 = ctx->uc_mcontext.rsi;
	args->arg3 = ctx->uc_mcontext.rdx;
	args->arg4 = ctx->uc_mcontext.r10;
	args->arg5 = ctx->uc_mcontext.r8;
	args->arg6 = ctx->uc_mcontext.r9;
}

__attribute__((unused))
static void set_return(void *ucontext, unsigned long ret) {
	struct ucontext* ctx = (struct ucontext*)ucontext;

	ctx->uc_mcontext.rax = ret;
}
