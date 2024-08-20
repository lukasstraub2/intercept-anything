/*      $NetBSD: queue.h,v 1.52 2009/04/20 09:56:08 mschuett Exp $ */

/*
 * QEMU version: Copy from netbsd, removed debug code, removed some of
 * the implementations.  Left in singly-linked lists, lists, simple
 * queues, and tail queues.
 */

/*
 * Copyright (c) 1991, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)queue.h     8.5 (Berkeley) 8/20/94
 */

#pragma once

#define RLIST_HEAD(name, type) \
struct name { \
		struct type *slh_first; \
}

#define RLIST_ENTRY(type) \
struct { \
		struct type *sle_next; \
}

#define RLIST_INSERT_HEAD(head, elm, field) do { \
		__atomic_store_n(&(elm)->field.sle_next, (head)->slh_first, __ATOMIC_RELAXED); \
		__asm volatile ("" ::: "memory"); \
		__atomic_store_n(&(head)->slh_first, (elm), __ATOMIC_RELAXED); \
} while (0)

#define RLIST_REMOVE_HEAD(head, field) do { \
		__typeof__((head)->slh_first) elm = (head)->slh_first; \
		__atomic_store_n(&(head)->slh_first, elm->field.sle_next, __ATOMIC_RELAXED); \
} while (0)

#define RLIST_REMOVE(head, elm, field) do { \
	if ((head)->slh_first == (elm)) { \
		RLIST_REMOVE_HEAD((head), field); \
	} else { \
		__typeof__((head)->slh_first) curelm = (head)->slh_first; \
		while (curelm->field.sle_next != (elm)) { \
			curelm = curelm->field.sle_next; \
		} \
		__atomic_store_n(&curelm->field.sle_next, curelm->field.sle_next->field.sle_next, __ATOMIC_RELAXED); \
	} \
} while (0)

#define RLIST_FOREACH(var, head, field, tvar) \
		for ((var) = RLIST_FIRST((head)); \
			(var) && ((tvar) = RLIST_NEXT((var), field), 1); \
			(var) = (tvar))

#define RLIST_EMPTY(head) ((head)->slh_first == NULL)
#define RLIST_FIRST(head) ((head)->slh_first)
#define RLIST_NEXT(elm, field) ((elm)->field.sle_next)
