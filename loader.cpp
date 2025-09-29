/* SPDX-License-Identifier: MIT */
/*
 * MIT License
 *
 * Copyright (c) 2018 Mikhail Ilyin
 * Copyright (c) 2024 Lukas Straub
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "mynolibc.h"

#include "loader.h"
#include "mprotect.h"
#include "trampo.h"
#include "myelf.h"

#define DEBUG_ENV "DEBUG_LOADER"
#include "debug.h"

#include "util.h"

#define PAGE_SIZE 4096
#define ALIGN (PAGE_SIZE - 1)
#define ROUND_PG(x) (((x) + (ALIGN)) & ~(ALIGN))
#define TRUNC_PG(x) ((x) & ~(ALIGN))
#define PFLAGS(x)                                                   \
    ((((x)&PF_R) ? PROT_READ : 0) | (((x)&PF_W) ? PROT_WRITE : 0) | \
     (((x)&PF_X) ? PROT_EXEC : 0))
#define LOAD_ERR ((unsigned long)-1)

int check_ehdr(Elf_Ehdr* ehdr) {
    unsigned char* e_ident = ehdr->e_ident;
    return (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
            e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3 ||
            e_ident[EI_CLASS] != ELFCLASS ||
            e_ident[EI_VERSION] != EV_CURRENT ||
            (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN))
               ? 0
               : 1;
}

static unsigned long loadelf_anon(int fd, Elf_Ehdr* ehdr, Elf_Phdr* phdr) {
    unsigned long minva, maxva;
    Elf_Phdr* iter;
    ssize_t sz;
    int dyn = ehdr->e_type == ET_DYN;
    unsigned char *p, *base, *hint;

    minva = (unsigned long)-1;
    maxva = 0;

    for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
        if (iter->p_type != PT_LOAD)
            continue;
        if (iter->p_vaddr < minva)
            minva = iter->p_vaddr;
        if (iter->p_vaddr + iter->p_memsz > maxva)
            maxva = iter->p_vaddr + iter->p_memsz;
    }

    minva = TRUNC_PG(minva);
    maxva = ROUND_PG(maxva);

    /* For dynamic ELF let the kernel chose the address. */
    hint = dyn ? nullptr : (void*)minva;

    /* Check that we can hold the whole image. */
    base = sys_mmap(hint, maxva - minva, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS,
                    -1, 0);
    if ((unsigned long)base >= -4095UL) {
        return LOAD_ERR;
    }
    sys_munmap(base, maxva - minva);
    /* For !dyn, we want MAP_FIXED_NOREPLACE behaviour, but older kernels do
     * not support it. So check if the kernel modified the mapping due to
     * collisions.
     */
    if (!dyn && base != hint) {
        return LOAD_ERR;
    }

    /* Now map each segment separately in precalculated address. */
    for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
        unsigned long off, start;
        if (iter->p_type != PT_LOAD)
            continue;
        off = iter->p_vaddr & ALIGN;
        start = dyn ? (unsigned long)base : 0;
        start += TRUNC_PG(iter->p_vaddr);
        sz = ROUND_PG(iter->p_memsz + off);

        p = sys_mmap((void*)start, sz, PROT_WRITE,
                     MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if ((unsigned long)p >= -4095UL)
            goto err;
        if (sys_lseek(fd, iter->p_offset, SEEK_SET) < 0)
            goto err;
        if (sys_read(fd, p + off, iter->p_filesz) != (ssize_t)iter->p_filesz)
            goto err;
        sys_mprotect(p, sz, PFLAGS(iter->p_flags));
    }

    return (unsigned long)base;
err:
    sys_munmap(base, maxva - minva);
    return LOAD_ERR;
}

int load_file(struct LoaderInfo* info, const char* file) {
    Elf_Ehdr* ehdr = info->ehdrs;
    unsigned long* base = info->base;
    unsigned long* entry = info->entry;
    info->elf_interp = nullptr;
    Elf_Phdr *phdr, *iter;
    ssize_t sz;
    int fd, i;

    for (i = 0;; i++, ehdr++) {
        /* Open file, read and than check ELF header.*/
        if ((fd = loader_open(file, O_RDONLY, 0)) < 0)
            exit_error("can't open %s", file);
        if (sys_read(fd, ehdr, sizeof(*ehdr)) != sizeof(*ehdr))
            exit_error("can't read ELF header %s", file);
        if (!check_ehdr(ehdr))
            exit_error("bogus ELF header %s", file);

        /* Read the program header. */
        sz = ehdr->e_phnum * sizeof(Elf_Phdr);
        phdr = alloca(sz);
        if (sys_lseek(fd, ehdr->e_phoff, SEEK_SET) < 0)
            exit_error("can't lseek to program header %s", file);
        if (sys_read(fd, phdr, sz) != sz)
            exit_error("can't read program header %s", file);
        /* Time to load ELF. */
        if ((base[i] = loadelf_anon(fd, ehdr, phdr)) == LOAD_ERR)
            exit_error("can't load ELF %s", file);

        /* Set the entry point, if the file is dynamic than add bias. */
        entry[i] = ehdr->e_entry + (ehdr->e_type == ET_DYN ? base[i] : 0);
        /* The second round, we've loaded ELF interp. */
        if (file == info->elf_interp)
            break;
        for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
            if (iter->p_type != PT_INTERP)
                continue;
            info->elf_interp = alloca(iter->p_filesz);
            if (sys_lseek(fd, iter->p_offset, SEEK_SET) < 0)
                exit_error("can't lseek interp segment");
            if (sys_read(fd, info->elf_interp, iter->p_filesz) !=
                (ssize_t)iter->p_filesz)
                exit_error("can't read interp segment");
            if (info->elf_interp[iter->p_filesz - 1] != '\0')
                exit_error("bogus interp path");
            file = info->elf_interp;
        }
        /* Looks like the ELF is static -- leave the loop. */
        if (info->elf_interp == nullptr)
            break;

        sys_close(fd);
    }

    sys_close(fd);

    return 0;
}

/* Reassign some vectors that are important for
 * the dynamic linker and for lib C. */
void* patch_auxv(unsigned long* auxv,
                 struct LoaderInfo* info,
                 const char* argv0) {
    Elf_Ehdr* ehdrs = info->ehdrs;
    unsigned long* base = info->base;
    unsigned long* entry = info->entry;
    char* elf_interp = info->elf_interp;

#define AVSET(t, expr)    \
    if (auxv[0] == (t)) { \
        auxv[1] = (expr); \
    }

    while (auxv[0] != AT_NULL) {
        AVSET(AT_PHDR, base[Z_PROG] + ehdrs[Z_PROG].e_phoff);
        AVSET(AT_PHNUM, ehdrs[Z_PROG].e_phnum);
        AVSET(AT_PHENT, ehdrs[Z_PROG].e_phentsize);
        AVSET(AT_ENTRY, entry[Z_PROG]);
        AVSET(AT_EXECFN, (unsigned long)argv0);
        AVSET(AT_BASE, elf_interp ? base[Z_INTERP] : auxv[1]);

        auxv += 2;
    }
#undef AVSET

    return auxv + 2;
}
