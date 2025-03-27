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

#pragma once

#include <linux/elf.h>
#include "stdint.h"

typedef struct Elf32_auxv_t Elf32_auxv_t;
struct Elf32_auxv_t {
    uint32_t a_type;
    union {
        uint32_t a_val;
    } a_un;
};

typedef struct Elf64_auxv_t Elf64_auxv_t;
struct Elf64_auxv_t {
    uint64_t a_type;
    union {
        uint64_t a_val;
    } a_un;
};

#if defined(__x86_64__) || defined(__aarch64__)
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
#define Elf_auxv_t Elf64_auxv_t
#define ELFCLASS ELFCLASS64
#elif defined(__i386__) || defined(__i486__) || defined(__i586__) || \
    defined(__i686__)
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Phdr Elf32_Phdr
#define Elf_auxv_t Elf32_auxv_t
#define ELFCLASS ELFCLASS32
#else
#error Unsupported Architecture
#endif
