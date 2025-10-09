/* SPDX-License-Identifier: MIT */
/*
 * MIT License
 *
 * Copyright (c) 2018 Mikhail Ilyin
 * Copyright (c) 2025 Lukas Straub
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

#include "loader.h"
#include "trampo.h"
#include "intercept.h"
#include "features.h"
#include "../libs/musl/src/include/features.h"
#include "../libs/musl/src/internal/libc.h"

#define DEBUG_ENV "DEBUG_LOADER"
#include "debug.h"

#include <string.h>
#include <unistd.h>

extern char** environ;
int main(int argc, char** argv, char** envp) {
    unsigned long* sp = (unsigned long*)argv;
    sp--;
    unsigned long* auxv;
    void* after_auxv;
    char** p;
    struct LoaderInfo info;

    for (p = envp; *p++;)
        ;
    auxv = (unsigned long*)p;

    if (argc < 2)
        exit_error("no input file");

    int recursing = !strcmp(argv[0], "loader_recurse");
    intercept_init(recursing, argv[1]);

    load_file(&info, argv[1]);

    after_auxv = patch_auxv(auxv, &info, argv[1]);

    /* Shift argv, env and av. */
    memcpy(&argv[0], &argv[1],
           (unsigned long)after_auxv - (unsigned long)&argv[1]);
    environ--;
    libc.auxv--;
    /* SP points to argc. */
    (*sp)--;

    z_trampo((void (*)(void))(info.elf_interp ? info.entry[Z_INTERP]
                                              : info.entry[Z_PROG]),
             sp, nullptr);
    /* Should not reach. */
    exit(0);
}
