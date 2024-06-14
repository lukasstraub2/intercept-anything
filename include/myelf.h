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

#if ELFCLASS == ELFCLASS64
#  define Elf_Ehdr	Elf64_Ehdr
#  define Elf_Phdr	Elf64_Phdr
#  define Elf_auxv_t	Elf64_auxv_t
#elif ELFCLASS == ELFCLASS32
#  define Elf_Ehdr	Elf32_Ehdr
#  define Elf_Phdr	Elf32_Phdr
#  define Elf_auxv_t	Elf32_auxv_t
#else
#  error "ELFCLASS is not defined"
#endif
