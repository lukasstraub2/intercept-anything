#pragma once

#define _STAT_VER
#define HAVE_OPEN64
#define HAVE_OPENAT
#define _GNU_SOURCE
#define BUF_SIZE (64*1024)

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif
