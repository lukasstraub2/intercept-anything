#!/bin/bash

set -e

cc -fPIC -fvisibility=hidden -fno-omit-frame-pointer -shared -O1 -g -Wall -Wno-unused-function -Wno-comment -Wno-nonnull-compare -Wmissing-prototypes \
	-I include -o rootlink.so \
	util.c intercept_glibc.c rootshim.c rootlink.c noxattrs.c signalshim.c hardlinkshim.c main.c

cc -pie -fno-omit-frame-pointer -O1 -g -Wall -o posix_spawnp_helper posix_spawnp_helper.c

# -fPIC -pie
cc -pipe -Wall -Wextra -fno-ident -fno-stack-protector -DELFCLASS=ELFCLASS64 -nostdinc -I include -I include/nolibc -I include/linux-headers/x86_64/include \
	-nostartfiles -nodefaultlibs -nostdlib -Wl,-Ttext-segment,0xA0000000 '-Wl,--defsym=__start_text=ADDR(.text)' -static -o loader \
	loader.c intercept_seccomp.c _start.c
#LDFLAGS += -Wl,-Bsymbolic,--no-undefined,--build-id=none -Wl,-Ttext-segment,0xA0000000 '-Wl,--defsym=__start_text=ADDR(.text)' -static
