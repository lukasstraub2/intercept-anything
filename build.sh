#!/bin/bash

set -e

if [ -z "$1" ]; then
        echo "Usage: $0 [x86_64|i386|aarch64|arm]" >&2
        exit 1
fi
ARCH="$1"

#cc -fPIC -fvisibility=hidden -fno-omit-frame-pointer -shared -O1 -g -Wall -Wno-unused-function -Wno-comment -Wno-nonnull-compare -Wmissing-prototypes \
#	-I include -o rootlink.so \
#	util.c intercept_glibc.c rootshim.c rootlink.c noxattrs.c hardlinkshim.c main.c

#cc -pie -fno-omit-frame-pointer -O1 -g -Wall -o posix_spawnp_helper posix_spawnp_helper.c

# -fPIC -pie
# Box64 loads at 0x34800000
# Wine loads at  0x60000000
# We load at     0xA0000000
# since the seccomp filter is inherited by all children
# and we need to load to the same address in all processes
cc -g -O1 -pipe -Wall -Wextra -Wno-unused-parameter -fno-ident -fno-stack-protector -nostdinc -I include -I include/nolibc -I "include/linux-headers/${ARCH}/include" \
	-nostartfiles -nodefaultlibs -nostdlib -Wl,-Ttext-segment,0xA0000000 '-Wl,--defsym=__start_text=ADDR(.text)' -Wl,--no-undefined -static -o loader \
	loader.c intercept_seccomp.c
#LDFLAGS += -Wl,-Bsymbolic,--no-undefined,--build-id=none -Wl,-Ttext-segment,0xA0000000 '-Wl,--defsym=__start_text=ADDR(.text)' -static
