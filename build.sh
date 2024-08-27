#!/bin/bash

set -e

if [ -z "$1" ]; then
        echo "Usage: $0 [x86_64|i386|aarch64|arm]" >&2
        exit 1
fi
ARCH="$1"

build_main() {
	out="$1"
	shift
	# -fPIC -pie
	# Box64 loads at 0x34800000
	# Wine loads at  0x60000000
	# We load at     0xA0000000
	# since the seccomp filter is inherited by all children
	# and we need to load to the same address in all processes
	cc -g -O1 -pipe -Wall -Wextra -Wno-unused-parameter -Wno-error=incompatible-pointer-types -fno-ident -fno-stack-protector -nostdinc -I include -I include/nolibc -I "include/linux-headers/${ARCH}/include" \
		-nostartfiles -nodefaultlibs -nostdlib -Wl,-Ttext-segment,0xA0000000 '-Wl,--defsym=__start_text=ADDR(.text)' -Wl,--no-undefined -static -o "$out" \
		loader.c mylock.c rmap.c tls.c intercept_seccomp.c util.c signalmanager.c noxattrs.c hardlinkshim.c rootlink.c rootshim.c androidislinux.c workarounds.c "$@" -lgcc
	#LDFLAGS += -Wl,-Bsymbolic,--no-undefined,--build-id=none -Wl,-Ttext-segment,0xA0000000 '-Wl,--defsym=__start_text=ADDR(.text)' -static
}

build_main loader main.c
build_main norootlink norootlink.c

cc -g -O1 -pipe -Wall -Wextra -Wno-unused-parameter -fno-ident -fno-stack-protector -nostdinc -I include -I include/nolibc -I "include/linux-headers/${ARCH}/include" \
	-nostartfiles -nodefaultlibs -nostdlib -Wl,-Ttext-segment,0xA0000000 '-Wl,--defsym=__start_text=ADDR(.text)' -Wl,--no-undefined -static -o tls_test \
        util.c rmap.c tls.c tls_test.c -lgcc

cc -g -O1 -pipe -Wall -Wextra -Wno-unused-parameter -fno-ident -fno-stack-protector -nostdinc -I include -I include/nolibc -I "include/linux-headers/${ARCH}/include" \
	-nostartfiles -nodefaultlibs -nostdlib -Wl,-Ttext-segment,0xA0000000 '-Wl,--defsym=__start_text=ADDR(.text)' -Wl,--no-undefined -static -o mylock_test \
        util.c rmap.c tls.c mylock.c mylock_test.c -lgcc

cc -g -O1 -pipe -Wall -Wextra -Wno-unused-parameter -fno-ident -fno-stack-protector -nostdinc -I include -I include/nolibc -I "include/linux-headers/${ARCH}/include" \
	-nostartfiles -nodefaultlibs -nostdlib -Wl,-Ttext-segment,0xA0000000 '-Wl,--defsym=__start_text=ADDR(.text)' -Wl,--no-undefined -static -o rwlock_test \
        util.c rmap.c tls.c mylock.c rwlock_test.c -lgcc
