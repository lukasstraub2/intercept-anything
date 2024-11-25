CC=gcc

# x86_64 or aarch64
ARCH=x86_64
CFLAGS=-g -O1 -pipe -Wall -Wextra -Wno-unused-parameter -fno-ident -fno-stack-protector -nostdinc -I include -I include/nolibc -I "include/linux-headers/${ARCH}/include"
LDFLAGS=-nostartfiles -nodefaultlibs -nostdlib -Wl,-Ttext-segment,0xA0000000 '-Wl,--defsym=__start_text=ADDR(.text)' -Wl,--no-undefined -static -lgcc
common_objects=loader.o mylock.o rmap.o tls.o intercept_seccomp.o util.o signalmanager.o workarounds.o
androidislinux_objects=noxattrs.o hardlinkshim.o rootlink.o rootshim.o androidislinux.o

%.o: %.c *.h
	$(CC) -c -o $@ $< $(CFLAGS)

all: rootlink norootlink emulate_swap check

rootlink: $(common_objects) $(androidislinux_objects) main.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

norootlink: $(common_objects) $(androidislinux_objects) norootlink.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

emulate_swap: $(common_objects) emulate_swap.o emulate_swap_main.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

tls_test: util.o rmap.o tls.o tls_test.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

mylock_test: util.o rmap.o tls.o mylock.o mylock_test.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

rwlock_test: util.o rmap.o tls.o mylock.o rwlock_test.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

.PHONY: clean check

# skip tls_test
check: mylock_test rwlock_test
	$(foreach EXEC,$^, echo "./${EXEC}"; ./${EXEC} || exit 1;)

clean:
	rm -f *.o rootlink norootlink emulate_swap tls_test mylock_test rwlock_test
