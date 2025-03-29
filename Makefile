CC=gcc

# x86_64 or aarch64
ARCH=x86_64
COMMON_CFLAGS=-g -O1 -pipe -Wall -Wextra -Wno-unused-parameter -fno-stack-protector -fvisibility=hidden -fPIC -I include
CFLAGS=$(COMMON_CFLAGS) -nostdinc -I include/nolibc -I "include/linux-headers/${ARCH}/include"
LDFLAGS=-nostartfiles -nodefaultlibs -nostdlib -lgcc -Wl,--no-relax
STATIC_ADDRESS=-Wl,-Ttext-segment,0xA0000000 -static
common_objects=loader.o loader_main.o mylock.o rmap.o tls.o intercept_seccomp.o util.o signalmanager.o workarounds.o
androidislinux_objects=$(addprefix androidislinux_tool/,noxattrs.o hardlinkshim.o rootlink.o rootshim.o androidislinux.o)

%.o: %.c *.h
	$(CC) -c -o $@ $< $(CFLAGS)

all: androidislinux norootlink emulate_swap libexecve_here.so mylock_test rwlock_test execve_here_test libexecve_here.so

androidislinux: $(common_objects) $(androidislinux_objects) androidislinux_tool/main.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS) $(STATIC_ADDRESS)

norootlink: $(common_objects) $(androidislinux_objects) androidislinux_tool/norootlink.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS) $(STATIC_ADDRESS)

emulate_swap: $(common_objects) emulate_swap_tool/emulate_swap.o emulate_swap_tool/emulate_swap_main.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS) $(STATIC_ADDRESS)

libexecve_here.so: loader.o execve_here.o libexecve_here.o libexecve_thread.c
	$(CC) -o $@ $^ $(COMMON_CFLAGS) $(LDFLAGS) -shared -pthread

tls_test: util.o rmap.o tls.o tls_test.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

mylock_test: util.o rmap.o tls.o mylock.o mylock_test.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

rwlock_test: util.o rmap.o tls.o mylock.o rwlock_test.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

execve_here_test: loader.o execve_here.o execve_here_test.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

.PHONY: clean check format

format:
	find . -maxdepth 2 -type f -name '*.c' -print0 -or -name '*.h' -print0 | xargs -0 clang-format -i --style='{BasedOnStyle: Chromium, IndentWidth: 4, SortIncludes: false}'

# skip tls_test
check: mylock_test rwlock_test
	$(foreach EXEC,$^, echo "./${EXEC}"; ./${EXEC} || exit 1;)

clean:
	rm -f *.o androidislinux_tool/*.o emulate_swap_tool/*.o androidislinux norootlink emulate_swap tls_test mylock_test rwlock_test
