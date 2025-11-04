CMAKE=cmake
CTEST=ctest
DIR=out

.PHONY: clean check format lint

all: compile

libs/musl/CMakeLists.txt:
	git submodule update --init libs/musl

$(DIR): libs/musl/CMakeLists.txt
	$(CMAKE) -B $(DIR)

compile: $(DIR)
	$(MAKE) -C $(DIR)

clean:
	rm -rf $(DIR)

check: compile lint
	cd $(DIR) && $(CTEST)

format:
	find . -maxdepth 2 -type f -name '*.c' -print0 -or -name '*.cpp' -print0 -or -name '*.h' -print0 | xargs -0 clang-format -i --style=file

lint:
	clang-tidy -p . --format-style=file --checks=-\*,cppcoreguidelines-pro-type-member-init -header-filter=syscalls_\* syscalls_*.cpp intercept_seccomp.cpp
