CMAKE=cmake
CTEST=ctest

.PHONY: clean check format

all: compile

build:
	$(CMAKE) -B build

compile: build
	$(MAKE) -C build

clean:
	rm -rf build

check: build
	cd build && $(CTEST) -j4

format:
	find . -maxdepth 2 -type f -name '*.c' -print0 -or -name '*.h' -print0 | xargs -0 clang-format -i --style=file
