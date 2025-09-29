CMAKE=cmake
CTEST=ctest
DIR=out

.PHONY: clean check format

all: compile

$(DIR):
	$(CMAKE) -B $(DIR)

compile: $(DIR)
	$(MAKE) -C $(DIR)

clean:
	rm -rf $(DIR)

check: compile
	cd $(DIR) && $(CTEST) -j4

format:
	find . -maxdepth 2 -type f -name '*.c' -print0 -or -name '*.cpp' -print0 -or -name '*.h' -print0 | xargs -0 clang-format -i --style=file
