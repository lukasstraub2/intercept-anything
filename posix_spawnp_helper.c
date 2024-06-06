
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
	int ret;

	if (argc < 2) {
		return 127;
	}

	if (!strcmp(argv[0], "posix_spawn")) {
		ret = execv(argv[1], argv + 2);
	} else {
		ret = execvp(argv[1], argv + 2);
	}
	if (ret < 0) {
		return 127;
	}

	return 0;
}
