
#include "common.h"

#include "util.h"
#include "nolibc.h"

size_t concat(char *out, size_t out_len, const char *a, const char *b) {
	const size_t a_len = strlen(a);
	const size_t b_len = strlen(b);

	if (!out) {
		return a_len + b_len +1;
	}

	if (a_len +1 > out_len) {
		memcpy(out, a, out_len);
		out[out_len -1] = '\0';
		return a_len + b_len +1;
	}

	memcpy(out, a, a_len +1);
	memcpy(out + a_len, b, min(b_len +1, out_len - a_len));
	out[out_len -1] = '\0';

	return a_len + b_len +1;
}

int strcmp_prefix(const char *a, const char *b) {
	return strncmp(a, b, strlen(b));
}
