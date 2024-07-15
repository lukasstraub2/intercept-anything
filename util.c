
#include "common.h"

#include "util.h"
#include "nolibc.h"
#include "tls.h"
#include "mysys.h"

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

static int getcwd_cache_hit(Cache *cache) {
	return cache->type == CACHETYPE_GETCWD;
}

int getcwd_cache(Cache *cache, char *out, size_t out_len) {
	// This function is reentrant as it accesses global thread data

	if (out && !out_len) {
		abort();
	}

	while (1) {
		uint32_t cnt = TLS_INC_FETCH(cache->reentrant_cnt);
		TLS_BARRIER();

		if (out && getcwd_cache_hit(cache)) {
			unsigned int ret = cache->out_len;

			if (ret > out_len) {
				return -ERANGE;
			}

			memcpy(out, cache->out, min(out_len, ret));

			TLS_BARRIER();
			if (cnt != TLS_READ(cache->reentrant_cnt)) {
				continue;
			}
			return ret;
		}

		if (out) {
			int ret = sys_getcwd(out, out_len);
			if (ret < 0) {
				return ret;
			}
			return ret;
		} else {
			cache->type = CACHETYPE_GETCWD;

			int ret = sys_getcwd(cache->out, SCRATCH_SIZE);
			if (ret < 0) {
				return ret;
			}

			cache->out_len = ret;
			TLS_BARRIER();
			if (cnt != TLS_READ(cache->reentrant_cnt)) {
				continue;
			}
			return ret;
		}
	}
}

static ssize_t _readlinkat(int dirfd, const char *path, char *out,
						   size_t out_len) {
	ssize_t ret;

	ret = sys_readlinkat(dirfd, path, out, out_len);
	if (ret < 0) {
		return ret;
	} else if ((size_t)ret == out_len) {
		return -ERANGE;
	}
	out[ret] = '\0';

	return ret +1;
}

static int readlink_cache_hit(Cache *cache, int dirfd, const char *path) {
	return cache->type == CACHETYPE_READLINK
			&& dirfd == cache->in_dirfd
			&& !strcmp(path, cache->in_path);
}

ssize_t readlink_cache(Cache *cache, char *out, size_t out_len,
					   int dirfd, const char *path) {
	// This function is reentrant as it accesses global thread data

	if (out && !out_len) {
		abort();
	}

	while (1) {
		uint32_t cnt = TLS_INC_FETCH(cache->reentrant_cnt);
		TLS_BARRIER();

		if (out && readlink_cache_hit(cache, dirfd, path)) {
			size_t ret = cache->out_len;
			memcpy(out, cache->out, min(out_len, ret));

			if (ret > out_len) {
				return -ERANGE;
			}

			TLS_BARRIER();
			if (cnt != TLS_READ(cache->reentrant_cnt)) {
				continue;
			}
			return ret;
		}

		if (out) {
			ssize_t ret = _readlinkat(dirfd, path, out, out_len);
			if (ret < 0) {
				return ret;
			}
			return ret;
		} else {
			size_t path_len = strlen(path) +1;
			cache->type = CACHETYPE_READLINK;
			cache->in_dirfd = dirfd;
			memcpy(cache->in_path, path, path_len);

			ssize_t ret = _readlinkat(dirfd, path, cache->out, SCRATCH_SIZE);
			if (ret < 0) {
				return ret;
			}

			cache->out_len = ret;
			TLS_BARRIER();
			if (cnt != TLS_READ(cache->reentrant_cnt)) {
				continue;
			}
			return ret;
		}
	}
}
