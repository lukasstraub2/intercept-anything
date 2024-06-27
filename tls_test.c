
#include "nolibc.h"
#include "tls.h"

int main(int argc, char **argv) {
	for (int i = 1; i <= 4096; i++) {
		Tls *tls = _tls_get(i);
		if (!tls) {
			abort();
		}

		if (tls->data[0]) {
			abort();
		}

		memcpy(tls->data, &i, sizeof(int));

		if (!tls_search_binary(i)) {
			abort();
		}
	}

	for (int i = 1; i <= 4096; i++) {
		TlsList *tls = tls_search_binary(i);
		if (!tls) {
			abort();
		}
	}

	for (int i = 1; i <= 4096; i++) {
		Tls *tls = _tls_get(i);
		if (!tls) {
			abort();
		}

		int stored;
		memcpy(&stored, tls->data, sizeof(int));
		if (stored != i) {
			abort();
		}
	}

	for (int i = 4096; i >= 2; i--) {
		if (!tls_search_binary(i)) {
			abort();
		}

		_tls_free(i);
	}

	if (!tls_search_binary(1)) {
		abort();
	}
	Tls *tls = _tls_get(1);
	if (!tls) {
		abort();
	}

	int stored;
	memcpy(&stored, tls->data, sizeof(int));
	if (stored != 1) {
		abort();
	}

	for (int i = 4096; i >= 2; i--) {
		Tls *tls = _tls_get(i);
		if (!tls) {
			abort();
		}

		memcpy(tls->data, &i, sizeof(int));
		if (!_tls_get(i)) {
			abort();
		}
	}

	for (int i = 1; i <= 4096; i++) {
		Tls *tls = _tls_get(i);
		if (!tls) {
			abort();
		}

		int stored;
		memcpy(&stored, tls->data, sizeof(int));
		if (stored != i) {
			abort();
		}

		_tls_free(i);
	}

	return 0;
}
