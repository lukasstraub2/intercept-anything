
#include "nolibc.h"
#include "tls.h"

int main(int argc, char **argv) {
	for (int i = 1; i <= TLS_LIST_ALLOC; i++) {
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

	for (int i = 1; i <= TLS_LIST_ALLOC; i++) {
		TlsList *tls = tls_search_binary(i);
		if (!tls) {
			abort();
		}
	}

	for (int i = 1; i <= TLS_LIST_ALLOC; i++) {
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

	for (int i = TLS_LIST_ALLOC; i >= 2; i--) {
		if (!tls_search_binary(i)) {
			abort();
		}

		_tls_free(i);
	}

	for (int i = 2; i <= TLS_LIST_ALLOC; i++) {
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

	for (int i = TLS_LIST_ALLOC; i >= 2; i--) {
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

	for (int i = TLS_LIST_ALLOC; i >= 2; i--) {
		Tls *tls = _tls_get(i);
		if (!tls) {
			abort();
		}

		if (tls->data[0]) {
			abort();
		}

		memcpy(tls->data, &i, sizeof(int));
		if (!_tls_get(i)) {
			abort();
		}
	}

	for (int i = 2; i <= TLS_LIST_ALLOC; i++) {
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

	if (!tls_search_binary(1)) {
		abort();
	}
	tls = _tls_get(1);
	if (!tls) {
		abort();
	}

	memcpy(&stored, tls->data, sizeof(int));
	if (stored != 1) {
		abort();
	}

	_tls_free(1);

	return 0;
}
