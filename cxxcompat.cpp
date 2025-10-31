#include <stdlib.h>

namespace std {
void __throw_out_of_range_fmt(char const*, ...);
};

void std::__throw_out_of_range_fmt(char const*, ...) {
    abort();
}