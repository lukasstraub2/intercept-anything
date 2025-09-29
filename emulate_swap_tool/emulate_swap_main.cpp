
#include "intercept.h"
#include "emulate_swap.h"

const CallHandler* main_init(const CallHandler* bottom, int recursing) {
    const CallHandler* emulate_swap = emulate_swap_init(bottom);
    return emulate_swap;
}
