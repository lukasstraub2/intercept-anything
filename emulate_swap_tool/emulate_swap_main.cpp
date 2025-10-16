
#include "intercept.h"
#include "emulate_swap.h"
#include "workarounds.h"

const CallHandler* main_init(const CallHandler* bottom, int recursing) {
    const CallHandler* emulate_swap = emulate_swap_init(bottom);
    const CallHandler* workarounds = workarounds_init(emulate_swap);
    return workarounds;
}
