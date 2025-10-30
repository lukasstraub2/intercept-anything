
#include "intercept.h"
#include "emulate_swap.h"
#include "workarounds.h"

CallHandler* main_init(CallHandler* const bottom, int recursing) {
    CallHandler* const emulate_swap = emulate_swap_init(bottom);
    CallHandler* const workarounds = workarounds_init(emulate_swap);
    return workarounds;
}
