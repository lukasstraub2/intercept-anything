
extern "C" {
void abort();
}

typedef struct CallHandler CallHandler;

__attribute__((weak)) char __etext;
__attribute__((weak)) char __start_signal_entry;
__attribute__((weak)) char __stop_signal_entry;

__attribute__((weak)) CallHandler* main_init(CallHandler* bottom,
                                             int recursing) {
    abort();
    return nullptr;
}

__attribute__((weak)) int main(int argc, char** argv) {
    abort();
    return 1;
}
