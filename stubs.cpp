
#ifdef __cplusplus
extern "C" {
#endif

void abort();

#ifdef __cplusplus
}
#endif

typedef struct CallHandler CallHandler;

__attribute__((weak)) char __etext;
__attribute__((weak)) char __start_signal_entry;
__attribute__((weak)) char __stop_signal_entry;

__attribute__((weak)) const CallHandler* main_init(const CallHandler* bottom,
                                                   int recursing) {
    abort();
}

__attribute__((weak)) int main(int argc, char** argv) {
    abort();
}
