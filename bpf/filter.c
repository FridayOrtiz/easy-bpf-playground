#include <uapi/linux/bpf.h>

static unsigned long long (*bpf_get_smp_processor_id)(void) =
    (void *)8;
static int (*bpf_perf_event_output)(void *ctx, void *map, unsigned long long flags, void *data, int size) =
    (void *)25;
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
    (void *)6;


/* Helper macro to print out debug messages */
#define bpf_printk(fmt, ...)                            \
({                                                      \
        char ____fmt[] = fmt;                           \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

__attribute__((section("your_bpf_program"), used)) int your_bpf_program(struct __sk_buff *ctx) {
    bpf_printk("Hello, world!\n");
    return TC_ACT_OK;
}

char _license[] __attribute__((section("license"), used)) = "Dual MIT/GPL";
uint32_t _version __attribute__((section("version"), used)) = 0xFFFFFFFE;
