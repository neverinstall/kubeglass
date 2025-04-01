// bpf/write_tracer.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/types.h>

// Simpler data structure for BPF verifier
struct write_event_t {
    __u32 pid;
    __u32 fd;
    char data[240];
    __u32 data_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

// Use built-in BPF tracing struct for safer context access
SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Check if we're watching this PID
    __u32 *watching = bpf_map_lookup_elem(&target_pid, &pid);
    if (!watching)
        return 0;
    
    // Access args carefully using tracing helpers
    struct write_event_t event = {0};
    event.pid = pid;
    
    // Read fd (first argument)
    bpf_probe_read_kernel(&event.fd, sizeof(event.fd), (void *)ctx + 16);
    
    // Read buffer pointer (second argument)
    const void *buf_ptr;
    bpf_probe_read_kernel(&buf_ptr, sizeof(buf_ptr), (void *)ctx + 24);
    
    // Read count (third argument)
    __u64 count;
    bpf_probe_read_kernel(&count, sizeof(count), (void *)ctx + 32);
    
    // Limit data size
    if (count > sizeof(event.data))
        count = sizeof(event.data);
    
    event.data_len = count;
    
    // Read data from user space buffer
    if (count > 0)
        bpf_probe_read_user(event.data, count, buf_ptr);
    
    // Send event to user space
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";