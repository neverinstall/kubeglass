// bpf/write_tracer.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/types.h>

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
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} events SEC(".maps");

// Built-in BPF tracing struct for safer context access
SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    __u32 *watching = bpf_map_lookup_elem(&target_pid, &pid);
    if (!watching)
        return 0;
    
    struct write_event_t event = {0};
    event.pid = pid;
    
    bpf_probe_read_kernel(&event.fd, sizeof(event.fd), (void *)ctx + 16);
    
    const void *buf_ptr;
    bpf_probe_read_kernel(&buf_ptr, sizeof(buf_ptr), (void *)ctx + 24);
    
    __u64 count;
    bpf_probe_read_kernel(&count, sizeof(count), (void *)ctx + 32);
    
    if (count > sizeof(event.data))
        count = sizeof(event.data);
    
    event.data_len = count;
    
    if (count > 0)
        bpf_probe_read_user(event.data, count, buf_ptr);
    
    bpf_ringbuf_output(&events, &event, sizeof(event), 0);
    
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
