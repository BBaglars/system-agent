//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb Sensor ./ebpf/sensor.c -- -I.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#define __TARGET_ARCH_x86
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct tcp_event_t {
    __u32 pid;
    char comm[16];
    __u32 daddr;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} tcp_events SEC(".maps");

SEC("kprobe/tcp_connect")
int kprobe_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct tcp_event_t *event;
    __u64 pid_tgid;

    bpf_printk("TCP connect triggered by PID %d", bpf_get_current_pid_tgid() >> 32);

    event = bpf_ringbuf_reserve(&tcp_events, sizeof(*event), 0);
    if (!event) {
        bpf_printk("ringbuf reserve failed in tcp_connect");
        return 0;
    }

    /* Read process metadata from current task context. */
    pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    /* Read destination IPv4 address and port from kernel sock fields. */
    event->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    event->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    /* Submit event to ring buffer for efficient user-space consumption. */
    bpf_ringbuf_submit(event, 0);
    return 0;
}
