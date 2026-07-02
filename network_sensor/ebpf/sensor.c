//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb Sensor ./ebpf/sensor.c -- -I.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#define __TARGET_ARCH_x86
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* Guard against vmlinux.h not exposing these constants explicitly. */
#ifndef TCP_ESTABLISHED
#define TCP_ESTABLISHED  1
#define TCP_SYN_SENT     2
#define TCP_CLOSE        7
#endif

/* tcp_event_t binary layout (28 bytes, matches Go tcpEventBinarySize):
 *   [0:4]   pid        __u32
 *   [4:20]  comm       char[16]
 *   [20:24] daddr      __u32
 *   [24:26] dport      __u16
 *   [26:27] tcp_state  __u8   (1=ESTABLISHED, 7=CLOSE/REFUSED)
 *   [27:28] _pad       __u8   (explicit alignment padding)
 */
struct tcp_event_t {
    __u32 pid;
    char  comm[16];
    __u32 daddr;
    __u16 dport;
    __u8  tcp_state;
    __u8  _pad;
};

/* Ring buffer shared with Go user-space consumer. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} tcp_events SEC(".maps");

/* Intermediate storage for connections initiated but not yet resolved.
 * Key:   sock pointer cast to u64 (unique per socket in the kernel).
 * Value: connection metadata captured at tcp_connect time.
 * Entries are removed once the outcome (ESTABLISHED or CLOSE) is known. */
struct pending_connect_t {
    __u32 pid;
    char  comm[16];
    __u32 daddr;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u64);
    __type(value, struct pending_connect_t);
} pending_connects SEC(".maps");

/* Capture outbound TCP connection attempts and store them in pending_connects.
 * We do not emit to the ring buffer here because the outcome is not yet known. */
SEC("kprobe/tcp_connect")
int kprobe_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    __u64 pid_tgid  = bpf_get_current_pid_tgid();
    __u64 sock_key  = (__u64)(uintptr_t)sk;

    struct pending_connect_t pending = {};
    pending.pid   = pid_tgid >> 32;
    bpf_get_current_comm(&pending.comm, sizeof(pending.comm));
    pending.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    pending.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_printk("TCP connect stored PID %d dport %d", pending.pid, pending.dport);

    /* Store under sock pointer so tcp_set_state can correlate later. */
    bpf_map_update_elem(&pending_connects, &sock_key, &pending, BPF_ANY);
    return 0;
}

/* Intercept TCP state transitions to emit enriched events with the connection outcome.
 * Only ESTABLISHED (success) and CLOSE (refused / reset / timed-out) are forwarded. */
SEC("kprobe/tcp_set_state")
int kprobe_tcp_set_state(struct pt_regs *ctx)
{
    struct sock *sk    = (struct sock *)PT_REGS_PARM1(ctx);
    int new_state      = (int)PT_REGS_PARM2(ctx);

    if (new_state != TCP_ESTABLISHED && new_state != TCP_CLOSE) {
        return 0;
    }

    __u64 sock_key = (__u64)(uintptr_t)sk;

    struct pending_connect_t *pending =
        bpf_map_lookup_elem(&pending_connects, &sock_key);
    if (!pending) {
        /* Socket not tracked by us — could be a listen/accept path. */
        return 0;
    }

    struct tcp_event_t *event =
        bpf_ringbuf_reserve(&tcp_events, sizeof(*event), 0);
    if (!event) {
        bpf_printk("ringbuf reserve failed in tcp_set_state");
        return 0;
    }

    event->pid       = pending->pid;
    event->daddr     = pending->daddr;
    event->dport     = pending->dport;
    event->tcp_state = (__u8)new_state;
    event->_pad      = 0;
    __builtin_memcpy(event->comm, pending->comm, sizeof(event->comm));

    bpf_printk("TCP state change PID %d dport %d -> state %d",
               event->pid, event->dport, new_state);

    /* Submit enriched event to user-space ring buffer consumer. */
    bpf_ringbuf_submit(event, 0);

    /* Outcome known — release the pending slot to avoid map exhaustion. */
    bpf_map_delete_elem(&pending_connects, &sock_key);
    return 0;
}
