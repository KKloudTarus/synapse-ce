// netconn.bpf.c — network-connect observer (detection class "network").
//
// Unlike the other three sensors, this one needs the socket to know the protocol: the connect/sendto
// syscalls do not reveal tcp-vs-udp, but the network detection rule (a DNS beacon) is specifically
// udp:53. So this program hooks the kernel functions where the protocol is implicit in the hook itself —
// udp_sendmsg (udp) and tcp_connect (tcp) — and reads the destination from struct sock via CO-RE.
//
// CO-RE is used HERE ONLY; the other sensors stay CO-RE-free. The repository-owned minimal type
// header makes both architecture artifacts reproducible without a host-generated vmlinux.h.
// Observe-only: a kprobe cannot change the syscall's outcome, it only records.
#include "core_types.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define COMM_LEN 16
#define PROTO_TCP 6
#define PROTO_UDP 17
#define RINGBUF_BYTES (256 * 1024)

struct net_event {
	__u32 pid;
	__u32 daddr; // IPv4 destination, network byte order
	__u16 dport; // destination port, host byte order
	__u8 proto;  // 6 = tcp, 17 = udp
	__u8 pad;
	char comm[COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_BYTES);
} net_events SEC(".maps");

static __always_inline void emit(__u8 proto, __u32 daddr, __u16 dport)
{
	if (dport == 0)
		return; // no destination resolved — nothing useful to record
	struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
	if (!e)
		return;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->proto = proto;
	e->pad = 0;
	e->daddr = daddr;
	e->dport = dport;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
}

// int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(detect_udp_sendmsg, struct sock___synapse *sk, struct msghdr___synapse *msg)
{
	// Connected UDP: the destination is on the socket.
	__u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	__u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	if (dport == 0) {
		// Unconnected UDP (the common DNS case): the destination is in msg->msg_name, which the syscall
		// layer has already copied into kernel memory as a sockaddr_in.
		struct sockaddr_in___synapse *sin =
			(struct sockaddr_in___synapse *)BPF_CORE_READ(msg, msg_name);
		if (sin) {
			dport = bpf_ntohs(BPF_CORE_READ(sin, sin_port));
			daddr = BPF_CORE_READ(sin, sin_addr.s_addr);
		}
	}
	emit(PROTO_UDP, daddr, dport);
	return 0;
}

// void tcp_connect(struct sock *sk) — the destination is set on the socket by this point.
SEC("kprobe/tcp_connect")
int BPF_KPROBE(detect_tcp_connect, struct sock___synapse *sk)
{
	__u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	__u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	emit(PROTO_TCP, daddr, dport);
	return 0;
}

char _license[] SEC("license") = "GPL";
