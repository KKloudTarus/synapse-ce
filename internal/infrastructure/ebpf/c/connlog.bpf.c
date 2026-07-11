// connlog.bpf.c – egress connection observability.
//
// Two cgroup hooks (connect4/connect6) fire on every outbound connect() a process in the
// attached cgroup makes – BEFORE the netns iptables filter runs – so even an *attempted*
// out-of-scope connection is captured, not just silently dropped. This program only
// OBSERVES (always returns 1 = allow); enforcement stays with the kernel egress filter
// Each attempt is pushed to a ring buffer the Go side drains + seals as
// evidence, labelling the verdict against the run's scope policy in userspace.
//
// Compiled to BPF bytecode by clang (`-target bpf`) and embedded via go:embed – no clang
// or libbpf at runtime; cilium/ebpf loads the object. UAPI-stable fields only (no CO-RE).
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define AF_INET6 10

// conn_event mirrors connlogEvent in monitor_linux.go (fixed layout, little-endian host).
struct conn_event {
	__u32 pid;
	__u32 ip4;      // IPv4 dst, network byte order
	__u8 ip6[16];   // IPv6 dst
	__u16 port;     // dst port, host byte order
	__u16 family;   // AF_INET (2) | AF_INET6 (10)
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} conn_events SEC(".maps");

static __always_inline void emit(struct bpf_sock_addr *ctx, __u16 family)
{
	struct conn_event *e = bpf_ringbuf_reserve(&conn_events, sizeof(*e), 0);
	if (!e)
		return; // ring full – drop the record, never block the connect
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->family = family;
	e->port = bpf_ntohs(ctx->user_port);
	if (family == AF_INET) {
		e->ip4 = ctx->user_ip4;
	} else {
		__builtin_memcpy(e->ip6, &ctx->user_ip6, sizeof(e->ip6));
	}
	bpf_ringbuf_submit(e, 0);
}

SEC("cgroup/connect4")
int connlog_connect4(struct bpf_sock_addr *ctx)
{
	emit(ctx, AF_INET);
	return 1; // 1 = allow: observe only, the iptables egress filter enforces
}

SEC("cgroup/connect6")
int connlog_connect6(struct bpf_sock_addr *ctx)
{
	emit(ctx, AF_INET6);
	return 1;
}

char _license[] SEC("license") = "GPL";
