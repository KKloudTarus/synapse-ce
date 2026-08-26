// priv.bpf.c — privilege-change observer (detection class "privilege").
//
// Hooks the setuid and setresuid syscall entries and emits the target uid, so the privilege-class rule
// (a change whose effective target is uid 0) can match in userspace. Observe-only. A real capset hook
// would need CO-RE to read the cap sets; that is deliberately left to a later refinement, and the domain
// rule already tolerates it (the "capset" kind simply never fires from this program yet).
#include "detect.bpf.h"

struct priv_event {
	__u64 ktime_ns; // kernel-monotonic occurred-at (bpf_ktime_get_ns); userspace maps it to wall-clock
	__u32 pid;
	__u32 uid;
	__u32 to_uid;
	char comm[COMM_LEN];
	char kind[KIND_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_BYTES);
} priv_events SEC(".maps");

static __always_inline void emit(__u32 to_uid, const char *kind)
{
	struct priv_event *e = bpf_ringbuf_reserve(&priv_events, sizeof(*e), 0);
	if (!e)
		return;
	e->ktime_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid() & 0xffffffff;
	e->to_uid = to_uid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memset(&e->kind, 0, sizeof(e->kind));
	// kind is a short constant; copy up to KIND_LEN-1 bytes.
#pragma unroll
	for (int i = 0; i < KIND_LEN - 1; i++) {
		char c = kind[i];
		e->kind[i] = c;
		if (c == 0)
			break;
	}
	bpf_ringbuf_submit(e, 0);
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int detect_setuid(struct sys_enter_ctx *ctx)
{
	// setuid(uid): args[0] is the target uid.
	emit((__u32)ctx->args[0], "setuid");
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int detect_setresuid(struct sys_enter_ctx *ctx)
{
	// setresuid(ruid, euid, suid): the effective uid (args[1]) is the escalation target.
	emit((__u32)ctx->args[1], "setuid");
	return 0;
}

char _license[] SEC("license") = "GPL";
