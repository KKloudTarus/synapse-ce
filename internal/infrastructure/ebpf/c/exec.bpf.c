// exec.bpf.c — process-execution observer (detection class "process").
//
// Hooks the execve syscall entry and emits one event per exec with the command, resolved filename, and
// the first two arguments — enough for the process-class rules (process enumeration, network-config
// discovery, service restart) to match in userspace. Observe-only; always allows the exec.
#include "detect.bpf.h"

struct exec_event {
	__u64 ktime_ns; // kernel-monotonic occurred-at (bpf_ktime_get_ns); userspace maps it to wall-clock
	__u32 pid;
	__u32 uid;
	char comm[COMM_LEN];
	char filename[PATH_LEN];
	char arg1[ARG_LEN];
	char arg2[ARG_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_BYTES);
} exec_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int detect_execve(struct sys_enter_ctx *ctx)
{
	struct exec_event *e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
	if (!e)
		return 0; // ring full — drop the record, never block the exec

	e->ktime_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid() & 0xffffffff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	const char *filename = (const char *)ctx->args[0];
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

	// argv is a user array of char*; read argv[1] and argv[2] (the first real arguments). argv[0] is the
	// program name, which is already covered by comm/filename.
	e->arg1[0] = 0;
	e->arg2[0] = 0;
	const char *const *argv = (const char *const *)ctx->args[1];
	if (argv) {
		const char *p1 = 0, *p2 = 0;
		bpf_probe_read_user(&p1, sizeof(p1), &argv[1]);
		if (p1)
			bpf_probe_read_user_str(&e->arg1, sizeof(e->arg1), p1);
		bpf_probe_read_user(&p2, sizeof(p2), &argv[2]);
		if (p2)
			bpf_probe_read_user_str(&e->arg2, sizeof(e->arg2), p2);
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
