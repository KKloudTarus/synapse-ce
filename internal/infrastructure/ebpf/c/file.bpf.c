// file.bpf.c — sensitive-file-access observer (detection class "file").
//
// Hooks the openat syscall entry. openat is extremely high volume, so this program applies a cheap
// in-kernel prefix gate — it only emits events for paths under /etc/ or /root/ — to keep overhead
// tractable. This gate is an OVERHEAD guard, not the detection rule: the authoritative match (exact
// sensitive paths + op) still runs in userspace against the domain catalogue. Observe-only.
#include "detect.bpf.h"

struct file_event {
	__u64 ktime_ns; // kernel-monotonic occurred-at (bpf_ktime_get_ns); userspace maps it to wall-clock
	__u32 pid;
	__u32 uid;
	char comm[COMM_LEN];
	char filename[PATH_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_BYTES);
} file_events SEC(".maps");

// under_watched_prefix returns 1 if the path begins with /etc/ or /root/. A coarse gate on the first
// bytes only — deliberately cheap, deliberately over-approximate (userspace narrows it exactly).
static __always_inline int under_watched_prefix(const char *p)
{
	// "/etc/" and "/root/" both start with '/'; branch on the second and third bytes.
	if (p[0] != '/')
		return 0;
	if (p[1] == 'e' && p[2] == 't' && p[3] == 'c' && p[4] == '/')
		return 1;
	if (p[1] == 'r' && p[2] == 'o' && p[3] == 'o' && p[4] == 't' && p[5] == '/')
		return 1;
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int detect_openat(struct sys_enter_ctx *ctx)
{
	// openat(dfd, filename, flags, mode): filename is args[1].
	const char *filename = (const char *)ctx->args[1];

	// Overhead gate FIRST, on a cheap 8-byte read: the overwhelming majority of opens are not under a
	// watched prefix, and paying a full path read for each would dominate the per-syscall cost. Only the
	// few opens that clear the gate pay for the full path read below.
	char pfx[8] = {};
	if (bpf_probe_read_user(&pfx, sizeof(pfx), filename) != 0)
		return 0;
	if (!under_watched_prefix(pfx))
		return 0;

	struct file_event *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->ktime_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid() & 0xffffffff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
