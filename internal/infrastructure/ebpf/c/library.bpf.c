// library.bpf.c — shared-library load observer (runtime reachability class "library", EPIC #1042 #1060).
//
// Hooks the openat syscall entry, the point at which the dynamic loader (or an explicit dlopen) opens a
// shared object before mapping it. openat is extremely high volume, so a cheap in-kernel PREFIX gate emits
// only paths under a standard OS shared-library directory (/lib*, /usr/lib*, /usr/local/*); userspace then
// confirms the ".so" suffix and resolves the file to its owning OS package (dpkg/rpm/apk) for the raise-only
// runtime-reachability join (#1061). Observe-only, mirroring file.bpf.c: it never blocks or mutates.
#include "detect.bpf.h"

struct library_event {
	__u64 ktime_ns; // kernel-monotonic occurred-at; userspace maps it to wall-clock
	__u32 pid;
	__u32 uid;
	char comm[COMM_LEN];
	char path[PATH_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_BYTES);
} library_events SEC(".maps");

// under_library_prefix returns 1 when the path begins with a standard OS shared-library directory. A coarse
// gate on the first bytes only — deliberately cheap and OVER-APPROXIMATE: it admits any "/lib*" (so also
// /libexec) and any "/usr/l*" (so also /usr/local/bin), and userspace then narrows to actual shared objects
// by the ".so" suffix. Covers /lib, /lib64, /usr/lib, /usr/lib64, /usr/local/lib.
static __always_inline int under_library_prefix(const char *p)
{
	if (p[0] != '/')
		return 0;
	// "/lib" ... (matches /lib/, /lib64/, and the harmless /libexec — userspace narrows by the .so suffix).
	if (p[1] == 'l' && p[2] == 'i' && p[3] == 'b')
		return 1;
	// "/usr/l" ... (matches /usr/lib, /usr/lib64, /usr/local/*; userspace narrows).
	if (p[1] == 'u' && p[2] == 's' && p[3] == 'r' && p[4] == '/' && p[5] == 'l')
		return 1;
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int detect_library(struct sys_enter_ctx *ctx)
{
	// openat(dfd, filename, flags, mode): filename is args[1].
	const char *filename = (const char *)ctx->args[1];

	// Overhead gate FIRST, on a cheap 8-byte read (see file.bpf.c): only opens under a library directory pay
	// for the full path read below.
	char pfx[8] = {};
	if (bpf_probe_read_user(&pfx, sizeof(pfx), filename) != 0)
		return 0;
	if (!under_library_prefix(pfx))
		return 0;

	struct library_event *e = bpf_ringbuf_reserve(&library_events, sizeof(*e), 0);
	if (!e)
		return 0; // ring full — drop, never block the open
	e->ktime_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid() & 0xffffffff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// Read the full path and DISCARD on failure or truncation: a faulted read or a path that fills the
	// buffer (>= PATH_LEN) would carry a wrong or clipped path into the package-ownership join, which is
	// worse than no evidence. A dropped over-long path is a raise-only false negative, never a wrong raise.
	long n = bpf_probe_read_user_str(&e->path, sizeof(e->path), filename);
	if (n <= 0 || n >= (long)sizeof(e->path)) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
