// Process lifecycle observer. Syscall entry only captures bounded arguments; successful exec and
// final thread-group exit are emitted from scheduler tracepoints with the group leader's start cookie.
#include "detect.bpf.h"
#include "core_types.bpf.h"
#include <bpf/bpf_core_read.h>

#define PROCESS_EXEC 1
#define PROCESS_EXIT 2

struct exec_args {
	char filename[PATH_LEN];
	char arg1[ARG_LEN];
	char arg2[ARG_LEN];
};
struct process_key {
	__u64 start;
	__u32 pid;
	__u32 pad;
};
struct exec_event {
	__u64 ktime_ns;
	__u64 start_ns;
	__u32 pid;
	__u32 uid;
	__u32 kind;
	char comm[COMM_LEN];
	char filename[PATH_LEN];
	char arg1[ARG_LEN];
	char arg2[ARG_LEN];
};
struct sched_exec_ctx {
	__u64 common;
	__u32 filename;
	__u32 pid;
	__u32 old_pid;
};
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_BYTES);
} exec_events SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct exec_args);
} exec_scratch SEC(".maps");
// A successful exec inserts an identity; only one racing final thread exit can remove it.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct process_key);
	__type(value, __u8);
} process_live SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} process_dropped SEC(".maps");

static __always_inline void count_drop(void)
{
	__u32 key = 0;
	__u64 *count = bpf_map_lookup_elem(&process_dropped, &key);
	if (count) __sync_fetch_and_add(count, 1);
}

static __always_inline int capture_exec(const char *filename, const char *const *argv)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct exec_args a = {};
	bpf_probe_read_user_str(a.filename, sizeof(a.filename), filename);
	if (argv) {
		const char *p = 0;
		bpf_probe_read_user(&p, sizeof(p), &argv[1]);
		if (p) bpf_probe_read_user_str(a.arg1, sizeof(a.arg1), p);
		p = 0;
		bpf_probe_read_user(&p, sizeof(p), &argv[2]);
		if (p) bpf_probe_read_user_str(a.arg2, sizeof(a.arg2), p);
	}
	bpf_map_update_elem(&exec_scratch, &tid, &a, BPF_ANY);
	return 0;
}
SEC("tracepoint/syscalls/sys_enter_execve")
int enter_execve(struct sys_enter_ctx *ctx) { return capture_exec((const char *)ctx->args[0], (const char *const *)ctx->args[1]); }
SEC("tracepoint/syscalls/sys_enter_execveat")
int enter_execveat(struct sys_enter_ctx *ctx) { return capture_exec((const char *)ctx->args[1], (const char *const *)ctx->args[2]); }
SEC("tracepoint/syscalls/sys_exit_execve")
int exit_execve(void *ctx) { __u32 tid = (__u32)bpf_get_current_pid_tgid(); bpf_map_delete_elem(&exec_scratch, &tid); return 0; }
SEC("tracepoint/syscalls/sys_exit_execveat")
int exit_execveat(void *ctx) { __u32 tid = (__u32)bpf_get_current_pid_tgid(); bpf_map_delete_elem(&exec_scratch, &tid); return 0; }

static __always_inline __u64 group_start(void)
{
	struct task_struct___synapse *task = (void *)bpf_get_current_task();
	struct task_struct___synapse *leader = BPF_CORE_READ(task, group_leader);
	return leader ? BPF_CORE_READ(leader, start_boottime) : 0;
}
SEC("tracepoint/sched/sched_process_exec")
int process_exec(struct sched_exec_ctx *ctx)
{
	__u32 old_tid = ctx->old_pid;
	struct exec_args *args = bpf_map_lookup_elem(&exec_scratch, &old_tid);
	struct process_key key = {.start = group_start(), .pid = bpf_get_current_pid_tgid() >> 32};
	if (!key.start || !key.pid) { count_drop(); goto cleanup; }
	struct exec_event *e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
	if (!e) { count_drop(); goto cleanup; }
	__builtin_memset(e, 0, sizeof(*e));
	e->ktime_ns = bpf_ktime_get_ns(); e->start_ns = key.start; e->pid = key.pid;
	e->uid = (__u32)bpf_get_current_uid_gid(); e->kind = PROCESS_EXEC;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	if (args) {
		__builtin_memcpy(e->filename, args->filename, sizeof(e->filename));
		__builtin_memcpy(e->arg1, args->arg1, sizeof(e->arg1));
		__builtin_memcpy(e->arg2, args->arg2, sizeof(e->arg2));
	}
	__u8 marker = 1;
	if (bpf_map_update_elem(&process_live, &key, &marker, BPF_ANY)) count_drop();
	bpf_ringbuf_submit(e, 0);
cleanup:
	bpf_map_delete_elem(&exec_scratch, &old_tid);
	return 0;
}
SEC("tracepoint/sched/sched_process_exit")
int process_exit(void *ctx)
{
	struct task_struct___synapse *task = (void *)bpf_get_current_task();
	struct signal_struct___synapse *signal = BPF_CORE_READ(task, signal);
	if (!signal || BPF_CORE_READ(signal, live.counter) != 0) return 0;
	struct process_key key = {.start = group_start(), .pid = bpf_get_current_pid_tgid() >> 32};
	if (!key.start || bpf_map_delete_elem(&process_live, &key)) return 0;
	struct exec_event *e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
	if (!e) { count_drop(); return 0; }
	__builtin_memset(e, 0, sizeof(*e));
	e->ktime_ns = bpf_ktime_get_ns(); e->start_ns = key.start; e->pid = key.pid;
	e->uid = (__u32)bpf_get_current_uid_gid(); e->kind = PROCESS_EXIT;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}
char _license[] SEC("license") = "GPL";
