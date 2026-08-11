// detect.bpf.h — shared definitions for the agent-side detection sensors (issue #422).
//
// Following the connlog seed's philosophy: UAPI-stable fields only, NO CO-RE, so the compiled objects
// load on any kernel with the syscall tracepoints without a per-host vmlinux.h. Each event class is a
// SEPARATE program with its OWN ring buffer map, so a class can be loaded, attached and disabled
// independently (issue #422 requirement 1). Every program only OBSERVES and emits to its ring buffer; no
// program writes state, spawns anything, or blocks a syscall (requirement 8).
#ifndef SYNAPSE_DETECT_BPF_H
#define SYNAPSE_DETECT_BPF_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define COMM_LEN 16
#define PATH_LEN 256
#define ARG_LEN 48
#define KIND_LEN 12

// sys_enter_ctx is the stable layout of a syscall-entry tracepoint context: a common preamble followed
// by the six syscall arguments. This is the documented format for tracepoint/syscalls/sys_enter_* and is
// what lets these programs avoid CO-RE entirely.
struct sys_enter_ctx {
	unsigned long long unused;
	long syscall_nr;
	unsigned long args[6];
};

// Each ring buffer is sized independently; the Go loader can tune this per class later, but a fixed cap
// here bounds kernel memory even before userspace applies its own ceiling.
#define RINGBUF_BYTES (256 * 1024)

#endif // SYNAPSE_DETECT_BPF_H
