// Minimal kernel type declarations used by netconn.bpf.c for CO-RE relocations.
//
// Keep this header deliberately small. Generating vmlinux.h on a developer workstation makes the
// object depend on that workstation's architecture and prevents a clean checkout from reproducing
// the committed amd64 and arm64 artifacts. These preserve_access_index declarations describe only
// the fields the sensor reads; ebpf-go relocates them against the target host's BTF at load time.
#ifndef SYNAPSE_CORE_TYPES_BPF_H
#define SYNAPSE_CORE_TYPES_BPF_H

#include <linux/bpf.h>

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

struct in_addr___synapse {
	__be32 s_addr;
};

struct sockaddr_in___synapse {
	__u16 sin_family;
	__be16 sin_port;
	struct in_addr___synapse sin_addr;
};

struct sock_common___synapse {
	__be32 skc_daddr;
	__be32 skc_rcv_saddr;
	__be16 skc_dport;
};

struct sock___synapse {
	struct sock_common___synapse __sk_common;
};

struct msghdr___synapse {
	void *msg_name;
};

#pragma clang attribute pop

// Kprobe arguments arrive in an architecture-specific pt_regs context. bpf_tracing.h deliberately
// requires __TARGET_ARCH_* and reads the corresponding ABI register. We define only the stable
// prefix needed to reach argument one. These declarations are not CO-RE kernel structures: their
// layouts are the architecture calling convention and are why separate amd64/arm64 objects exist.
#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
};
#elif defined(__TARGET_ARCH_arm64)
struct pt_regs;
struct user_pt_regs {
	unsigned long regs[31];
	unsigned long sp;
	unsigned long pc;
	unsigned long pstate;
};
#else
#error "Synapse eBPF objects support __TARGET_ARCH_x86 and __TARGET_ARCH_arm64"
#endif

#endif // SYNAPSE_CORE_TYPES_BPF_H
