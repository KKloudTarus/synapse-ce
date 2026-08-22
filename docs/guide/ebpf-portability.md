# eBPF portability

Synapse ships the host detection sensor as precompiled eBPF objects. Production hosts do not need
Clang, kernel headers, or a C toolchain. The agent selects an object compiled for its own architecture
and tests the host's capabilities before loading it.

## Supported architectures

| Agent platform | Embedded object | Status |
| --- | --- | --- |
| Linux amd64 | *.bpf.o | Supported and loaded in the native compatibility job |
| Linux arm64 | *.arm64.bpf.o | Supported and loaded in the native compatibility job |
| Other Linux architectures | None | Fails closed with an explicit observation gap |
| Non-Linux | None | Existing Linux-only sensor fallback; every requested class is a gap |

The network object is architecture-specific because kprobes receive arguments through **pt_regs**.
The first two amd64 arguments are in **rdi** and **rsi**; arm64 uses **regs[0]** and **regs[1]**.
Embedding a single object for both architectures can load successfully while reading the wrong
registers, so the agent never falls back to an object built for another architecture.

The process, file, and privilege observers use stable syscall tracepoint contexts. Separate objects
are still built for both supported architectures so the release artifact set is explicit and can be
validated uniformly.

## Capability probing

Portability is capability-based, not kernel-version-based. This matters for distributions such as
RHEL, which backport eBPF features to kernels whose release number predates the upstream feature.

At startup the detection sensor:

1. Confirms that the binary contains an object matching GOARCH.
2. Removes the memlock limit needed by the eBPF loader.
3. If the network class is enabled, reads the actual kernel BTF through ebpf-go.
4. Confirms that the BTF exposes the sock, msghdr, and sockaddr_in types used by CO-RE.
5. Loads and attaches each requested class independently.

Loading remains the final compatibility test. The preflight does not claim that BTF alone guarantees
attach support; it gives a stable and actionable reason when CO-RE relocation cannot begin.

If BTF is absent or incomplete, the network class becomes a degraded coverage record. The other
classes still load because they do not require CO-RE. If no requested class can load, Start returns
ErrSensorUnavailable as well as retaining the per-class gap reasons. Missing capability is never
reported as a clean observation window.

ProbeHostCapabilities exposes the same preflight result for diagnostics:

    caps := ebpf.ProbeHostCapabilities()
    fmt.Printf("arch=%s btf=%t core=%t reason=%s\n",
        caps.Architecture, caps.KernelBTF, caps.CORE, caps.Reason)

No kernel release string participates in this decision.

## Rebuilding the objects

Use a Linux build host with Clang, LLVM strip, and libbpf headers:

    sudo apt-get install clang llvm libbpf-dev
    make ebpf-generate
    go test ./internal/infrastructure/ebpf

scripts/ebpf/build.sh compiles every source twice:

- **-target bpfel -D__TARGET_ARCH_x86** for amd64;
- **-target bpfel -D__TARGET_ARCH_arm64** for arm64.

The script applies a debug-prefix map so BTF line information contains repository-relative paths
rather than a contributor's absolute workspace path. It preserves .BTF and .BTF.ext, which are
required for CO-RE relocation, while stripping ordinary DWARF debug sections.

The network observer uses the repository-owned core_types.bpf.h. It declares only the kernel fields
the program reads and marks them for preserve-access-index relocation. Do not replace it with a
vmlinux.h generated on a workstation: doing so makes cross-architecture generation depend on the
build host's pt_regs and prevents a clean checkout from reproducing both artifacts.

After rebuilding, commit all ten object files with their C/header changes. Go binaries embed only the
five files for their target architecture.

## Verification

The package tests enforce four separate properties:

- every committed amd64 and arm64 ELF parses and contains its expected programs, maps, and BTF;
- network objects encode the correct target calling-convention offsets;
- the native Go build embeds only its matching object set;
- missing BTF, missing required types, and unsupported architectures produce explicit failures.

The **eBPF Compatibility** workflow runs these checks on native ubuntu-24.04 amd64 and
ubuntu-24.04-arm runners. It then runs the privileged load/attach test on each native kernel. A
cross-compile is not accepted as proof that an arm64 sensor attaches.

For a manual native check:

    sudo --preserve-env=PATH \
      go test ./internal/infrastructure/ebpf \
      -run '^TestSensorLoadsAndDisablesEachClassIndependently$' -v

The test loads process, network, file, and privilege objects one at a time and verifies that the
requested class is active while disabled classes remain explicit coverage gaps. The native workflow
also sends a local UDP fixture and requires the network sensor to decode udp/53, proving the selected
object reads the native kprobe argument registers rather than merely passing the verifier.
