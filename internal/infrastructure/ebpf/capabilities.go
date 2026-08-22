package ebpf

// HostCapabilities is the result of a per-host eBPF portability probe. It deliberately contains no
// kernel-version field: enterprise distributions backport eBPF and BTF support, so capabilities are
// tested directly rather than inferred from uname.
type HostCapabilities struct {
	Architecture          string
	ObjectArchitecture    string
	ArchitectureSupported bool
	KernelBTF             bool
	CORE                  bool
	Reason                string
}
