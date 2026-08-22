//go:build !linux

package ebpf

import "runtime"

// ProbeHostCapabilities reports the Linux-only sensor boundary on other operating systems.
func ProbeHostCapabilities() HostCapabilities {
	return HostCapabilities{
		Architecture: runtime.GOARCH,
		Reason:       "eBPF sensor unavailable: Linux only",
	}
}
