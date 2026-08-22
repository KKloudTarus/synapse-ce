//go:build linux

package ebpf

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/cilium/ebpf/btf"
)

type kernelTypeLookup func(name string) (btf.Type, error)
type kernelTypeLoader func() (kernelTypeLookup, error)

// ProbeHostCapabilities checks the current host using its actual kernel BTF. Loading a program remains
// the final compatibility test; this preflight provides a deterministic, actionable coverage reason
// when CO-RE cannot possibly relocate the network sensor.
func ProbeHostCapabilities() HostCapabilities {
	cache := btf.NewCache()
	return probeHostCapabilities(runtime.GOARCH, embeddedObjectArch, func() (kernelTypeLookup, error) {
		spec, err := cache.Kernel()
		if err != nil {
			return nil, err
		}
		return spec.AnyTypeByName, nil
	})
}

func probeHostCapabilities(goarch, objectArch string, load kernelTypeLoader) HostCapabilities {
	result := HostCapabilities{Architecture: goarch, ObjectArchitecture: objectArch}
	if objectArch == "" || objectArch != goarch {
		result.Reason = fmt.Sprintf("no architecture-matched eBPF objects for linux/%s", goarch)
		return result
	}
	result.ArchitectureSupported = true

	lookup, err := load()
	if err != nil {
		result.Reason = "kernel BTF unavailable: " + err.Error()
		return result
	}
	result.KernelBTF = true

	var missing []string
	for _, name := range [...]string{"sock", "msghdr", "sockaddr_in"} {
		if _, err := lookup(name); err != nil {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		result.Reason = "kernel BTF lacks CO-RE types: " + strings.Join(missing, ", ")
		return result
	}
	result.CORE = true
	return result
}
