//go:build !linux

package ebpf

import (
	"strings"
	"testing"
)

func TestProbeHostCapabilitiesFailsClosedOffLinux(t *testing.T) {
	got := ProbeHostCapabilities()
	if got.ArchitectureSupported || got.KernelBTF || got.CORE {
		t.Fatalf("off-Linux host must not report eBPF capability: %+v", got)
	}
	if !strings.Contains(got.Reason, "Linux only") {
		t.Fatalf("off-Linux capability reason is not actionable: %+v", got)
	}
}
