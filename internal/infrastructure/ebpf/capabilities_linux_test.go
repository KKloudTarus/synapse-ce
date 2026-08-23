//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
)

func TestProbeHostCapabilities(t *testing.T) {
	allTypes := func() (kernelTypeLookup, error) {
		return func(name string) (btf.Type, error) {
			return &btf.Int{Name: name, Size: 4}, nil
		}, nil
	}

	tests := []struct {
		name       string
		goarch     string
		objectArch string
		load       kernelTypeLoader
		wantArch   bool
		wantBTF    bool
		wantCORE   bool
		wantReason string
	}{
		{
			name: "amd64 ready", goarch: "amd64", objectArch: "amd64", load: allTypes,
			wantArch: true, wantBTF: true, wantCORE: true,
		},
		{
			name: "arm64 ready", goarch: "arm64", objectArch: "arm64", load: allTypes,
			wantArch: true, wantBTF: true, wantCORE: true,
		},
		{
			name: "unsupported architecture", goarch: "riscv64", objectArch: "",
			load: func() (kernelTypeLookup, error) {
				t.Fatal("BTF must not be loaded without an architecture-matched object")
				return nil, nil
			},
			wantReason: "no architecture-matched",
		},
		{
			name: "wrong embedded architecture", goarch: "arm64", objectArch: "amd64", load: allTypes,
			wantReason: "no architecture-matched",
		},
		{
			name: "kernel BTF unavailable", goarch: "amd64", objectArch: "amd64",
			load:     func() (kernelTypeLookup, error) { return nil, errors.New("not supported") },
			wantArch: true, wantReason: "kernel BTF unavailable",
		},
		{
			name: "required type missing", goarch: "arm64", objectArch: "arm64",
			load: func() (kernelTypeLookup, error) {
				return func(name string) (btf.Type, error) {
					if name == "msghdr" {
						return nil, fmt.Errorf("type %s: %w", name, btf.ErrNotFound)
					}
					return &btf.Int{Name: name, Size: 4}, nil
				}, nil
			},
			wantArch: true, wantBTF: true, wantReason: "msghdr",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := probeHostCapabilities(tt.goarch, tt.objectArch, tt.load)
			if got.ArchitectureSupported != tt.wantArch || got.KernelBTF != tt.wantBTF || got.CORE != tt.wantCORE {
				t.Fatalf("capabilities = %+v", got)
			}
			if tt.wantReason != "" && !strings.Contains(got.Reason, tt.wantReason) {
				t.Fatalf("reason %q does not contain %q", got.Reason, tt.wantReason)
			}
			if tt.wantReason == "" && got.Reason != "" {
				t.Fatalf("unexpected reason %q", got.Reason)
			}
		})
	}
}

func TestProbeCurrentHostDoesNotUseKernelVersionGating(t *testing.T) {
	got := ProbeHostCapabilities()
	if got.Architecture != embeddedObjectArch {
		t.Fatalf("running architecture %q does not match embedded object %q", got.Architecture, embeddedObjectArch)
	}
	if got.ArchitectureSupported && !got.KernelBTF && !strings.Contains(got.Reason, "BTF") {
		t.Fatalf("missing BTF must have an actionable reason, got %+v", got)
	}
	t.Logf("host capability probe: %+v", got)
}
