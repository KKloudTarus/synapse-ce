//go:build linux

package ebpf

import (
	"bytes"
	"embed"
	"fmt"
	"testing"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// Include both architecture sets in the test binary so an amd64 maintainer can validate the arm64
// artifacts structurally without executing an arm64 program on the wrong kernel ABI.
//
//go:embed c/*.bpf.o
var committedObjects embed.FS

type artifactExpectation struct {
	base     string
	programs []string
	maps     []string
}

var artifactExpectations = []artifactExpectation{
	{base: "connlog", programs: []string{"connlog_connect4", "connlog_connect6"}, maps: []string{"conn_events"}},
	{base: "exec", programs: []string{"detect_execve"}, maps: []string{"exec_events"}},
	{base: "file", programs: []string{"detect_openat"}, maps: []string{"file_events"}},
	{base: "priv", programs: []string{"detect_setuid", "detect_setresuid"}, maps: []string{"priv_events"}},
	{base: "netconn", programs: []string{"detect_udp_sendmsg", "detect_tcp_connect"}, maps: []string{"net_events"}},
}

func artifactPath(base, arch string) string {
	if arch == "amd64" {
		return "c/" + base + ".bpf.o"
	}
	return fmt.Sprintf("c/%s.%s.bpf.o", base, arch)
}

func loadCommittedSpec(t *testing.T, base, arch string) (*cebpf.CollectionSpec, []byte) {
	t.Helper()
	path := artifactPath(base, arch)
	data, err := committedObjects.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(data) == 0 {
		t.Fatalf("%s is empty", path)
	}
	spec, err := cebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return spec, data
}

func TestCommittedObjectsCoverAMD64AndARM64(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		for _, want := range artifactExpectations {
			t.Run(arch+"/"+want.base, func(t *testing.T) {
				spec, _ := loadCommittedSpec(t, want.base, arch)
				for _, name := range want.programs {
					if spec.Programs[name] == nil {
						t.Errorf("program %q missing", name)
					}
				}
				for _, name := range want.maps {
					if spec.Maps[name] == nil {
						t.Errorf("map %q missing", name)
					}
				}
				if spec.Types == nil {
					t.Error("BTF metadata missing from reproducible artifact")
				}
			})
		}
	}
}

func TestNetworkObjectsUseTargetCallingConvention(t *testing.T) {
	tests := []struct {
		arch        string
		wantOffsets []int16
	}{
		{arch: "amd64", wantOffsets: []int16{112, 104}},
		{arch: "arm64", wantOffsets: []int16{0, 8}},
	}
	for _, tt := range tests {
		t.Run(tt.arch, func(t *testing.T) {
			spec, _ := loadCommittedSpec(t, "netconn", tt.arch)
			prog := spec.Programs["detect_udp_sendmsg"]
			if prog == nil {
				t.Fatal("detect_udp_sendmsg missing")
			}
			seen := make(map[int16]bool)
			for i, ins := range prog.Instructions {
				if i >= 8 {
					break
				}
				if ins.OpCode.Class() == asm.LdXClass && ins.Src == asm.R1 {
					seen[ins.Offset] = true
				}
			}
			for _, offset := range tt.wantOffsets {
				if !seen[offset] {
					t.Fatalf("target argument offset %d missing; saw %v", offset, seen)
				}
			}
		})
	}
}

func TestNativeBuildEmbedsOnlyMatchingObjects(t *testing.T) {
	if embeddedObjectArch == "" {
		t.Fatal("amd64/arm64 test build must select an object architecture")
	}
	wants := map[string][]byte{
		"connlog": connlogObj,
		"exec":    execObj,
		"file":    fileObj,
		"priv":    privObj,
		"netconn": netObj,
	}
	for base, embedded := range wants {
		_, committed := loadCommittedSpec(t, base, embeddedObjectArch)
		if !bytes.Equal(embedded, committed) {
			t.Errorf("%s embedded bytes do not match committed %s object", base, embeddedObjectArch)
		}
	}
}
