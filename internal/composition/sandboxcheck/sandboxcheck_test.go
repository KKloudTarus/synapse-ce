package sandboxcheck

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestBaseSpecRequestsConstrainedPosture(t *testing.T) {
	spec := BaseSpec("probe")
	if spec.CapAdd != nil || spec.EgressPolicy != nil || spec.HostNetwork {
		t.Fatalf("default probe must request no capabilities, no egress policy, and no host network: %#v", spec)
	}
	if spec.Workdir != "" || len(spec.ReadOnlyPaths) != 0 {
		t.Fatalf("default probe must not request a host bind: %#v", spec)
	}
	if spec.Name != "probe" {
		t.Fatalf("Name = %q, want probe", spec.Name)
	}
}

func TestFilesystemSpecOnlyBindsDeclaredWorkdir(t *testing.T) {
	spec := BaseSpec("probe")
	spec.Workdir = "/scoped/workdir"
	if spec.Workdir != "/scoped/workdir" || len(spec.ReadOnlyPaths) != 0 {
		t.Fatalf("filesystem probe spec must have only its declared writable workdir: %#v", spec)
	}
	if contains(spec.CapAdd, "CAP_SYS_ADMIN") || contains(spec.CapAdd, "CAP_NET_RAW") {
		t.Fatalf("conformance filesystem probe must add no capabilities: %#v", spec.CapAdd)
	}
}

func TestFailedHonorsStrictMode(t *testing.T) {
	tests := []struct {
		name   string
		report Report
		want   bool
	}{
		{"unenforced non-strict", Report{Strict: false, Checks: []CheckResult{UnenforcedResult("memory-limit", "resource", "unavailable")}}, false},
		{"unenforced strict", Report{Strict: true, Checks: []CheckResult{UnenforcedResult("memory-limit", "resource", "unavailable")}}, true},
		{"hard failure", Report{Checks: []CheckResult{FailResult("network", "network", "reachable")}}, true},
		{"passing", Report{Strict: true, Checks: []CheckResult{PassResult("network", "network", "blocked")}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Failed(tt.report); got != tt.want {
				t.Fatalf("Failed() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestJSONReportIsDeterministic(t *testing.T) {
	r := Report{
		Mode: "full", Strict: true, CgroupLimitsEnforced: true,
		Checks: []CheckResult{
			PassResult("filesystem", "filesystem", "ok"),
			UnenforcedResult("memory-limit", "resource", "unavailable"),
		},
	}
	var first, second bytes.Buffer
	if err := WriteReport("-", r, &first, io.Discard); err != nil {
		t.Fatalf("first WriteReport: %v", err)
	}
	if err := WriteReport("-", r, &second, io.Discard); err != nil {
		t.Fatalf("second WriteReport: %v", err)
	}
	if first.String() != second.String() {
		t.Fatalf("JSON reports differ:\n%s\n%s", first.String(), second.String())
	}
	var got Report
	if err := json.Unmarshal(first.Bytes(), &got); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if strings.Join([]string{got.Checks[0].Name, got.Checks[1].Name}, ",") != "filesystem,memory-limit" {
		t.Fatalf("check order changed: %#v", got.Checks)
	}
}

func TestProbeSpecHasNoBroadCapabilities(t *testing.T) {
	spec := ProbeSpec("probe", "network")
	if contains(spec.CapAdd, "CAP_SYS_ADMIN") || contains(spec.CapAdd, "CAP_NET_RAW") {
		t.Fatalf("probe capabilities = %#v, want none", spec.CapAdd)
	}
	if spec.EgressPolicy != nil || spec.HostNetwork {
		t.Fatalf("network denial probe must use the isolated default: %#v", spec)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
