package engagement

import (
	"strings"
	"testing"
)

func TestProcessScopeIsCanonicalExactAndTyped(t *testing.T) {
	const entity = "pe_017d9ed4a0ea4f517671139847db4941"
	process := Target{Kind: TargetProcess, Value: entity}
	if err := process.Validate(); err != nil {
		t.Fatalf("canonical process identity rejected: %v", err)
	}
	scope := Scope{InScope: []Target{process}}
	if !scope.AllowsTarget(process) {
		t.Fatal("exact process scope denied")
	}
	for _, value := range []string{"2582", " " + entity, entity + "\n", "process-1", "pe_*", entity + "0", entity[:len(entity)-1], strings.ToUpper(entity), "pe_" + strings.Repeat("g", 32)} {
		bad := Target{Kind: process.Kind, Value: value}
		if err := bad.Validate(); err == nil || scope.AllowsTarget(bad) {
			t.Errorf("invalid process identity accepted: %q", value)
		}
	}
	other := Target{Kind: process.Kind, Value: "pe_117d9ed4a0ea4f517671139847db4941"}
	if scope.AllowsTarget(other) {
		t.Fatal("different process allowed")
	}
	for _, kind := range []TargetKind{TargetDomain, TargetIP, TargetCIDR, TargetURL, TargetRepo, TargetImage, TargetCloudAccount} {
		otherKind := Target{Kind: kind, Value: entity}
		if scope.AllowsTarget(otherKind) || (Scope{InScope: []Target{otherKind}}).AllowsTarget(process) {
			t.Errorf("process identity crossed scope kind %q", kind)
		}
	}
	scope.OutOfScope = []Target{process}
	if scope.AllowsTarget(process) {
		t.Fatal("explicit process denial lost")
	}
}

func TestRepoAndImageScopeCannotAuthorizeProcess(t *testing.T) {
	process := Target{Kind: TargetProcess, Value: "pe_017d9ed4a0ea4f517671139847db4941"}
	for _, kind := range []TargetKind{TargetRepo, TargetImage} {
		if (Scope{InScope: []Target{{Kind: kind, Value: process.Value}}}).AllowsTarget(process) {
			t.Errorf("%s scope authorized a process by string equality", kind)
		}
	}
}

func TestProcessScopeFailsClosedWithoutInference(t *testing.T) {
	process := Target{Kind: TargetProcess, Value: "pe_11111111111111111111111111111111"}
	scope := Scope{InScope: []Target{process}}
	if scope.Allows(process.Value) {
		t.Fatal("untyped process identity granted authority")
	}
	scope.OutOfScope = []Target{{Kind: TargetProcess, Value: "pe_bad"}}
	if scope.AllowsTarget(process) {
		t.Fatal("malformed process deny did not fail closed")
	}
	scope.OutOfScope = []Target{{Kind: TargetURL, Value: "https://example.test/"}}
	if !scope.AllowsTarget(process) {
		t.Fatal("network exclusion captured process authority")
	}
}
