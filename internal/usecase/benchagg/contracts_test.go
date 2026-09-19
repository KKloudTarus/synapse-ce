package benchagg

import (
	"encoding/json"
	"os"
	"testing"
)

const committedContractsPath = "../../../docs/benchmarks/dimension-contracts.json"

// TestCommittedContractManifestIsValid is the drift guard for the committed truth-contract manifest: it loads,
// validates (schema, complete contracts with documented Unknown semantics, floors in range), and covers exactly
// the five #1040 A5 dimensions. It runs with no scanner or corpus present, so the versioned truth contract is
// checked in every CI run.
func TestCommittedContractManifestIsValid(t *testing.T) {
	data, err := os.ReadFile(committedContractsPath)
	if err != nil {
		t.Fatalf("read committed contract manifest: %v", err)
	}
	var m ContractManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("decode committed contract manifest: %v", err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("committed contract manifest must validate: %v", err)
	}
	// The five A5 dimensions this issue added gates for must each have a contract.
	for _, id := range []string{"secrets", "iac-misconfig", "dast", "cspm", "host-cve"} {
		if _, ok := m.Dimensions[id]; !ok {
			t.Errorf("contract manifest is missing dimension %q", id)
		}
	}
	// The committed floors must match the gates they document, so lowering a gate's floor without updating the
	// truth contract (or vice versa) is caught. secrets is the only dimension whose precision floor is below 1.0.
	if got := m.Dimensions["secrets"].PrecisionFloor; got != 0.85 {
		t.Errorf("secrets precision floor = %v, want 0.85 (must match secretsOwnedPrecisionFloor)", got)
	}
	for _, id := range []string{"secrets", "iac-misconfig", "dast", "cspm", "host-cve"} {
		if got := m.Dimensions[id].RecallFloor; got != 1.0 {
			t.Errorf("%s recall floor = %v, want 1.0", id, got)
		}
	}
}

func TestContractValidateRejectsIncomplete(t *testing.T) {
	base := func() ContractManifest {
		return ContractManifest{
			Schema: ContractSchemaVersion,
			Dimensions: map[string]Contract{
				"d": {Positive: "p", Unit: "u", UnknownSemantics: "s", Provenance: "prov", RecallFloor: 1, PrecisionFloor: 1},
			},
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("a complete manifest must validate: %v", err)
	}
	cases := map[string]func(*ContractManifest){
		"wrong schema":       func(m *ContractManifest) { m.Schema = "nope" },
		"no dimensions":      func(m *ContractManifest) { m.Dimensions = nil },
		"missing unknown":    func(m *ContractManifest) { d := m.Dimensions["d"]; d.UnknownSemantics = ""; m.Dimensions["d"] = d },
		"missing provenance": func(m *ContractManifest) { d := m.Dimensions["d"]; d.Provenance = ""; m.Dimensions["d"] = d },
		"missing positive":   func(m *ContractManifest) { d := m.Dimensions["d"]; d.Positive = ""; m.Dimensions["d"] = d },
		"floor out of range": func(m *ContractManifest) { d := m.Dimensions["d"]; d.RecallFloor = 1.5; m.Dimensions["d"] = d },
	}
	for name, mutate := range cases {
		m := base()
		mutate(&m)
		if err := m.Validate(); err == nil {
			t.Errorf("%s: Validate must reject it", name)
		}
	}
}
