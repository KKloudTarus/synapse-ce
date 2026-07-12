package fptriage

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestTriagerMapsToPortsDTO(t *testing.T) {
	llm := fakeLLM{byTitleSubstr: map[string]string{
		"fp.go":   `{"verdict":"refuted","driver":"test_or_example_code","confidence":90}`,
		"real.go": `{"verdict":"sound","driver":"attacker_controlled","confidence":80}`,
	}}
	tr := NewTriager(New(llm, "m"), nil) // nil reader → metadata-only critique
	var _ ports.FPTriager = tr           // implements the port
	cands := []finding.Finding{
		mkFinding("1", "X (a/fp.go:1)"),
		mkFinding("2", "Y (a/real.go:2)"),
	}
	out := tr.Triage(context.Background(), cands, "/root")
	if len(out) != 2 {
		t.Fatalf("want 2 critiques, got %d", len(out))
	}
	byKey := map[string]ports.AICritique{}
	for _, c := range out {
		byKey[c.DedupKey] = c
	}
	if c := byKey["dk-1"]; !c.SuspectedFP || c.Verdict != "refuted" || c.Driver != "test_or_example_code" {
		t.Errorf("fp finding mapping wrong: %+v", c)
	}
	if c := byKey["dk-2"]; c.SuspectedFP || c.Verdict != "sound" {
		t.Errorf("sound finding must not be suspected-FP: %+v", c)
	}
	// Verified is false in single-model mode.
	if byKey["dk-1"].Verified {
		t.Error("single-model refutation must not be marked verified")
	}
}

func TestTriagerNilSafe(t *testing.T) {
	var tr *Triager
	if got := tr.Triage(context.Background(), []finding.Finding{mkFinding("1", "X (a.go:1)")}, "/r"); got != nil {
		t.Errorf("nil triager must return nil, got %v", got)
	}
	if got := NewTriager(nil, nil).Triage(context.Background(), nil, "/r"); got != nil {
		t.Errorf("nil coordinator / no candidates must return nil, got %v", got)
	}
}
