package sca

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestFPTriageCandidates(t *testing.T) {
	fs := []finding.Finding{
		{DedupKey: "sast-prod", Kind: finding.KindSAST, Scope: sbom.ScopeProduction},
		{DedupKey: "secret-prod", Kind: finding.KindSecret, Scope: sbom.ScopeProduction},
		{DedupKey: "misconfig-prod", Kind: finding.KindMisconfig, Scope: sbom.ScopeProduction},
		{DedupKey: "sast-test", Kind: finding.KindSAST, Scope: sbom.ScopeTest},       // background → skip
		{DedupKey: "sca-prod", Kind: finding.KindSCA, Scope: sbom.ScopeProduction},   // SCA → skip (DB-backed fact)
		{DedupKey: "sast-fixture", Kind: finding.KindSAST, Scope: sbom.ScopeFixture}, // background → skip
	}
	got := fpTriageCandidates(fs)
	if len(got) != 3 {
		t.Fatalf("want 3 production source candidates, got %d: %+v", len(got), got)
	}
	for _, c := range got {
		if sbom.IsBackgroundScope(c.Scope) || c.Kind == finding.KindSCA {
			t.Errorf("unexpected candidate: %+v", c)
		}
	}
}

func TestSuspectedFPKeys(t *testing.T) {
	res := &ScanResult{AITriage: []ports.AICritique{
		{DedupKey: "a", SuspectedFP: true},
		{DedupKey: "b", SuspectedFP: false},
		{DedupKey: "c", SuspectedFP: true},
	}}
	keys := res.SuspectedFPKeys()
	if len(keys) != 2 || !keys["a"] || !keys["c"] || keys["b"] {
		t.Errorf("SuspectedFPKeys = %v, want {a,c}", keys)
	}
}
