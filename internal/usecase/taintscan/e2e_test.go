package taintscan

import (
	"context"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/analysis"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/findings"
)

// TestTaintFileLineReachesFindingE2E is the deterministic end-to-end proof for #163: the real taint
// coordinator proposes a gated CapSAST judgment carrying the sink's file:line, a DISTINCT verifier confirms
// it (>= the evidence bar), and the emitted Kind=sast finding's title shows the file:line — not just a
// symbol. This is the "effective output" the def-use precision delivers, proven without a live model.
func TestTaintFileLineReachesFindingE2E(t *testing.T) {
	store := memory.NewJudgmentStore()
	findingRepo := memory.NewFindingRepository()
	analysisSvc, err := analysis.NewService(store, liveSealer{}, &fakeAudit{}, fixedClock{}, &liveIDs{})
	if err != nil {
		t.Fatalf("analysis service: %v", err)
	}
	analysisSvc.SetSASTRecorder(findings.NewService(findingRepo, nil, nil, &fakeAudit{}, fixedClock{}, &liveIDs{}))

	coord, err := NewCoordinator(
		&fakeBuilder{g: &callgraph.Graph{
			Edges:     []callgraph.Edge{{Caller: "app.handler", Callees: []string{"os.Getenv", "os/exec.Command"}}},
			Positions: map[string]string{"app.handler": "internal/app/handler.go:42"},
		}},
		analysisSvc, taint.DefaultCatalog(), &fakeAudit{}, fixedClock{},
	)
	if err != nil {
		t.Fatalf("coordinator: %v", err)
	}
	eng := shared.ID("eng-e2e")
	if n, err := coord.Scan(context.Background(), eng, "/work/target"); err != nil || n == 0 {
		t.Fatalf("taint scan proposed nothing: n=%d err=%v", n, err)
	}

	js, _ := store.ListByEngagement(context.Background(), eng)
	var jid shared.ID
	var ver int
	for _, j := range js {
		if j.Capability == judgment.CapSAST {
			jid, ver = j.ID, j.Version
		}
	}
	if jid == "" {
		t.Fatal("no CapSAST judgment was proposed")
	}
	// A DISTINCT verifier (≠ "system:taint-scan") confirms above the bar.
	if _, err := analysisSvc.Verify(context.Background(), "human:appsec-lead", eng, jid, 85, "reviewed the source→sink path", ver); err != nil {
		t.Fatalf("verify: %v", err)
	}

	fs, _ := findingRepo.ListByEngagement(context.Background(), eng)
	if len(fs) != 1 {
		t.Fatalf("want exactly one emitted finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Kind != finding.KindSAST {
		t.Fatalf("want Kind=sast, got %s", f.Kind)
	}
	if f.CWE != "CWE-78" {
		t.Errorf("want CWE-78 carried through, got %q", f.CWE)
	}
	if !strings.Contains(f.Title, "internal/app/handler.go:42") {
		t.Fatalf("the finding title must show the file:line (def-use precision), not just a symbol; got %q", f.Title)
	}
}
