package pyreach_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/pyimports"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/srcimports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/analysis"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/export"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/pyreach"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachproof"
)

type sealer struct{}

func (sealer) Seal(context.Context, shared.ID, string, []byte, string) (evidence.Evidence, error) {
	return evidence.Evidence{}, nil
}

type auditor struct{}

func (auditor) Record(context.Context, ports.AuditEntry) error     { return nil }
func (auditor) RecordOnce(context.Context, ports.AuditEntry) error { return nil }

type clock struct{}

func (clock) Now() time.Time { return time.Unix(1700000000, 0).UTC() }

type ids struct{ n int }

func (i *ids) NewID() shared.ID { i.n++; return shared.ID(fmt.Sprintf("id-%d", i.n)) }

func writePy(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestPyReachToOpenVEXEndToEnd confirms a Python project imports `requests` but
// not `jinja2`, yielding a reachable result and a technical negative. Without an
// independently resolved authority context, export retains the false-positive's
// status-derived justification rather than treating the negative as authoritative.
func TestPyReachToOpenVEXEndToEnd(t *testing.T) {
	dir := writePy(t, map[string]string{
		"app/__init__.py": "",
		"app/main.py":     "import requests\n\ndef run():\n    return requests.get('https://x')\n",
		"pyproject.toml":  "[project]\ndependencies = [\"requests\", \"jinja2\"]\n",
	})

	store := memory.NewJudgmentStore()
	analysisSvc, err := analysis.NewService(store, sealer{}, auditor{}, clock{}, &ids{})
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	analyzer, err := pyreach.New(pyimports.New(), func(ctx context.Context, d string) (map[string]bool, bool) {
		return srcimports.DirectDependencies(ctx, d, "pypi")
	})
	if err != nil {
		t.Fatalf("analyzer: %v", err)
	}
	coord, err := reachproof.NewCoordinatorForTier(analyzer, analysisSvc, auditor{}, clock{}, judgment.Tier1)
	if err != nil {
		t.Fatalf("coordinator: %v", err)
	}

	const eng = shared.ID("eng-1")
	deadFinding := shared.ID("f-jinja2")
	liveFinding := shared.ID("f-requests")
	subs := []ports.ReachabilitySubject{
		{FindingID: deadFinding, Symbols: []string{"jinja2"}},   // declared, never imported → not_reachable
		{FindingID: liveFinding, Symbols: []string{"requests"}}, // imported → reachable
	}
	n, err := coord.Record(context.Background(), eng, dir, subs)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if n != 2 {
		t.Fatalf("want 2 reachability judgments minted, got %d", n)
	}

	// The jinja2 judgment must be a PUBLISHABLE Tier-1 not_reachable proof.
	js, _ := store.ListByEngagement(context.Background(), eng)
	var dead, live judgment.ReachabilityClaim
	var deadPub bool
	for _, j := range js {
		rc, _ := j.Claim.(judgment.ReachabilityClaim)
		switch j.SubjectID {
		case deadFinding:
			dead, deadPub = rc, j.Publishable()
		case liveFinding:
			live = rc
		}
	}
	if dead.Reachable != judgment.NotReachable || dead.Tier != judgment.Tier1 || !deadPub {
		t.Fatalf("jinja2 must be a publishable Tier-1 not_reachable judgment, got %+v publishable=%v", dead, deadPub)
	}
	if live.Reachable != judgment.Reachable {
		t.Fatalf("requests is imported → must be reachable, got %+v", live)
	}

	// Export has no live authority context, so this technical negative remains
	// non-suppressing and the false-positive uses its generic justification.
	findingRepo := memory.NewFindingRepository()
	if err := findingRepo.Upsert(context.Background(), []finding.Finding{{
		ID: deadFinding, EngagementID: eng, Kind: finding.KindSCA, Status: finding.StatusFalsePos,
		Title: "jinja2 vuln", Severity: shared.SeverityHigh, DedupKey: "vuln:CVE-2024-9999:jinja2:2.0",
	}}); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	exp := export.NewService(findingRepo, clock{}, "test")
	exp.SetJudgments(store)
	doc, err := exp.OpenVEX(context.Background(), eng, "")
	if err != nil {
		t.Fatalf("openvex: %v", err)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("want 1 VEX statement, got %d", len(doc.Statements))
	}
	st := doc.Statements[0]
	if st.Status != "not_affected" || st.Justification != "vulnerable_code_not_present" {
		t.Fatalf("OpenVEX must fail closed without current authority: got status=%q justification=%q", st.Status, st.Justification)
	}
}
