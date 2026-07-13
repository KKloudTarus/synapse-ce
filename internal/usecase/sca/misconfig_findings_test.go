package sca

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestBuildMisconfigFindings(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	raws := []ports.MisconfigRawFinding{
		{File: "Dockerfile", Line: 1, RuleID: "dockerfile-run-as-root", Title: "Container runs as root", Severity: shared.SeverityHigh, Resource: "Dockerfile USER", Description: "runs as root"},
		{File: "k8s/pod.yaml", Line: 12, RuleID: "kubernetes-privileged", Title: "Privileged container", Severity: shared.SeverityHigh, Resource: "Pod/api container=app", Description: "privileged"},
		{File: "info.yaml", Line: 3, RuleID: "low-note", Title: "low", Severity: shared.SeverityLow, Description: "note"},
	}

	// minSeverity=medium must drop the low finding.
	got := buildMisconfigFindings("eng-1", raws, now, shared.SeverityMedium)
	if len(got) != 2 {
		t.Fatalf("want 2 findings (low dropped by threshold), got %d", len(got))
	}
	for i, f := range got {
		if f.Kind != finding.KindMisconfig {
			t.Errorf("finding %q must be Kind=misconfig, got %q", f.Title, f.Kind)
		}
		if f.RuleKey != raws[i].RuleID {
			t.Errorf("finding %q must have RuleKey = %q, got %q", f.Title, raws[i].RuleID, f.RuleKey)
		}
		if f.Class != finding.ClassFirstParty {
			t.Errorf("misconfig must be first-party, got %q", f.Class)
		}
		if f.ProposedBy != "" || f.RequiresEvidenceGate() {
			t.Errorf("misconfig is deterministic → must be ungated/publishable, finding %q gated", f.Title)
		}
		if f.DedupKey == "" || f.EngagementID != "eng-1" {
			t.Errorf("finding %q missing dedup/engagement wiring", f.Title)
		}
	}

	// Ungated findings survive the publishability gate with a zero evidence score.
	if pub := finding.Publishable(got); len(pub) != 2 {
		t.Errorf("all misconfig findings must be publishable, got %d/2", len(pub))
	}

	// Re-scan idempotency: same raws → same finding IDs (dedup upsert in place).
	again := buildMisconfigFindings("eng-1", raws, now, shared.SeverityMedium)
	if again[0].ID != got[0].ID || again[1].ID != got[1].ID {
		t.Error("re-scan must produce stable finding IDs for in-place upsert")
	}
}
