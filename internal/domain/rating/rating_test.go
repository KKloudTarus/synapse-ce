package rating

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func f(kind finding.Kind, sev shared.Severity) finding.Finding {
	return finding.Finding{Kind: kind, Severity: sev}
}

func TestCleanCodebaseAllA(t *testing.T) {
	r := Compute(nil, 1000)
	if r.Security != GradeA || r.Reliability != GradeA || r.Maintainability != GradeA {
		t.Errorf("empty findings should be all A, got %+v", r)
	}
	if r.TechDebtMinutes != 0 || r.DebtRatioPct != 0 {
		t.Errorf("no debt expected, got %+v", r)
	}
}

func TestSecurityAndReliabilityWorstSeverity(t *testing.T) {
	findings := []finding.Finding{
		f(finding.KindSAST, shared.SeverityHigh),            // security worst = high -> D
		f(finding.KindSCA, shared.SeverityLow),              // security low (dominated)
		f(finding.KindReliability, shared.SeverityCritical), // reliability critical -> E
	}
	r := Compute(findings, 1000)
	if r.Security != GradeD {
		t.Errorf("security want D (worst=high), got %s", r.Security)
	}
	if r.Reliability != GradeE {
		t.Errorf("reliability want E (critical bug), got %s", r.Reliability)
	}
	if r.Maintainability != GradeA {
		t.Errorf("no maintainability issues -> A, got %s", r.Maintainability)
	}
}

func TestMaintainabilityDebtRatio(t *testing.T) {
	// 3 medium quality issues = 3*20 = 60 min of debt.
	findings := []finding.Finding{
		f(finding.KindQuality, shared.SeverityMedium),
		f(finding.KindQuality, shared.SeverityMedium),
		f(finding.KindQuality, shared.SeverityMedium),
	}
	// loc=10 -> devCost=300 -> ratio=20% -> C
	r := Compute(findings, 10)
	if r.TechDebtMinutes != 60 {
		t.Errorf("debt want 60, got %d", r.TechDebtMinutes)
	}
	if r.DebtRatioPct != 20 {
		t.Errorf("ratio want 20, got %.1f", r.DebtRatioPct)
	}
	if r.Maintainability != GradeC {
		t.Errorf("ratio 20%% -> C, got %s", r.Maintainability)
	}
	// loc=5 -> devCost=150 -> ratio=40% -> D
	if g := Compute(findings, 5).Maintainability; g != GradeD {
		t.Errorf("ratio 40%% -> D, got %s", g)
	}
	// loc=1000 -> devCost=30000 -> ratio=0.2% -> A
	if g := Compute(findings, 1000).Maintainability; g != GradeA {
		t.Errorf("low ratio -> A, got %s", g)
	}
}

func TestInfoDoesNotDegradeSecurity(t *testing.T) {
	r := Compute([]finding.Finding{f(finding.KindSAST, shared.SeverityInfo)}, 1000)
	if r.Security != GradeA {
		t.Errorf("info-only security -> A, got %s", r.Security)
	}
}

func TestNonRatingKindsIgnored(t *testing.T) {
	// recon/manual/threat must not affect any grade.
	r := Compute([]finding.Finding{
		f(finding.KindRecon, shared.SeverityCritical),
		f(finding.KindManual, shared.SeverityCritical),
		f(finding.KindThreat, shared.SeverityCritical),
	}, 1000)
	if r.Security != GradeA || r.Reliability != GradeA || r.Maintainability != GradeA {
		t.Errorf("non-rating kinds must not degrade grades, got %+v", r)
	}
}
