package offensivepolicy

import (
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// mutate returns the embedded register with one YAML substitution applied, so a test can assert that a
// malformed register is REFUSED at load rather than accepted and enforced.
func mutate(t *testing.T, old, new string) error {
	t.Helper()
	raw := strings.ReplaceAll(string(embeddedPolicy), "\r\n", "\n")
	old = strings.ReplaceAll(old, "\r\n", "\n")
	new = strings.ReplaceAll(new, "\r\n", "\n")
	if !strings.Contains(raw, old) {
		t.Fatalf("fixture anchor not found in policy.yaml: %q", old)
	}
	_, err := parse([]byte(strings.Replace(raw, old, new, 1)))
	return err
}

// TestLoadEmbeddedRegisterIsValid is the baseline: the register that actually ships must load.
func TestLoadEmbeddedRegisterIsValid(t *testing.T) {
	reg, err := Load()
	if err != nil {
		t.Fatalf("the shipped register does not load: %v", err)
	}
	if len(reg.TechniqueIDs()) == 0 {
		t.Fatal("the shipped register is empty")
	}
}

// TestLookupRefusesUnregisteredTechnique is the fail-closed default and the single most important
// property in this package: the register is an allowlist. An unknown technique is not "unrestricted",
// it is refused, because the set of things an offensive engine could attempt is unbounded.
func TestLookupRefusesUnregisteredTechnique(t *testing.T) {
	reg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"exploit.rce_unclassified", "", "   ", "RECON.SERVICE_BANNER", "recon.service_banner ",
		"../recon.service_banner", "recon.service_banner\x00",
	} {
		if _, ok := reg.Lookup(name); ok && strings.TrimSpace(name) != "recon.service_banner" {
			t.Errorf("technique %q must not resolve to a policy entry", name)
		}
	}
	// A nil register refuses everything rather than panicking: a caller that failed to load the policy
	// must not be able to proceed as though nothing were restricted.
	var nilReg *Register
	if _, ok := nilReg.Lookup("recon.service_banner"); ok {
		t.Error("a nil register must refuse every technique")
	}
}

// TestRegisterRejectsStateChangingWithoutCleanup is the CI-time gate the document's §7 promises.
// Discovering an unreversible action at runtime means it has already run.
func TestRegisterRejectsStateChangingWithoutCleanup(t *testing.T) {
	err := mutate(t, `    blast_radius: state_changing
    cleanup:
      steps:
        - delete uploaded artifact
      verification: verify absence`, `    blast_radius: state_changing
    cleanup:
      steps: []
      verification: ""`)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a state-changing technique with no cleanup path must fail validation, got %v", err)
	}
	if !strings.Contains(err.Error(), "cleanup steps") {
		t.Errorf("the refusal must name the missing cleanup: %v", err)
	}
}

// TestRegisterRejectsStateChangingWithoutVerification: steps alone are not a cleanup path. An undo
// nobody checks is a hope.
func TestRegisterRejectsStateChangingWithoutVerification(t *testing.T) {
	err := mutate(t, `      verification: verify absence`, `      verification: ""`)
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "verification") {
		t.Fatalf("a cleanup path with no verification must fail validation, got %v", err)
	}
}

// TestRegisterRejectsSofterClassThanTheAxesImply stops the drift that matters most: a hand-written risk
// class that is gentler than the two axes reduce to would silently lower the approval requirement.
func TestRegisterRejectsSofterClassThanTheAxesImply(t *testing.T) {
	err := mutate(t, `    disruption: low
    reversibility: irreversible
    risk_class: high
    approval: dual`, `    disruption: low
    reversibility: irreversible
    risk_class: medium
    approval: single`)
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "reduce") {
		t.Fatalf("a class softer than its axes must fail validation, got %v", err)
	}
}

// TestRegisterRejectsApprovalMismatch pins the §4 matrix: the register cannot disagree with it.
func TestRegisterRejectsApprovalMismatch(t *testing.T) {
	err := mutate(t, `    risk_class: medium
    approval: single`, `    risk_class: medium
    approval: automatic`)
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "approval must be") {
		t.Fatalf("an approval mode that contradicts the risk class must fail validation, got %v", err)
	}
}

// TestRegisterRejectsApprovableProhibitedTechnique: allowing an approval mode on a prohibited technique
// would imply some signature could authorise it. None can.
func TestRegisterRejectsApprovableProhibitedTechnique(t *testing.T) {
	err := mutate(t, `    risk_class: prohibited
    approval: ""`, `    risk_class: prohibited
    approval: dual`)
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "must not carry an approval mode") {
		t.Fatalf("a prohibited technique with an approval mode must fail validation, got %v", err)
	}
}

// TestRegisterRefusesProductionSafeBeforeCounselReview is referenced by name in the policy document's
// Status section. Production clearance is gated on EXTERNAL COUNSEL review, and the shipped register
// records only maintainer adoption (counsel_reviewed: false) — so marking any technique production-safe
// must still fail, proving that a maintainer adopting the policy does not lift the production gate.
func TestRegisterRefusesProductionSafeBeforeCounselReview(t *testing.T) {
	err := mutate(t, `    blast_radius: read_only
    cleanup:
      steps: []
      verification: ""
    production_safe: false`, `    blast_radius: read_only
    cleanup:
      steps: []
      verification: ""
    production_safe: true`)
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "before external legal counsel review") {
		t.Fatalf("production-safe before a recorded counsel review must fail validation, got %v", err)
	}
}

// TestAdoptionAloneDoesNotClearProductionSafe is the important negative: the shipped register IS adopted
// (reviewed: true), and that must NOT be enough. If a future edit ever re-gated production_safe on
// adoption instead of counsel, this fails.
func TestAdoptionAloneDoesNotClearProductionSafe(t *testing.T) {
	reg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reg.LegalReview.Reviewed {
		t.Fatal("fixture expects the shipped policy to be adopted")
	}
	if reg.LegalReview.CounselReviewed {
		t.Fatal("fixture expects counsel review to still be pending")
	}
	// Marking a technique production-safe under adoption-but-not-counsel must be refused.
	if err := mutate(t, "    production_safe: false", "    production_safe: true"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("adoption alone must not clear production-safe, got %v", err)
	}
}

// TestRecordedAdoptionNeedsDateOwnerAndReviewer: a recorded adoption that omits any of the three is not
// a review, it is a claim.
func TestRecordedAdoptionNeedsDateOwnerAndReviewer(t *testing.T) {
	if err := mutate(t, `  date: "2026-08-10"`, `  date: ""`); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("adoption without a date must fail, got %v", err)
	}
	if err := mutate(t, `  reviewer: "nghiadaulau (repository maintainer, accountable owner)"`, `  reviewer: ""`); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("adoption without a reviewer must fail, got %v", err)
	}
}

// TestRecordedCounselReviewNeedsDateAndReviewer: if counsel review is ever recorded, it must carry who
// and when, or it unlocks production clearance on an anonymous, undated claim.
func TestRecordedCounselReviewNeedsDateAndReviewer(t *testing.T) {
	err := mutate(t, `  counsel_reviewed: false
  counsel_date: ""
  counsel_reviewer: ""`, `  counsel_reviewed: true
  counsel_date: ""
  counsel_reviewer: ""`)
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "counsel review needs") {
		t.Fatalf("a recorded counsel review without a date and reviewer must fail, got %v", err)
	}
}

// TestRegisterRejectsUnknownFields catches a typo'd key, which YAML would otherwise ignore in silence —
// and a policy field that is silently ignored is a control that silently does not exist.
func TestRegisterRejectsUnknownFields(t *testing.T) {
	if err := mutate(t, `    production_safe: false`, `    production_safe: false
    prod_safe: true`); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an unknown policy field must fail to load, got %v", err)
	}
}

// TestRegisterRejectsUnclassifiableTechnique: a technique that cannot state both axes is refused, which
// is the same outcome as having no entry at all (document §3).
func TestRegisterRejectsUnclassifiableTechnique(t *testing.T) {
	err := mutate(t, `    disruption: none
    reversibility: reversible
    risk_class: low`, `    disruption: ""
    reversibility: reversible
    risk_class: low`)
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "both risk axes") {
		t.Fatalf("a technique missing a risk axis must fail validation, got %v", err)
	}
}

func TestRegisterRejectsDuplicateTechnique(t *testing.T) {
	err := mutate(t, `  - technique: recon.tls_inspect`, `  - technique: recon.service_banner`)
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("a duplicate technique must fail validation, got %v", err)
	}
}

// TestRiskCeilingOnlyNarrows pins document §5: an engagement's ceiling can reduce what the register
// permits and can never widen it, and no ceiling whatsoever permits a prohibited technique.
func TestRiskCeilingOnlyNarrows(t *testing.T) {
	tests := []struct {
		ceiling, have RiskClass
		want          bool
	}{
		{RiskLow, RiskLow, true},
		{RiskLow, RiskMedium, false},
		{RiskLow, RiskHigh, false},
		{RiskMedium, RiskLow, true},
		{RiskMedium, RiskMedium, true},
		{RiskMedium, RiskHigh, false},
		{RiskHigh, RiskHigh, true},
		// No ceiling permits a prohibited technique, including a ceiling of "prohibited" itself, which
		// is not a permission level but a refusal.
		{RiskHigh, RiskProhibited, false},
		{RiskProhibited, RiskLow, false},
		{RiskProhibited, RiskProhibited, false},
		// An unset or unknown ceiling permits nothing.
		{RiskClass(""), RiskLow, false},
		{RiskClass("critical"), RiskLow, false},
	}
	for _, tc := range tests {
		if got := RiskCeilingPermits(tc.ceiling, tc.have); got != tc.want {
			t.Errorf("RiskCeilingPermits(%q, %q) = %v, want %v", tc.ceiling, tc.have, got, tc.want)
		}
	}
}

func TestRequiredApprovalsCounts(t *testing.T) {
	for mode, want := range map[ApprovalMode]int{
		ApprovalAutomatic: 0, ApprovalSingle: 1, ApprovalDual: 2, ApprovalNone: 0, ApprovalMode("triple"): 0,
	} {
		if got := mode.RequiredApprovals(); got != want {
			t.Errorf("%q requires %d approvals, want %d", mode, got, want)
		}
	}
}
