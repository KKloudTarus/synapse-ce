package offensivepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type sealedRecord struct {
	engagementID shared.ID
	content      []byte
	createdBy    string
}

type fakeSealer struct {
	mu      sync.Mutex
	records []sealedRecord
	err     error
}

func (f *fakeSealer) SealOffensiveAuthorization(_ context.Context, engagementID shared.ID, content []byte, createdBy string) (shared.ID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return "", f.err
	}
	f.records = append(f.records, sealedRecord{engagementID: engagementID, content: content, createdBy: createdBy})
	return shared.ID("ev-" + createdBy), nil
}

type fakeAudit struct {
	mu      sync.Mutex
	entries []ports.AuditEntry
	err     error
}

func (f *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.entries = append(f.entries, e)
	return nil
}

func (f *fakeAudit) actions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.entries))
	for _, e := range f.entries {
		out = append(out, e.Action)
	}
	return out
}

func (f *fakeAudit) last() ports.AuditEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.entries) == 0 {
		return ports.AuditEntry{}
	}
	return f.entries[len(f.entries)-1]
}

var testNow = time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)

// completeRoE is an engagement that satisfies every document-5 field, so a test that wants to exercise
// one refusal can remove exactly one field rather than starting from nothing.
func completeRoE() RulesOfEngagement {
	return RulesOfEngagement{
		AuthorizedScope:   []string{"app.example.test"},
		WindowStart:       testNow.Add(-time.Hour),
		WindowEnd:         testNow.Add(time.Hour),
		CustomerContact:   "customer-ciso@example.test",
		EmergencyContact:  "+84-000-000-000",
		RiskCeiling:       domain.RiskHigh,
		ExclusionsChecked: true,
	}
}

func newService(t *testing.T) (*Service, *fakeSealer, *fakeAudit) {
	t.Helper()
	reg, err := domain.Load()
	if err != nil {
		t.Fatal(err)
	}
	sealer, audit := &fakeSealer{}, &fakeAudit{}
	svc, err := NewService(reg, sealer, audit)
	if err != nil {
		t.Fatal(err)
	}
	return svc, sealer, audit
}

// TestAuthorizeRefusesTechniqueWithNoRegisterEntry is acceptance criterion 3: a technique with no policy
// entry is refused by the enforcement path. This is the fail-closed default — the register is an
// allowlist, so "unknown" and "forbidden" are the same answer.
func TestAuthorizeRefusesTechniqueWithNoRegisterEntry(t *testing.T) {
	svc, sealer, audit := newService(t)
	_, err := svc.Authorize(context.Background(), Request{
		EngagementID: "eng-1", Technique: "exploit.brand_new_zero_day", Target: "https://app.example.test",
		Actor: "alice", RoE: completeRoE(), Now: testNow,
		Approvals: []Approval{{Approver: "alice", Technique: "exploit.brand_new_zero_day", Target: "https://app.example.test"}},
	})
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("an unregistered technique must be forbidden, got %v", err)
	}
	if len(sealer.records) != 0 {
		t.Error("a refused action must not seal an authorization")
	}
	if got := audit.last(); got.Action != "offensive.refused" || got.Metadata["reason"] != "no_register_entry" {
		t.Errorf("the refusal must be audited with its reason, got %+v", got)
	}
}

// TestAuthorizeRefusesProhibitedTechniqueWhateverTheApprovals: nothing about an engagement can make a
// prohibited technique permissible, including dual approval from two humans.
func TestAuthorizeRefusesProhibitedTechniqueWhateverTheApprovals(t *testing.T) {
	svc, sealer, audit := newService(t)
	for _, technique := range []string{"impact.service_stop", "exfil.bulk_data", "persist.scheduled_task"} {
		_, err := svc.Authorize(context.Background(), Request{
			EngagementID: "eng-1", Technique: technique, Target: "https://app.example.test",
			Actor: "alice", RoE: completeRoE(), Now: testNow,
			Approvals: []Approval{
				{Approver: "alice", Technique: technique, Target: "https://app.example.test"},
				{Approver: "bob", Technique: technique, Target: "https://app.example.test"},
			},
		})
		if !errors.Is(err, shared.ErrForbidden) {
			t.Errorf("%s is prohibited and must be forbidden even with dual approval, got %v", technique, err)
		}
		if got := audit.last(); got.Metadata["reason"] != "prohibited_category" {
			t.Errorf("%s: refusal reason = %q, want prohibited_category", technique, got.Metadata["reason"])
		}
	}
	if len(sealer.records) != 0 {
		t.Error("a prohibited technique must never seal an authorization")
	}
}

// TestAuthorizeRefusesMissingRulesOfEngagement is acceptance criterion for the RoE refusal: a missing
// field is a refusal, not a default. Each subtest removes exactly one field from an otherwise complete
// engagement, so a pass cannot come from some unrelated gap.
func TestAuthorizeRefusesMissingRulesOfEngagement(t *testing.T) {
	cases := map[string]func(*RulesOfEngagement){
		"authorized_scope":         func(r *RulesOfEngagement) { r.AuthorizedScope = nil },
		"authorization_window":     func(r *RulesOfEngagement) { r.WindowStart, r.WindowEnd = time.Time{}, time.Time{} },
		"customer_contact":         func(r *RulesOfEngagement) { r.CustomerContact = "  " },
		"emergency_contact":        func(r *RulesOfEngagement) { r.EmergencyContact = "" },
		"risk_ceiling":             func(r *RulesOfEngagement) { r.RiskCeiling = "" },
		"excluded_assets_reviewed": func(r *RulesOfEngagement) { r.ExclusionsChecked = false },
	}
	for field, remove := range cases {
		t.Run(field, func(t *testing.T) {
			svc, sealer, audit := newService(t)
			roe := completeRoE()
			remove(&roe)
			_, err := svc.Authorize(context.Background(), Request{
				EngagementID: "eng-1", Technique: "recon.service_banner", Target: "https://app.example.test",
				Actor: "alice", RoE: roe, Now: testNow,
			})
			if !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("a missing %s must be forbidden, got %v", field, err)
			}
			// The refusal must NAME the missing field. "forbidden" alone leaves an operator guessing which
			// of six fields to fill in.
			if !strings.Contains(err.Error(), field) {
				t.Errorf("the refusal does not name the missing field %q: %v", field, err)
			}
			if len(sealer.records) != 0 {
				t.Error("a refused action must not seal an authorization")
			}
			if got := audit.last().Metadata["reason"]; got != "missing_roe" {
				t.Errorf("refusal reason = %q, want missing_roe", got)
			}
		})
	}
}

// TestAuthorizeRefusesWithoutRecordedApproval is acceptance criterion 4: a technique whose risk class
// requires approval cannot execute without a recorded approval.
func TestAuthorizeRefusesWithoutRecordedApproval(t *testing.T) {
	const technique = "exploit.default_credentials" // medium -> single
	const target = "https://app.example.test"
	cases := map[string][]Approval{
		"no approvals at all": nil,
		// A machine may propose an offensive plan; it may never approve one.
		"machine principal": {{Approver: "system:dast-engine", Technique: technique, Target: target}},
		"agent principal":   {{Approver: "agent:runner", Technique: technique, Target: target}},
		// A signature collected for a different technique or target is not a signature for this one.
		"approval for another technique": {{Approver: "alice", Technique: "recon.tls_inspect", Target: target}},
		"approval for another target":    {{Approver: "alice", Technique: technique, Target: "https://other.example.test"}},
		"blank approver":                 {{Approver: "   ", Technique: technique, Target: target}},
	}
	for name, approvals := range cases {
		t.Run(name, func(t *testing.T) {
			svc, sealer, audit := newService(t)
			_, err := svc.Authorize(context.Background(), Request{
				EngagementID: "eng-1", Technique: technique, Target: target,
				Actor: "alice", RoE: completeRoE(), Now: testNow, Approvals: approvals,
			})
			if !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("want forbidden, got %v", err)
			}
			if len(sealer.records) != 0 {
				t.Error("an unapproved action must not seal an authorization")
			}
			if got := audit.last().Metadata["reason"]; got != "approval_missing" {
				t.Errorf("refusal reason = %q, want approval_missing", got)
			}
		})
	}
}

// TestAuthorizeRequiresTwoDistinctHumansForDualApproval: "dual" means two humans, not one human twice.
func TestAuthorizeRequiresTwoDistinctHumansForDualApproval(t *testing.T) {
	const technique = "exploit.web_shell_upload" // high -> dual
	const target = "https://app.example.test"
	svc, _, _ := newService(t)

	// The same human twice, in different letter case, is still one human.
	_, err := svc.Authorize(context.Background(), Request{
		EngagementID: "eng-1", Technique: technique, Target: target, Actor: "alice",
		RoE: completeRoE(), Now: testNow,
		Approvals: []Approval{
			{Approver: "alice", Technique: technique, Target: target},
			{Approver: "ALICE", Technique: technique, Target: target},
		},
	})
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("one human signing twice must not satisfy dual approval, got %v", err)
	}

	decision, err := svc.Authorize(context.Background(), Request{
		EngagementID: "eng-1", Technique: technique, Target: target, Actor: "alice",
		RoE: completeRoE(), Now: testNow,
		Approvals: []Approval{
			{Approver: "alice", Technique: technique, Target: target},
			{Approver: "bob", Technique: technique, Target: target},
		},
	})
	if err != nil {
		t.Fatalf("two distinct humans must satisfy dual approval: %v", err)
	}
	if len(decision.Approvers) != 2 {
		t.Fatalf("decision records %d approvers, want 2: %+v", len(decision.Approvers), decision.Approvers)
	}
}

// TestAuthorizeRefusesAboveTheEngagementRiskCeiling: the ceiling narrows the register and never widens
// it, so a high-risk technique is refused by a medium-ceiling engagement even with dual approval.
func TestAuthorizeRefusesAboveTheEngagementRiskCeiling(t *testing.T) {
	svc, _, audit := newService(t)
	roe := completeRoE()
	roe.RiskCeiling = domain.RiskMedium
	const technique = "exploit.web_shell_upload"
	const target = "https://app.example.test"
	_, err := svc.Authorize(context.Background(), Request{
		EngagementID: "eng-1", Technique: technique, Target: target, Actor: "alice",
		RoE: roe, Now: testNow,
		Approvals: []Approval{
			{Approver: "alice", Technique: technique, Target: target},
			{Approver: "bob", Technique: technique, Target: target},
		},
	})
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("want forbidden above the ceiling, got %v", err)
	}
	if got := audit.last().Metadata["reason"]; got != "above_risk_ceiling" {
		t.Errorf("refusal reason = %q, want above_risk_ceiling", got)
	}
}

func TestAuthorizeRefusesOutsideTheWindow(t *testing.T) {
	svc, _, audit := newService(t)
	roe := completeRoE()
	svc2 := svc
	for name, now := range map[string]time.Time{
		"before the window": roe.WindowStart.Add(-time.Minute),
		"after the window":  roe.WindowEnd.Add(time.Minute),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := svc2.Authorize(context.Background(), Request{
				EngagementID: "eng-1", Technique: "recon.service_banner", Target: "https://app.example.test",
				Actor: "alice", RoE: roe, Now: now,
			})
			if !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("want forbidden, got %v", err)
			}
			if got := audit.last().Metadata["reason"]; got != "outside_window" {
				t.Errorf("refusal reason = %q, want outside_window", got)
			}
		})
	}
}

// TestApprovalAppearsInTheEvidenceChain is acceptance criterion 7: approval appears in the evidence
// chain for the action, not only in configuration. The document is explicit that a stored flag saying
// "approved" is not an approval.
func TestApprovalAppearsInTheEvidenceChain(t *testing.T) {
	svc, sealer, audit := newService(t)
	const technique = "exploit.default_credentials"
	const target = "https://app.example.test"
	roe := completeRoE()

	decision, err := svc.Authorize(context.Background(), Request{
		EngagementID: "eng-42", Technique: technique, Target: target, Actor: "alice",
		RoE: roe, Now: testNow,
		Approvals: []Approval{{Approver: "carol", Technique: technique, Target: target}},
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if len(sealer.records) != 1 {
		t.Fatalf("want exactly one sealed authorization, got %d", len(sealer.records))
	}
	rec := sealer.records[0]
	if rec.engagementID != "eng-42" {
		t.Errorf("sealed under engagement %q, want eng-42", rec.engagementID)
	}
	var sealed sealedAuthorization
	if err := json.Unmarshal(rec.content, &sealed); err != nil {
		t.Fatalf("sealed payload is not decodable: %v", err)
	}
	// Everything document 4 requires: the approving human, the technique, the target, the window, the
	// timestamp.
	if sealed.Technique != technique || sealed.Target != target {
		t.Errorf("sealed technique/target = %q/%q", sealed.Technique, sealed.Target)
	}
	if len(sealed.Approvers) != 1 || sealed.Approvers[0] != "carol" {
		t.Errorf("sealed approvers = %v, want [carol]", sealed.Approvers)
	}
	if !sealed.WindowStart.Equal(roe.WindowStart.UTC()) || !sealed.WindowEnd.Equal(roe.WindowEnd.UTC()) {
		t.Errorf("sealed window = %v..%v", sealed.WindowStart, sealed.WindowEnd)
	}
	if !sealed.AuthorizedAt.Equal(testNow) {
		t.Errorf("sealed timestamp = %v, want %v", sealed.AuthorizedAt, testNow)
	}
	// The shipped policy is adopted by the maintainer but has no counsel review, and the seal must
	// record that pair honestly: an auditor reading the evidence must be able to tell that no external
	// counsel stood behind the action.
	if !sealed.PolicyAdopted {
		t.Error("the sealed record does not reflect that the policy is adopted")
	}
	if sealed.PolicyCounselReviewed {
		t.Error("the sealed record claims a counsel review; the shipped policy has none")
	}
	if decision.EvidenceID == "" {
		t.Error("the decision does not carry the evidence id it was sealed under")
	}
	if got := audit.last(); got.Action != "offensive.authorized" || got.Metadata["evidence_id"] != decision.EvidenceID.String() {
		t.Errorf("the authorization audit does not reference the evidence: %+v", got)
	}
}

// TestAuthorizeRefusesWhenEvidenceCannotBeSealed: evidence that failed to seal is not evidence, so the
// action is not authorized. This is the difference between approval-as-evidence and approval-as-config.
func TestAuthorizeRefusesWhenEvidenceCannotBeSealed(t *testing.T) {
	reg, err := domain.Load()
	if err != nil {
		t.Fatal(err)
	}
	sealer := &fakeSealer{err: errors.New("evidence store unavailable")}
	svc, err := NewService(reg, sealer, &fakeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	const technique = "exploit.default_credentials"
	const target = "https://app.example.test"
	_, err = svc.Authorize(context.Background(), Request{
		EngagementID: "eng-1", Technique: technique, Target: target, Actor: "alice",
		RoE: completeRoE(), Now: testNow,
		Approvals: []Approval{{Approver: "carol", Technique: technique, Target: target}},
	})
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("an unsealable authorization must be forbidden, got %v", err)
	}
}

func TestAuthorizeRefusesWithoutATimestamp(t *testing.T) {
	svc, _, audit := newService(t)
	_, err := svc.Authorize(context.Background(), Request{
		EngagementID: "eng-1", Technique: "recon.service_banner", Target: "https://app.example.test",
		Actor: "alice", RoE: completeRoE(),
	})
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("want forbidden, got %v", err)
	}
	if got := audit.last().Metadata["reason"]; got != "no_timestamp" {
		t.Errorf("refusal reason = %q, want no_timestamp", got)
	}
}

// TestAuthorizeAutomaticClassNeedsNoSignatureButIsStillSealed: an automatic technique runs without a
// per-action human decision, and is still recorded. "No approval needed" is not "no record needed".
func TestAuthorizeAutomaticClassNeedsNoSignatureButIsStillSealed(t *testing.T) {
	svc, sealer, audit := newService(t)
	decision, err := svc.Authorize(context.Background(), Request{
		EngagementID: "eng-1", Technique: "recon.service_banner", Target: "https://app.example.test",
		Actor: "alice", RoE: completeRoE(), Now: testNow,
	})
	if err != nil {
		t.Fatalf("an automatic-class technique inside scope must be permitted: %v", err)
	}
	if decision.Approval != domain.ApprovalAutomatic || len(decision.Approvers) != 0 {
		t.Errorf("decision = %+v, want automatic with no approvers", decision)
	}
	if len(sealer.records) != 1 {
		t.Fatalf("an automatic authorization must still be sealed, got %d records", len(sealer.records))
	}
	if got := audit.actions(); len(got) != 1 || got[0] != "offensive.authorized" {
		t.Errorf("audit actions = %v", got)
	}
}
