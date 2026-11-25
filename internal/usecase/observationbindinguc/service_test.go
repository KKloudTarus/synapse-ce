package observationbindinguc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/observationbinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeAudit struct{ entries []ports.AuditEntry }

func (f *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	f.entries = append(f.entries, e)
	return nil
}

type failingAudit struct{}

func (failingAudit) Record(context.Context, ports.AuditEntry) error {
	return errors.New("audit log unavailable")
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(1700000000, 0).UTC() }

type seqIDs struct{ n int }

func (s *seqIDs) NewID() shared.ID { s.n++; return shared.ID("bind-" + string(rune('0'+s.n))) }

type fakeEngagements struct{ tenant shared.ID }

func (f fakeEngagements) GetByIDInTenant(_ context.Context, tenantID, id shared.ID) (*engagement.Engagement, error) {
	stamped := f.tenant
	if stamped == "" {
		stamped = tenantID
	}
	return &engagement.Engagement{ID: id, TenantID: stamped}, nil
}

type fakeFindings struct{ list []finding.Finding }

func (f fakeFindings) ListByEngagement(context.Context, shared.ID) ([]finding.Finding, error) {
	return f.list, nil
}

// observation returns a stored SARIF result with a tool fingerprint, which is the identity a decision
// about it is keyed on.
func observation(id shared.ID, fingerprint string) importedfinding.ImportedFinding {
	at := time.Unix(1700000000, 0).UTC()
	return importedfinding.ImportedFinding{
		ID: id, TenantID: "t1", EngagementID: "eng1",
		Severity: shared.SeverityHigh, Title: "external result", Message: "m",
		Location:    importedfinding.Location{Path: "src/app.go", StartLine: 42},
		Fingerprint: fingerprint,
		Provenance: importedfinding.Provenance{
			ToolName: "semgrep", ToolVersion: "1.2.3", RuleID: "rule.a",
			SourceDigest: "sha256:doc", IngestedBy: "human:alice", IngestedAt: at,
		},
		Audit: shared.Audit{CreatedAt: at, UpdatedAt: at},
	}
}

func newService(t *testing.T, observations []importedfinding.ImportedFinding, findings []finding.Finding) (*Service, *memory.ObservationBindingStore, *fakeAudit) {
	t.Helper()
	store := memory.NewImportedFindingStore()
	if len(observations) > 0 {
		if _, _, err := store.Save(context.Background(), "t1", observations); err != nil {
			t.Fatalf("seed observations: %v", err)
		}
	}
	bindings := memory.NewObservationBindingStore()
	audit := &fakeAudit{}
	svc, err := NewService(bindings, store, fakeFindings{list: findings}, fakeEngagements{}, audit, fixedClock{}, &seqIDs{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc, bindings, audit
}

func decide(t *testing.T, svc *Service, req DecideRequest) (observationbinding.Binding, error) {
	t.Helper()
	if req.TenantID == "" {
		req.TenantID = "t1"
	}
	if req.EngagementID == "" {
		req.EngagementID = "eng1"
	}
	if req.Actor == "" {
		req.Actor = "human:alice"
	}
	if req.Reason == "" {
		req.Reason = "confirmed by hand, same injection"
	}
	return svc.Decide(context.Background(), req)
}

func TestDecideRecordsTheActorAndTheReason(t *testing.T) {
	t.Parallel()
	svc, _, audit := newService(t, []importedfinding.ImportedFinding{observation("o1", "abc")}, []finding.Finding{{ID: "f1", EngagementID: "eng1"}})

	binding, err := decide(t, svc, DecideRequest{ObservationID: "o1", FindingID: "f1"})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if binding.DecidedBy != "human:alice" || binding.Reason == "" {
		t.Fatalf("binding = %+v, want the actor and the reason recorded", binding)
	}
	// Identity is keyed on what survives a re-import, not on the row id.
	if binding.Scope != "semgrep" || binding.ExternalIdentity != "fingerprint:abc" {
		t.Fatalf("identity = %s/%s, want the tool and its fingerprint", binding.Scope, binding.ExternalIdentity)
	}
	if binding.ObservationID != "o1" {
		t.Fatalf("lineage = %s, want the observation the decision was made on", binding.ObservationID)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "finding.observation.bound" {
		t.Fatalf("audit = %+v, want one bound entry", audit.entries)
	}
}

func TestADecisionWithoutAReasonOrAnActorIsRefused(t *testing.T) {
	t.Parallel()
	svc, _, _ := newService(t, []importedfinding.ImportedFinding{observation("o1", "abc")}, []finding.Finding{{ID: "f1", EngagementID: "eng1"}})

	if _, err := svc.Decide(context.Background(), DecideRequest{TenantID: "t1", EngagementID: "eng1", ObservationID: "o1", FindingID: "f1", Reason: "why"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a decision with no actor = %v, want a validation error", err)
	}
	if _, err := svc.Decide(context.Background(), DecideRequest{TenantID: "t1", EngagementID: "eng1", ObservationID: "o1", FindingID: "f1", Actor: "human:alice"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a decision with no reason = %v, want a validation error", err)
	}
}

func TestBindingAFindingFromAnotherEngagementIsRefused(t *testing.T) {
	t.Parallel()
	// The PostgreSQL store also refuses this through a composite foreign key. The usecase check makes the
	// in-memory adapter behave the same and turns a constraint name into a clear refusal.
	svc, _, _ := newService(t, []importedfinding.ImportedFinding{observation("o1", "abc")}, []finding.Finding{{ID: "f1", EngagementID: "eng1"}})
	if _, err := decide(t, svc, DecideRequest{ObservationID: "o1", FindingID: "f-elsewhere"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("binding a foreign finding = %v, want not found", err)
	}
}

func TestBindingAnObservationFromAnotherEngagementIsRefused(t *testing.T) {
	t.Parallel()
	svc, _, _ := newService(t, []importedfinding.ImportedFinding{observation("o1", "abc")}, []finding.Finding{{ID: "f1", EngagementID: "eng1"}})
	if _, err := decide(t, svc, DecideRequest{ObservationID: "o-elsewhere", FindingID: "f1"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("binding a foreign observation = %v, want not found", err)
	}
}

// stubObservations returns whatever it is given, so a test can present an observation the real store
// would have refused to persist.
type stubObservations struct {
	list []importedfinding.ImportedFinding
}

func (stubObservations) Save(context.Context, shared.ID, []importedfinding.ImportedFinding) (int, int, error) {
	return 0, 0, nil
}
func (s stubObservations) ListByEngagement(context.Context, shared.ID, shared.ID) ([]importedfinding.ImportedFinding, error) {
	return s.list, nil
}
func (stubObservations) ExistsDigest(context.Context, shared.ID, shared.ID, string) (bool, error) {
	return false, nil
}

func TestAnObservationWithNoDurableIdentityCannotBeBound(t *testing.T) {
	t.Parallel()
	// No fingerprint and no rule: nothing about this result survives a re-import, so a decision would
	// have nothing to attach to. Binding it anyway would produce a record that silently stops applying
	// the next time the report is imported.
	anonymous := observation("o1", "")
	anonymous.Provenance.RuleID = ""

	svc, err := NewService(memory.NewObservationBindingStore(), stubObservations{list: []importedfinding.ImportedFinding{anonymous}},
		fakeFindings{list: []finding.Finding{{ID: "f1", EngagementID: "eng1"}}}, fakeEngagements{}, &fakeAudit{}, fixedClock{}, &seqIDs{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	if _, err := decide(t, svc, DecideRequest{ObservationID: "o1", FindingID: "f1"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("binding an identity-less observation = %v, want a validation error", err)
	}
}

func TestRedecidingTheSameFindingIsIdempotent(t *testing.T) {
	t.Parallel()
	svc, bindings, _ := newService(t, []importedfinding.ImportedFinding{observation("o1", "abc")}, []finding.Finding{{ID: "f1", EngagementID: "eng1"}})

	first, err := decide(t, svc, DecideRequest{ObservationID: "o1", FindingID: "f1"})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	second, err := decide(t, svc, DecideRequest{ObservationID: "o1", FindingID: "f1"})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("retry minted binding %s, want the existing %s", second.ID, first.ID)
	}
	all, err := bindings.ListByEngagement(context.Background(), "t1", "eng1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("%d versions after a retry, want 1", len(all))
	}
}

func TestChangingTheBoundFindingNeedsAnExplicitSupersede(t *testing.T) {
	t.Parallel()
	svc, _, audit := newService(t, []importedfinding.ImportedFinding{observation("o1", "abc")},
		[]finding.Finding{{ID: "f1", EngagementID: "eng1"}, {ID: "f2", EngagementID: "eng1"}})

	if _, err := decide(t, svc, DecideRequest{ObservationID: "o1", FindingID: "f1"}); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	// Naming a different finding without naming the version being replaced is a conflict, never a
	// silent replacement.
	if _, err := decide(t, svc, DecideRequest{ObservationID: "o1", FindingID: "f2"}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("an implicit rebind = %v, want a conflict", err)
	}
	rebound, err := decide(t, svc, DecideRequest{ObservationID: "o1", FindingID: "f2", ExpectedVersion: 1, Reason: "the first match was a coincidence of line"})
	if err != nil {
		t.Fatalf("supersede: %v", err)
	}
	if rebound.Version != 2 || rebound.FindingID != "f2" {
		t.Fatalf("rebound = %+v, want version 2 on f2", rebound)
	}
	if len(audit.entries) != 2 || audit.entries[1].Action != "finding.observation.rebound" {
		t.Fatalf("audit = %+v, want a distinct rebound entry", audit.entries)
	}
}

func TestCurrentReturnsOnlyTheVersionInForce(t *testing.T) {
	t.Parallel()
	svc, _, _ := newService(t, []importedfinding.ImportedFinding{observation("o1", "abc")},
		[]finding.Finding{{ID: "f1", EngagementID: "eng1"}, {ID: "f2", EngagementID: "eng1"}})

	if _, err := decide(t, svc, DecideRequest{ObservationID: "o1", FindingID: "f1"}); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if _, err := decide(t, svc, DecideRequest{ObservationID: "o1", FindingID: "f2", ExpectedVersion: 1, Reason: "rebound"}); err != nil {
		t.Fatalf("supersede: %v", err)
	}

	current, err := svc.Current(context.Background(), "t1", "eng1")
	if err != nil {
		t.Fatalf("current: %v", err)
	}
	if len(current) != 1 {
		t.Fatalf("%d bindings in force, want 1", len(current))
	}
	binding := current[observationbinding.Identity{Scope: "semgrep", ExternalIdentity: "fingerprint:abc"}]
	if binding.FindingID != "f2" || binding.Version != 2 {
		t.Fatalf("binding in force = %+v, want version 2 on f2", binding)
	}

	// The lineage read keeps both, which is the only way a wrong decision can be audited.
	all, err := svc.List(context.Background(), "t1", "eng1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("%d versions in the lineage, want both", len(all))
	}
}

func TestADecisionThatCannotBeAuditedSaysItWasRecorded(t *testing.T) {
	t.Parallel()
	store := memory.NewImportedFindingStore()
	if _, _, err := store.Save(context.Background(), "t1", []importedfinding.ImportedFinding{observation("o1", "abc")}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	bindings := memory.NewObservationBindingStore()
	svc, err := NewService(bindings, store, fakeFindings{list: []finding.Finding{{ID: "f1", EngagementID: "eng1"}}},
		fakeEngagements{}, failingAudit{}, fixedClock{}, &seqIDs{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	_, err = decide(t, svc, DecideRequest{ObservationID: "o1", FindingID: "f1"})
	if err == nil {
		t.Fatal("an audit failure must surface")
	}
	// The decision is already durable. Saying only "audit failed" would leave the caller believing
	// nothing was recorded.
	if !contains(err.Error(), "was recorded but could not be audited") {
		t.Fatalf("error = %q, want it to state that the decision is durable", err)
	}
	all, listErr := bindings.ListByEngagement(context.Background(), "t1", "eng1")
	if listErr != nil {
		t.Fatalf("list: %v", listErr)
	}
	if len(all) != 1 {
		t.Fatalf("%d bindings stored, want the durable one the error describes", len(all))
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func TestANegativeExpectedVersionIsRefusedRatherThanTreatedAsAnAdoption(t *testing.T) {
	t.Parallel()
	svc, bindings, _ := newService(t, []importedfinding.ImportedFinding{observation("o1", "abc")},
		[]finding.Finding{{ID: "f1", EngagementID: "eng1"}, {ID: "f2", EngagementID: "eng1"}})
	if _, err := decide(t, svc, DecideRequest{ObservationID: "o1", FindingID: "f1"}); err != nil {
		t.Fatalf("adopt: %v", err)
	}

	// Falling through to Adopt would answer 200 with the binding already in force and drop the caller's
	// new reason, so a client that meant to change a decision is told it succeeded while nothing changed.
	_, err := decide(t, svc, DecideRequest{ObservationID: "o1", FindingID: "f2", ExpectedVersion: -5, Reason: "meant to rebind"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a negative expected version = %v, want a validation error", err)
	}
	current, err := svc.Current(context.Background(), "t1", "eng1")
	if err != nil {
		t.Fatalf("current: %v", err)
	}
	binding := current[observationbinding.Identity{Scope: "semgrep", ExternalIdentity: "fingerprint:abc"}]
	if binding.FindingID != "f1" || binding.Version != 1 {
		t.Fatalf("binding in force = %+v, want the original", binding)
	}
	all, err := bindings.ListByEngagement(context.Background(), "t1", "eng1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("%d versions, want the refused request to have written nothing", len(all))
	}
}

func TestARepeatedRequestIsAuditedAsARepeatRatherThanADecision(t *testing.T) {
	t.Parallel()
	svc, _, audit := newService(t, []importedfinding.ImportedFinding{observation("o1", "abc")},
		[]finding.Finding{{ID: "f1", EngagementID: "eng1"}})

	if _, err := decide(t, svc, DecideRequest{ObservationID: "o1", FindingID: "f1", Actor: "human:alice"}); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	// Bob re-posts the same decision. Adopt is idempotent, so his reason is dropped and nothing changes.
	// Recording that as a decision would credit him with one he did not make.
	if _, err := decide(t, svc, DecideRequest{ObservationID: "o1", FindingID: "f1", Actor: "human:bob", Reason: "agreeing"}); err != nil {
		t.Fatalf("repeat: %v", err)
	}
	if len(audit.entries) != 2 {
		t.Fatalf("%d audit entries, want both requests recorded", len(audit.entries))
	}
	if audit.entries[0].Action != "finding.observation.bound" {
		t.Fatalf("first entry = %q, want the decision", audit.entries[0].Action)
	}
	if audit.entries[1].Action != "finding.observation.bind.repeated" {
		t.Fatalf("second entry = %q, want it marked as a repeat", audit.entries[1].Action)
	}
}

func TestCurrentReadsOnlyTheBindingsInForce(t *testing.T) {
	t.Parallel()
	svc, _, _ := newService(t, []importedfinding.ImportedFinding{observation("o1", "abc")},
		[]finding.Finding{{ID: "f1", EngagementID: "eng1"}, {ID: "f2", EngagementID: "eng1"}})
	if _, err := decide(t, svc, DecideRequest{ObservationID: "o1", FindingID: "f1"}); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if _, err := decide(t, svc, DecideRequest{ObservationID: "o1", FindingID: "f2", ExpectedVersion: 1, Reason: "rebound"}); err != nil {
		t.Fatalf("supersede: %v", err)
	}

	// The page-load path reads only what is in force, so a superseded version must never reach it.
	current, err := svc.Current(context.Background(), "t1", "eng1")
	if err != nil {
		t.Fatalf("current: %v", err)
	}
	if len(current) != 1 {
		t.Fatalf("%d bindings in force, want 1", len(current))
	}
	for _, binding := range current {
		if !binding.Current() {
			t.Fatalf("a superseded version reached the page-load read: %+v", binding)
		}
	}
}
