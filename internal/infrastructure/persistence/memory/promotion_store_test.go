package memory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/promotion"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	analysis "github.com/KKloudTarus/synapse-ce/internal/usecase/analysis"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	promotionuc "github.com/KKloudTarus/synapse-ce/internal/usecase/promotion"
)

// mockEngagementReader is a test double for ports.EngagementOwnershipReader.
// It maps (tenantID, engagementID) -> bool and returns ErrNotFound for
// unknown pairs.
func mustPromotionStore(t *testing.T, findingRepo *FindingRepository, engagementReader ports.EngagementOwnershipReader) *PromotionStore {
	t.Helper()
	store, err := NewPromotionStore(findingRepo, engagementReader)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

type mockEngagementReader struct {
	// allowed maps "tenantID:engagementID" -> true.
	allowed map[string]bool
}

func newMockEngagementReader() *mockEngagementReader {
	return &mockEngagementReader{allowed: map[string]bool{}}
}

func (m *mockEngagementReader) allow(tenantID, engagementID shared.ID) {
	m.allowed[string(tenantID)+":"+string(engagementID)] = true
}

func (m *mockEngagementReader) GetByIDInTenant(_ context.Context, tenantID, id shared.ID) (*engagement.Engagement, error) {
	if m.allowed[string(tenantID)+":"+string(id)] {
		return &engagement.Engagement{ID: id, TenantID: tenantID}, nil
	}
	return nil, fmt.Errorf("engagement %s in tenant %s: %w", id, tenantID, shared.ErrNotFound)
}

var _ ports.EngagementOwnershipReader = (*mockEngagementReader)(nil)

// seedFinding inserts a finding with the given priority into the memory finding
// repo at version 1, then optionally bumps the version through the repository
// API to simulate prior concurrent edits. Returns the stored finding state.
func seedFinding(t *testing.T, repo *FindingRepository, engagementID, findingID shared.ID, priority, wantVersion int) finding.Finding {
	t.Helper()
	f := finding.Finding{
		ID:           findingID,
		EngagementID: engagementID,
		Title:        "test finding",
		Severity:     shared.SeverityHigh,
		Status:       finding.StatusConfirmed,
		Kind:         finding.KindSCA,
		Priority:     priority,
		// Version=0 so Upsert always sets it to 1 for a fresh insert.
		DedupKey: "test:" + findingID.String(),
		Audit:    shared.Audit{CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}
	if err := repo.Upsert(context.Background(), []finding.Finding{f}); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	// Bump to the desired version through a public, versioned repository update.
	for v := 1; v < wantVersion; v++ {
		if _, err := repo.SetEvidenceScore(context.Background(), engagementID, findingID, 0, v); err != nil {
			t.Fatalf("bump version from %d to %d: %v", v, v+1, err)
		}
	}
	out, err := repo.getFinding(engagementID, findingID)
	if err != nil {
		t.Fatalf("get seeded finding: %v", err)
	}
	return out
}

// sampleCmd builds a valid PromotionCommand for testing.
func sampleCmd(effect judgment.PromotionChange, before, after int) ports.PromotionCommand {
	return ports.PromotionCommand{
		EventID:        "evt-1",
		JudgmentID:     "j1",
		FindingVersion: 1,
		Rule:           judgment.RuleRuntimeReachableExposed,
		Effect:         effect,
		BeforePriority: before,
		AfterPriority:  after,
		Inputs: []judgment.PromotionInput{
			{Kind: judgment.PromotionInputReachability, ID: "j1"},
		},
		Fingerprint:      strings.Repeat("a", 64),
		VerdictScore:     75,
		VerdictRationale: "verified",
		EvidenceID:       "evidence-1",
		Verifier:         "human:verifier",
		AppliedBy:        "tester",
	}
}

// tenantCtx returns a context with the default test tenant.
func tenantCtx() context.Context {
	return shared.WithTenant(context.Background(), "test-tenant")
}

// defaultReader returns a mockEngagementReader that allows common test
// engagement-tenant pairs.
func defaultReader() *mockEngagementReader {
	r := newMockEngagementReader()
	r.allow("test-tenant", "eng-1")
	r.allow("test-tenant", "eng-2")
	r.allow("tenant-a", "eng-a")
	r.allow("tenant-b", "eng-b")
	return r
}

func TestPromotionStoreTypedKeysResistColonCollisions(t *testing.T) {
	fingerprint := strings.Repeat("a", 64)
	judgmentA, judgmentB := judgmentKey("tenant:a", "judgment"), judgmentKey("tenant", "a:judgment")
	fingerA, fingerB := fingerprintKey("tenant:a", fingerprint), fingerprintKey("tenant", "a:"+fingerprint)
	findingA, findingB := storeFindingKey("tenant:a", "engagement", "finding"), storeFindingKey("tenant", "a:engagement", "finding")
	eventA, eventB := eventIDKey("tenant:a", "event"), eventIDKey("tenant", "a:event")

	if judgmentA == judgmentB || fingerA == fingerB || findingA == findingB || eventA == eventB {
		t.Fatal("typed promotion-store keys must retain colon-containing field boundaries")
	}
	pending := map[eventStoreKey]bool{eventA: true, eventB: true}
	if len(pending) != 2 {
		t.Fatalf("pending audit keys collided: %#v", pending)
	}
}

func TestPromotionStoreApplyEscalation(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	f := seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)
	cmd := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd.ExpectedPriority = 3
	cmd.ExpectedVersion = f.Version

	got, err := store.Apply(ctx, "eng-1", "f1", cmd)
	if err != nil {
		t.Fatalf("Apply escalation: %v", err)
	}
	if got.Priority != 2 {
		t.Errorf("priority = %d, want 2", got.Priority)
	}
	if got.Version != 2 {
		t.Errorf("version = %d, want 2 (bumped)", got.Version)
	}
	// Event persisted.
	events, _ := store.ListByFinding(ctx, "eng-1", "f1")
	if len(events) != 1 || events[0].Effect != judgment.PromotionEscalate {
		t.Fatalf("events: %+v", events)
	}
	if events[0].JudgmentID != "j1" {
		t.Errorf("event JudgmentID = %s, want j1", events[0].JudgmentID)
	}
	if events[0].VerdictScore != 75 {
		t.Errorf("event VerdictScore = %d, want 75", events[0].VerdictScore)
	}
}

func TestPromotionStoreApplyDeescalation(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	f := seedFinding(t, findingRepo, "eng-1", "f1", 2, 1)
	cmd := sampleCmd(judgment.PromotionDeescalate, 2, 3)
	cmd.Rule = judgment.RuleDeterministicUnreachable
	cmd.ExpectedPriority = 2
	cmd.ExpectedVersion = f.Version

	got, err := store.Apply(ctx, "eng-1", "f1", cmd)
	if err != nil {
		t.Fatalf("Apply de-escalation: %v", err)
	}
	if got.Priority != 3 {
		t.Errorf("priority = %d, want 3", got.Priority)
	}
	if got.Version != 2 {
		t.Errorf("version = %d, want 2 (bumped)", got.Version)
	}
}

func TestPromotionStoreApplyExactReversal(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	// First, seed a finding at P4, version 1 and escalate it to P3.
	f := seedFinding(t, findingRepo, "eng-1", "f1", 4, 1)
	escCmd := sampleCmd(judgment.PromotionEscalate, 4, 3)
	escCmd.ExpectedPriority = 4
	escCmd.ExpectedVersion = f.Version
	escCmd.EventID = "prior-evt"
	if _, err := store.Apply(ctx, "eng-1", "f1", escCmd); err != nil {
		t.Fatalf("setup escalation: %v", err)
	}

	// Now apply exact reversal: corroborating_signal_loss references
	// "prior-evt" and restores P4 (the prior event's BeforePriority).
	revCmd := sampleCmd(judgment.PromotionDeescalate, 3, 4)
	revCmd.Rule = judgment.RuleCorroboratingSignalLoss
	revCmd.Inputs = []judgment.PromotionInput{
		{Kind: judgment.PromotionInputPrior, ID: "prior-evt"},
		{Kind: judgment.PromotionInputReachability, ID: "j1"},
	}
	revCmd.JudgmentID = "j-rev"
	revCmd.Fingerprint = strings.Repeat("d", 64)
	revCmd.EventID = "evt-rev"
	revCmd.FindingVersion = 2
	revCmd.ExpectedPriority = 3
	revCmd.ExpectedVersion = 2

	got, err := store.Apply(ctx, "eng-1", "f1", revCmd)
	if err != nil {
		t.Fatalf("Apply exact reversal: %v", err)
	}
	if got.Priority != 4 {
		t.Errorf("priority = %d, want 4 (exact reversal)", got.Priority)
	}
	if got.Version != 3 {
		t.Errorf("version = %d, want 3 (bumped)", got.Version)
	}
}

func TestPromotionStoreStackedReversalsAreLIFO(t *testing.T) {
	findingRepo := NewFindingRepository()
	store := mustPromotionStore(t, findingRepo, defaultReader())
	ctx := tenantCtx()
	f := seedFinding(t, findingRepo, "eng-1", "f1", 4, 1)
	apply := func(cmd ports.PromotionCommand) {
		t.Helper()
		if _, err := store.Apply(ctx, "eng-1", "f1", cmd); err != nil {
			t.Fatal(err)
		}
	}
	a := sampleCmd(judgment.PromotionEscalate, 4, 3)
	a.EventID, a.JudgmentID, a.ExpectedPriority, a.ExpectedVersion = "event-a", "judgment-a", f.Priority, f.Version
	apply(a)
	b := sampleCmd(judgment.PromotionEscalate, 3, 2)
	b.EventID, b.JudgmentID, b.Fingerprint, b.FindingVersion, b.ExpectedPriority, b.ExpectedVersion = "event-b", "judgment-b", strings.Repeat("b", 64), 2, 3, 2
	apply(b)
	reverse := func(eventID, judgmentID, fingerprint string, before, after, version int) ports.PromotionCommand {
		cmd := sampleCmd(judgment.PromotionDeescalate, before, after)
		cmd.EventID, cmd.JudgmentID, cmd.Fingerprint = shared.ID(eventID+"-reverse"), shared.ID(judgmentID), fingerprint
		cmd.Rule = judgment.RuleCorroboratingSignalLoss
		cmd.Inputs = []judgment.PromotionInput{{Kind: judgment.PromotionInputPrior, ID: shared.ID(eventID)}, {Kind: judgment.PromotionInputReachability, ID: "j1"}}
		cmd.FindingVersion, cmd.ExpectedPriority, cmd.ExpectedVersion = version, before, version
		return cmd
	}
	apply(reverse("event-b", "judgment-b-reverse", strings.Repeat("c", 64), 2, 3, 3))
	got, err := findingRepo.GetByEngagementAndID(ctx, "eng-1", "f1")
	if err != nil || got.Priority != 3 {
		t.Fatalf("first LIFO reversal finding = %#v, %v", got, err)
	}
	apply(reverse("event-a", "judgment-a-reverse", strings.Repeat("d", 64), 3, 4, 4))
	got, err = findingRepo.GetByEngagementAndID(ctx, "eng-1", "f1")
	if err != nil || got.Priority != 4 {
		t.Fatalf("second LIFO reversal finding = %#v, %v", got, err)
	}
	if _, err := store.Apply(ctx, "eng-1", "f1", reverse("event-a", "judgment-a-reverse", strings.Repeat("d", 64), 3, 4, 4)); err != nil {
		t.Fatalf("unchanged reverse replay: %v", err)
	}
	events, err := store.ListByFinding(ctx, "eng-1", "f1")
	if err != nil || len(events) != 4 {
		t.Fatalf("events after unchanged reevaluation = %#v, %v", events, err)
	}
}

func TestPromotionStoreApplyFlagForReview(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	f := seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)
	cmd := sampleCmd(judgment.PromotionFlagForReview, 3, 3)
	cmd.Rule = judgment.RuleUncertainCorroboration
	cmd.ExpectedPriority = 3
	cmd.ExpectedVersion = f.Version

	got, err := store.Apply(ctx, "eng-1", "f1", cmd)
	if err != nil {
		t.Fatalf("Apply review: %v", err)
	}
	// Review must NOT mutate the finding.
	if got.Priority != 3 {
		t.Errorf("priority = %d, want 3 (unchanged)", got.Priority)
	}
	if got.Version != 1 {
		t.Errorf("version = %d, want 1 (no bump for review)", got.Version)
	}
	// Event persisted.
	events, _ := store.ListByFinding(ctx, "eng-1", "f1")
	if len(events) != 1 || events[0].Effect != judgment.PromotionFlagForReview {
		t.Fatalf("events: %+v", events)
	}
}

func TestPromotionStoreApplyCASVersionMismatch(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)
	// Bump the finding version externally through the repository API.
	if _, err := findingRepo.SetEvidenceScore(context.Background(), "eng-1", "f1", 0, 1); err != nil {
		t.Fatalf("bump finding version: %v", err)
	}

	cmd := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd.ExpectedPriority = 3
	cmd.ExpectedVersion = 1 // stale

	_, err := store.Apply(ctx, "eng-1", "f1", cmd)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	// No event should be persisted on CAS failure.
	events, _ := store.ListByFinding(ctx, "eng-1", "f1")
	if len(events) != 0 {
		t.Fatalf("events on CAS failure: %+v", events)
	}
}

func TestPromotionStoreApplyCASPriorityMismatchReview(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	seedFinding(t, findingRepo, "eng-1", "f1", 2, 1)

	cmd := sampleCmd(judgment.PromotionFlagForReview, 3, 3)
	cmd.Rule = judgment.RuleUncertainCorroboration
	cmd.ExpectedPriority = 3 // stale -- finding is P2
	cmd.ExpectedVersion = 1

	_, err := store.Apply(ctx, "eng-1", "f1", cmd)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	// No event should be persisted on priority mismatch.
	events, _ := store.ListByFinding(ctx, "eng-1", "f1")
	if len(events) != 0 {
		t.Fatalf("events on priority mismatch: %+v", events)
	}
}

func TestPromotionStoreApplyCASPriorityMismatchEscalation(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	seedFinding(t, findingRepo, "eng-1", "f1", 2, 1)

	cmd := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd.ExpectedPriority = 3 // stale -- finding is P2
	cmd.ExpectedVersion = 1

	_, err := store.Apply(ctx, "eng-1", "f1", cmd)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	// No event should be persisted on priority mismatch.
	events, _ := store.ListByFinding(ctx, "eng-1", "f1")
	if len(events) != 0 {
		t.Fatalf("events on priority mismatch: %+v", events)
	}
}

func TestPromotionStoreApplyJudgmentIdempotent(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	f := seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)
	cmd := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd.ExpectedPriority = 3
	cmd.ExpectedVersion = f.Version

	// First apply succeeds and moves priority.
	_, err := store.Apply(ctx, "eng-1", "f1", cmd)
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}

	// Second apply with same judgmentID is idempotent (no error, no
	// duplicate event, no double mutation).
	got, err := store.Apply(ctx, "eng-1", "f1", cmd)
	if err != nil {
		t.Fatalf("idempotent re-apply: %v", err)
	}
	if got.Priority != 2 {
		t.Errorf("priority after idempotent re-apply = %d, want 2", got.Priority)
	}
	// Only one event.
	events, _ := store.ListByFinding(ctx, "eng-1", "f1")
	if len(events) != 1 {
		t.Fatalf("events after idempotent re-apply: %d, want 1", len(events))
	}
}

func TestPromotionStoreApplyJudgmentFingerprintConflict(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	f := seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)
	cmd := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd.ExpectedPriority = 3
	cmd.ExpectedVersion = f.Version

	// First apply succeeds.
	_, err := store.Apply(ctx, "eng-1", "f1", cmd)
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}

	// Same fingerprint but different judgmentID is a semantic conflict.
	cmd2 := cmd
	cmd2.JudgmentID = "j2"
	_, err = store.Apply(ctx, "eng-1", "f1", cmd2)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("want ErrConflict for fingerprint conflict, got %v", err)
	}
}

func TestPromotionStoreApplyFindingNotFound(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	cmd := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd.ExpectedPriority = 3
	cmd.ExpectedVersion = 1

	_, err := store.Apply(ctx, "eng-1", "nonexistent", cmd)
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestPromotionStoreApplyMissingTenantContext(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := context.Background() // no tenant

	cmd := sampleCmd(judgment.PromotionEscalate, 3, 2)

	_, err := store.Apply(ctx, "eng-1", "f1", cmd)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for missing tenant, got %v", err)
	}
}

func TestPromotionStoreApplyCrossTenantEngagementRejection(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)

	// Engage under tenant-a but the engagement belongs to tenant-b.
	ctxA := shared.WithTenant(context.Background(), "tenant-a")
	seedFinding(t, findingRepo, "eng-a", "f1", 3, 1)

	cmd := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd.ExpectedPriority = 3
	cmd.ExpectedVersion = 1

	// Try to apply with tenant-a's context against eng-b (owned by tenant-b).
	_, err := store.Apply(ctxA, "eng-b", "f1", cmd)
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound for cross-tenant engagement, got %v", err)
	}
}

func TestPromotionStoreApplyCASBindingVersionMismatch(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	f := seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)
	cmd := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd.ExpectedPriority = 3
	cmd.ExpectedVersion = f.Version
	cmd.FindingVersion = 5 // does not match ExpectedVersion

	_, err := store.Apply(ctx, "eng-1", "f1", cmd)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for FindingVersion != ExpectedVersion, got %v", err)
	}
}

func TestPromotionStoreApplyCASBindingPriorityMismatch(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	f := seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)
	cmd := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd.ExpectedPriority = 3
	cmd.ExpectedVersion = f.Version
	cmd.BeforePriority = 2 // does not match ExpectedPriority

	_, err := store.Apply(ctx, "eng-1", "f1", cmd)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for BeforePriority != ExpectedPriority, got %v", err)
	}
}

func TestPromotionStoreReversalMissingPriorInput(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	f := seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)
	cmd := sampleCmd(judgment.PromotionDeescalate, 3, 4)
	cmd.Rule = judgment.RuleCorroboratingSignalLoss
	cmd.Inputs = []judgment.PromotionInput{
		{Kind: judgment.PromotionInputReachability, ID: "j1"},
		// No prior_promotion input.
	}
	cmd.ExpectedPriority = 3
	cmd.ExpectedVersion = f.Version

	_, err := store.Apply(ctx, "eng-1", "f1", cmd)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for missing prior input, got %v", err)
	}
}

func TestPromotionStoreReversalMissingPriorEvent(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	f := seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)
	cmd := sampleCmd(judgment.PromotionDeescalate, 3, 4)
	cmd.Rule = judgment.RuleCorroboratingSignalLoss
	cmd.Inputs = []judgment.PromotionInput{
		{Kind: judgment.PromotionInputReachability, ID: "j1"},
		{Kind: judgment.PromotionInputPrior, ID: "nonexistent-prior"},
	}
	cmd.ExpectedPriority = 3
	cmd.ExpectedVersion = f.Version

	_, err := store.Apply(ctx, "eng-1", "f1", cmd)
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound for missing prior event, got %v", err)
	}
}

func TestPromotionStoreReversalWrongFinding(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	// Seed two findings in the same engagement.
	seedFinding(t, findingRepo, "eng-1", "f1", 4, 1)
	f2 := seedFinding(t, findingRepo, "eng-1", "f2", 3, 1)

	// Escalate f1 from P4 to P3 (creates prior event).
	escCmd := sampleCmd(judgment.PromotionEscalate, 4, 3)
	escCmd.ExpectedPriority = 4
	escCmd.ExpectedVersion = 1
	escCmd.EventID = "prior-evt-f1"
	if _, err := store.Apply(ctx, "eng-1", "f1", escCmd); err != nil {
		t.Fatalf("setup escalation: %v", err)
	}

	// Try to use prior-evt-f1 (on f1) to reverse f2: wrong finding.
	revCmd := sampleCmd(judgment.PromotionDeescalate, 3, 4)
	revCmd.Rule = judgment.RuleCorroboratingSignalLoss
	revCmd.Inputs = []judgment.PromotionInput{
		{Kind: judgment.PromotionInputReachability, ID: "j1"},
		{Kind: judgment.PromotionInputPrior, ID: "prior-evt-f1"},
	}
	revCmd.JudgmentID = "j-rev"
	revCmd.Fingerprint = strings.Repeat("d", 64)
	revCmd.ExpectedPriority = 3
	revCmd.ExpectedVersion = f2.Version

	_, err := store.Apply(ctx, "eng-1", "f2", revCmd)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("want ErrConflict for wrong finding, got %v", err)
	}
}

func TestPromotionStoreReversalNonEscalation(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	// Seed a finding and apply a flag_for_review (not an escalation).
	f := seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)
	reviewCmd := sampleCmd(judgment.PromotionFlagForReview, 3, 3)
	reviewCmd.Rule = judgment.RuleUncertainCorroboration
	reviewCmd.ExpectedPriority = 3
	reviewCmd.ExpectedVersion = f.Version
	reviewCmd.EventID = "review-evt"
	if _, err := store.Apply(ctx, "eng-1", "f1", reviewCmd); err != nil {
		t.Fatalf("setup review: %v", err)
	}

	// Try to use review-evt as prior for reversal: not an escalation.
	revCmd := sampleCmd(judgment.PromotionDeescalate, 3, 3)
	revCmd.Rule = judgment.RuleCorroboratingSignalLoss
	revCmd.Inputs = []judgment.PromotionInput{
		{Kind: judgment.PromotionInputReachability, ID: "j1"},
		{Kind: judgment.PromotionInputPrior, ID: "review-evt"},
	}
	revCmd.JudgmentID = "j-rev"
	revCmd.Fingerprint = strings.Repeat("d", 64)
	revCmd.ExpectedPriority = 3
	revCmd.ExpectedVersion = 1

	_, err := store.Apply(ctx, "eng-1", "f1", revCmd)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("want ErrConflict for non-escalation prior, got %v", err)
	}
}

func TestPromotionStoreReversalIncorrectTarget(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	// Escalate from P4 to P3 (prior event: BeforePriority=4).
	f := seedFinding(t, findingRepo, "eng-1", "f1", 4, 1)
	escCmd := sampleCmd(judgment.PromotionEscalate, 4, 3)
	escCmd.ExpectedPriority = 4
	escCmd.ExpectedVersion = f.Version
	escCmd.EventID = "prior-evt"
	if _, err := store.Apply(ctx, "eng-1", "f1", escCmd); err != nil {
		t.Fatalf("setup escalation: %v", err)
	}

	// Try to reverse to P5 (wrong target: prior BeforePriority was P4).
	revCmd := sampleCmd(judgment.PromotionDeescalate, 3, 5)
	revCmd.Rule = judgment.RuleCorroboratingSignalLoss
	revCmd.Inputs = []judgment.PromotionInput{
		{Kind: judgment.PromotionInputPrior, ID: "prior-evt"},
		{Kind: judgment.PromotionInputReachability, ID: "j1"},
	}
	revCmd.JudgmentID = "j-rev"
	revCmd.Fingerprint = strings.Repeat("d", 64)
	revCmd.FindingVersion = 2
	revCmd.ExpectedPriority = 3
	revCmd.ExpectedVersion = 2

	_, err := store.Apply(ctx, "eng-1", "f1", revCmd)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("want ErrConflict for incorrect target priority, got %v", err)
	}
}

func TestPromotionStoreReversalWrongTenant(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)

	tenantA := shared.WithTenant(context.Background(), "tenant-a")
	tenantB := shared.WithTenant(context.Background(), "tenant-b")

	// Escalate under tenant-a.
	seedFinding(t, findingRepo, "eng-a", "f1", 4, 1)
	escCmd := sampleCmd(judgment.PromotionEscalate, 4, 3)
	escCmd.ExpectedPriority = 4
	escCmd.ExpectedVersion = 1
	escCmd.EventID = "prior-evt-a"
	if _, err := store.Apply(tenantA, "eng-a", "f1", escCmd); err != nil {
		t.Fatalf("setup escalation: %v", err)
	}

	// Try to reference tenant-a's prior event under tenant-b context.
	seedFinding(t, findingRepo, "eng-b", "f1", 3, 1)
	revCmd := sampleCmd(judgment.PromotionDeescalate, 3, 4)
	revCmd.Rule = judgment.RuleCorroboratingSignalLoss
	revCmd.Inputs = []judgment.PromotionInput{
		{Kind: judgment.PromotionInputReachability, ID: "j1"},
		{Kind: judgment.PromotionInputPrior, ID: "prior-evt-a"},
	}
	revCmd.JudgmentID = "j-rev"
	revCmd.Fingerprint = strings.Repeat("d", 64)
	revCmd.ExpectedPriority = 3
	revCmd.ExpectedVersion = 1

	_, err := store.Apply(tenantB, "eng-b", "f1", revCmd)
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound for cross-tenant prior event, got %v", err)
	}
}

func TestPromotionStoreHostileFalseHistory(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	// Hostile test: caller tries to forge a FindingVersion that doesn't match
	// ExpectedVersion to trick the store into accepting stale data.
	f := seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)

	// Attempt 1: FindingVersion claims v5 but finding is at v1.
	cmd := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd.ExpectedPriority = 3
	cmd.ExpectedVersion = f.Version
	cmd.FindingVersion = 5 // forged
	_, err := store.Apply(ctx, "eng-1", "f1", cmd)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("hostile version: want ErrValidation, got %v", err)
	}

	// Attempt 2: BeforePriority claims P1 but finding is at P3.
	cmd2 := sampleCmd(judgment.PromotionEscalate, 1, 2)
	cmd2.ExpectedPriority = 3
	cmd2.ExpectedVersion = f.Version
	cmd2.FindingVersion = f.Version
	cmd2.BeforePriority = 1 // forged
	_, err = store.Apply(ctx, "eng-1", "f1", cmd2)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("hostile priority: want ErrValidation, got %v", err)
	}

	// Verify no events were persisted.
	events, _ := store.ListByFinding(ctx, "eng-1", "f1")
	if len(events) != 0 {
		t.Fatalf("hostile test: %d events persisted (should be 0)", len(events))
	}
}

func TestPromotionStoreLatestByFinding(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	// No events yet.
	_, ok, err := store.LatestByFinding(ctx, "eng-1", "f1")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected no latest event for unknown finding")
	}

	// Seed and apply two events.
	f := seedFinding(t, findingRepo, "eng-1", "f1", 4, 1)
	cmd1 := sampleCmd(judgment.PromotionEscalate, 4, 3)
	cmd1.ExpectedPriority = 4
	cmd1.ExpectedVersion = f.Version
	if _, err := store.Apply(ctx, "eng-1", "f1", cmd1); err != nil {
		t.Fatal(err)
	}
	cmd2 := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd2.EventID = "evt-2"
	cmd2.JudgmentID = "j2"
	cmd2.Fingerprint = strings.Repeat("b", 64)
	cmd2.FindingVersion = 2
	cmd2.ExpectedPriority = 3
	cmd2.ExpectedVersion = 2
	if _, err := store.Apply(ctx, "eng-1", "f1", cmd2); err != nil {
		t.Fatal(err)
	}

	latest, ok, err := store.LatestByFinding(ctx, "eng-1", "f1")
	if err != nil || !ok {
		t.Fatalf("LatestByFinding: ok=%v err=%v", ok, err)
	}
	if latest.ID != "evt-2" {
		t.Errorf("latest ID = %s, want evt-2", latest.ID)
	}
	if latest.AfterPriority != 2 {
		t.Errorf("latest AfterPriority = %d, want 2", latest.AfterPriority)
	}
}

func TestPromotionStoreListByFinding(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	// Empty list for unknown finding.
	events, err := store.ListByFinding(ctx, "eng-1", "f1")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("expected empty, got %d events", len(events))
	}

	// Apply two events.
	f := seedFinding(t, findingRepo, "eng-1", "f1", 4, 1)
	cmd1 := sampleCmd(judgment.PromotionEscalate, 4, 3)
	cmd1.ExpectedPriority = 4
	cmd1.ExpectedVersion = f.Version
	if _, err := store.Apply(ctx, "eng-1", "f1", cmd1); err != nil {
		t.Fatal(err)
	}
	cmd2 := sampleCmd(judgment.PromotionFlagForReview, 3, 3)
	cmd2.EventID = "evt-2"
	cmd2.JudgmentID = "j2"
	cmd2.Fingerprint = strings.Repeat("b", 64)
	cmd2.Rule = judgment.RuleUncertainCorroboration
	cmd2.FindingVersion = 2
	cmd2.ExpectedPriority = 3
	cmd2.ExpectedVersion = 2
	if _, err := store.Apply(ctx, "eng-1", "f1", cmd2); err != nil {
		t.Fatal(err)
	}

	events, _ = store.ListByFinding(ctx, "eng-1", "f1")
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].ID != "evt-1" || events[1].ID != "evt-2" {
		t.Errorf("events not in order: %s, %s", events[0].ID, events[1].ID)
	}
}

func TestPromotionStoreImmutableLifecycle(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	f := seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)
	cmd := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd.ExpectedPriority = 3
	cmd.ExpectedVersion = f.Version

	if _, err := store.Apply(ctx, "eng-1", "f1", cmd); err != nil {
		t.Fatal(err)
	}

	// The stored event should be identical to what we put in (immutable).
	events, _ := store.ListByFinding(ctx, "eng-1", "f1")
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	stored := events[0]
	if stored.Effect != judgment.PromotionEscalate {
		t.Errorf("Effect = %s, want escalate", stored.Effect)
	}
	if stored.BeforePriority != 3 || stored.AfterPriority != 2 {
		t.Errorf("priority: before=%d after=%d, want 3->2", stored.BeforePriority, stored.AfterPriority)
	}
	if stored.JudgmentID != "j1" {
		t.Errorf("JudgmentID = %s, want j1", stored.JudgmentID)
	}
	if stored.AfterFindingVersion != 2 {
		t.Errorf("AfterFindingVersion = %d, want 2", stored.AfterFindingVersion)
	}
}

func TestPromotionStoreVersionBump(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	// Apply two escalations in sequence. Each should bump the version.
	f := seedFinding(t, findingRepo, "eng-1", "f1", 4, 1)

	cmd1 := sampleCmd(judgment.PromotionEscalate, 4, 3)
	cmd1.ExpectedPriority = 4
	cmd1.ExpectedVersion = f.Version
	got1, err := store.Apply(ctx, "eng-1", "f1", cmd1)
	if err != nil {
		t.Fatal(err)
	}
	if got1.Version != 2 {
		t.Errorf("version after first escalation = %d, want 2", got1.Version)
	}

	cmd2 := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd2.EventID = "evt-2"
	cmd2.JudgmentID = "j2"
	cmd2.Fingerprint = strings.Repeat("b", 64)
	cmd2.FindingVersion = got1.Version
	cmd2.ExpectedPriority = 3
	cmd2.ExpectedVersion = got1.Version
	got2, err := store.Apply(ctx, "eng-1", "f1", cmd2)
	if err != nil {
		t.Fatal(err)
	}
	if got2.Version != 3 {
		t.Errorf("version after second escalation = %d, want 3", got2.Version)
	}
	if got2.Priority != 2 {
		t.Errorf("priority after second escalation = %d, want 2", got2.Priority)
	}
}

func TestPromotionStoreReviewDoesNotBumpVersion(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	f := seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)

	// Apply three review flags in sequence. Version must never change.
	for i := 0; i < 3; i++ {
		cmd := sampleCmd(judgment.PromotionFlagForReview, 3, 3)
		cmd.EventID = shared.ID("evt-" + string(rune('a'+i)))
		cmd.JudgmentID = shared.ID("judg-" + string(rune('a'+i)))
		cmd.Fingerprint = strings.Repeat(string(rune('a'+i)), 64)
		cmd.Rule = judgment.RuleUncertainCorroboration
		cmd.ExpectedPriority = 3
		cmd.ExpectedVersion = 1
		got, err := store.Apply(ctx, "eng-1", "f1", cmd)
		if err != nil {
			t.Fatalf("review %d: %v", i, err)
		}
		if got.Version != 1 {
			t.Errorf("review %d: version = %d, want 1 (no bump)", i, got.Version)
		}
		if got.Priority != 3 {
			t.Errorf("review %d: priority = %d, want 3 (no change)", i, got.Priority)
		}
	}
	_ = f
}

func TestPromotionEventValidation(t *testing.T) {
	now := time.Now()
	valid := func() promotion.PromotionEvent {
		evt, _ := promotion.NewPromotionEvent(
			"evt-1", "eng-1", "j1", "f1", 1, 2,
			judgment.RuleRuntimeReachableExposed,
			judgment.PromotionEscalate, 3, 2,
			[]judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "j1"}},
			strings.Repeat("a", 64),
			75, "rationale", "ev-1", "verifier",
			nil, "tester", now,
		)
		return evt
	}

	// Valid construction.
	evt := valid()
	if evt.ID != "evt-1" {
		t.Errorf("ID = %s, want evt-1", evt.ID)
	}
	if evt.JudgmentID != "j1" {
		t.Errorf("JudgmentID = %s, want j1", evt.JudgmentID)
	}

	cases := []struct {
		name   string
		mutate func(*promotion.PromotionEvent)
	}{
		{"zero id", func(e *promotion.PromotionEvent) { e.ID = "" }},
		{"zero engagement", func(e *promotion.PromotionEvent) { e.EngagementID = "" }},
		{"zero judgment", func(e *promotion.PromotionEvent) { e.JudgmentID = "" }},
		{"zero finding", func(e *promotion.PromotionEvent) { e.FindingID = "" }},
		{"zero version", func(e *promotion.PromotionEvent) { e.FindingVersion = 0 }},
		{"invalid effect", func(e *promotion.PromotionEvent) { e.Effect = "bogus" }},
		{"before priority zero", func(e *promotion.PromotionEvent) { e.BeforePriority = 0 }},
		{"after priority too high", func(e *promotion.PromotionEvent) { e.AfterPriority = 6 }},
		{"no inputs", func(e *promotion.PromotionEvent) { e.Inputs = nil }},
		{"no fingerprint", func(e *promotion.PromotionEvent) { e.Fingerprint = "" }},
		{"escalation wrong delta", func(e *promotion.PromotionEvent) { e.AfterPriority = 1 }}, // 3->1 is two levels
		{"de-escalation toward P1", func(e *promotion.PromotionEvent) {
			e.Effect = judgment.PromotionDeescalate
			e.BeforePriority = 3
			e.AfterPriority = 2
		}},
		{"review changes priority", func(e *promotion.PromotionEvent) {
			e.Effect = judgment.PromotionFlagForReview
			e.BeforePriority = 3
			e.AfterPriority = 4
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := valid()
			tc.mutate(&e)
			_, err := promotion.NewPromotionEvent(
				e.ID, e.EngagementID, e.JudgmentID, e.FindingID,
				e.FindingVersion, e.AfterFindingVersion,
				e.Rule, e.Effect, e.BeforePriority, e.AfterPriority,
				e.Inputs, e.Fingerprint,
				e.VerdictScore, e.VerdictRationale, e.EvidenceID, e.Verifier,
				nil, e.AppliedBy, e.AppliedAt,
			)
			if !errors.Is(err, shared.ErrValidation) {
				t.Errorf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestPromotionEventRejectsMissingAppliedProvenance(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name       string
		score      int
		rationale  string
		evidenceID shared.ID
		verifier   string
		appliedBy  string
	}{
		{"score below threshold", 74, "verified", "ev-1", "human:verifier", "system:promotion"},
		{"score over maximum", 101, "verified", "ev-1", "human:verifier", "system:promotion"},
		{"missing rationale", 75, "", "ev-1", "human:verifier", "system:promotion"},
		{"missing evidence", 75, "verified", "", "human:verifier", "system:promotion"},
		{"missing verifier", 75, "verified", "ev-1", "", "system:promotion"},
		{"missing actor", 75, "verified", "ev-1", "human:verifier", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := promotion.NewPromotionEvent(
				"evt-1", "eng-1", "j1", "f1", 1, 2,
				judgment.RuleRuntimeReachableExposed, judgment.PromotionEscalate, 3, 2,
				[]judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "j1"}},
				strings.Repeat("a", 64), tc.score, tc.rationale, tc.evidenceID, tc.verifier, nil, tc.appliedBy, now,
			)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("NewPromotionEvent error = %v, want ErrValidation", err)
			}
		})
	}
}

func TestPromotionStoreDefensiveCopies(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	f := seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)
	inputs := []judgment.PromotionInput{
		{Kind: judgment.PromotionInputReachability, ID: "j1"},
	}
	cmd := ports.PromotionCommand{
		ExpectedPriority: 3,
		ExpectedVersion:  f.Version,
		EventID:          "evt-1",
		JudgmentID:       "j1",
		FindingVersion:   1,
		Rule:             judgment.RuleRuntimeReachableExposed,
		Effect:           judgment.PromotionEscalate,
		BeforePriority:   3,
		AfterPriority:    2,
		Inputs:           inputs,
		Fingerprint:      strings.Repeat("a", 64),
		VerdictScore:     75,
		VerdictRationale: "verified",
		EvidenceID:       "evidence-1",
		Verifier:         "human:verifier",
		AppliedBy:        "tester",
	}

	_, err := store.Apply(ctx, "eng-1", "f1", cmd)
	if err != nil {
		t.Fatal(err)
	}

	// Mutate the caller's inputs after Apply returns.
	inputs[0].ID = "mutated"

	// The stored event must be unaffected.
	events, _ := store.ListByFinding(ctx, "eng-1", "f1")
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Inputs[0].ID == "mutated" {
		t.Error("stored event's Inputs were mutated by the caller (defensive copy failed)")
	}

	// Mutating the returned list must not affect the store.
	events[0].ID = "mutated-evt"
	events2, _ := store.ListByFinding(ctx, "eng-1", "f1")
	if events2[0].ID == "mutated-evt" {
		t.Error("ListByFinding returned a mutable reference to the store's internal data")
	}
}

func TestPromotionEventAfterFindingVersionValidation(t *testing.T) {
	now := time.Now()
	base := func() promotion.PromotionEvent {
		evt, _ := promotion.NewPromotionEvent(
			"evt-1", "eng-1", "j1", "f1", 1, 2,
			judgment.RuleRuntimeReachableExposed,
			judgment.PromotionEscalate, 3, 2,
			[]judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "j1"}},
			strings.Repeat("a", 64),
			75, "verified", "ev-1", "human:verifier",
			nil, "tester", now,
		)
		return evt
	}
	_ = base

	// Escalation: afterVersion must be findingVersion+1.
	t.Run("escalation version must be +1", func(t *testing.T) {
		_, err := promotion.NewPromotionEvent(
			"evt-1", "eng-1", "j1", "f1", 1, 3, // should be 2
			judgment.RuleRuntimeReachableExposed,
			judgment.PromotionEscalate, 3, 2,
			[]judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "j1"}},
			strings.Repeat("a", 64), 75, "", "", "", nil, "tester", now,
		)
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("want ErrValidation, got %v", err)
		}
	})

	// Review: afterVersion must equal findingVersion.
	t.Run("review version must equal findingVersion", func(t *testing.T) {
		_, err := promotion.NewPromotionEvent(
			"evt-1", "eng-1", "j1", "f1", 1, 2, // should be 1
			judgment.RuleUncertainCorroboration,
			judgment.PromotionFlagForReview, 3, 3,
			[]judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "j1"}},
			strings.Repeat("b", 64), 0, "", "", "", nil, "tester", now,
		)
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("want ErrValidation, got %v", err)
		}
	})
}

func TestPromotionEventRuleEffectCoherence(t *testing.T) {
	now := time.Now()

	// Rule produces de_escalate, but effect is escalate.
	_, err := promotion.NewPromotionEvent(
		"evt-1", "eng-1", "j1", "f1", 1, 2,
		judgment.RuleDeterministicUnreachable,
		judgment.PromotionEscalate, 3, 2,
		[]judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "j1"}},
		strings.Repeat("a", 64), 0, "", "", "", nil, "tester", now,
	)
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("rule/effect mismatch: want ErrValidation, got %v", err)
	}

	// Unknown rule key.
	_, err = promotion.NewPromotionEvent(
		"evt-1", "eng-1", "j1", "f1", 1, 2,
		"promotion.unknown.rule",
		judgment.PromotionEscalate, 3, 2,
		[]judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "j1"}},
		strings.Repeat("a", 64), 0, "", "", "", nil, "tester", now,
	)
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("unknown rule: want ErrValidation, got %v", err)
	}
}

func TestPromotionStoreCrossTenantIsolation(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)

	tenantA := shared.WithTenant(context.Background(), "tenant-a")
	tenantB := shared.WithTenant(context.Background(), "tenant-b")

	// Seed separate findings per tenant (different engagements).
	seedFinding(t, findingRepo, "eng-a", "f1", 3, 1)
	seedFinding(t, findingRepo, "eng-b", "f1", 3, 1)

	// Apply under tenant A.
	cmd := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd.ExpectedPriority = 3
	cmd.ExpectedVersion = 1
	_, err := store.Apply(tenantA, "eng-a", "f1", cmd)
	if err != nil {
		t.Fatalf("apply under tenant A: %v", err)
	}

	// Tenant B must not see tenant A's events.
	events, err := store.ListByFinding(tenantB, "eng-b", "f1")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Errorf("tenant B saw %d events from tenant A", len(events))
	}

	// Tenant B should be able to apply its own event.
	cmd2 := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd2.JudgmentID = "j2"
	cmd2.Fingerprint = strings.Repeat("b", 64)
	cmd2.ExpectedPriority = 3
	cmd2.ExpectedVersion = 1
	_, err = store.Apply(tenantB, "eng-b", "f1", cmd2)
	if err != nil {
		t.Fatalf("apply under tenant B: %v", err)
	}

	// Each tenant sees exactly 1 event.
	eventsA, _ := store.ListByFinding(tenantA, "eng-a", "f1")
	eventsB, _ := store.ListByFinding(tenantB, "eng-b", "f1")
	if len(eventsA) != 1 || len(eventsB) != 1 {
		t.Errorf("tenant A events: %d, tenant B events: %d, want 1 each", len(eventsA), len(eventsB))
	}
}

// --- New tests for Task #9 fixes ---

func TestPromotionEventEquals(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	base := promotion.PromotionEvent{
		ID: "evt-1", EngagementID: "eng-1", JudgmentID: "j1", FindingID: "f1",
		FindingVersion: 1, AfterFindingVersion: 2,
		Rule: judgment.RuleRuntimeReachableExposed, Effect: judgment.PromotionEscalate,
		BeforePriority: 3, AfterPriority: 2,
		Inputs:      []judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "in1"}},
		Fingerprint: strings.Repeat("a", 64),
		Uncertainty: nil,
		AppliedAt:   now,
	}
	if !base.Equals(base) {
		t.Error("event should equal itself")
	}
	other := base
	other.EngagementID = "eng-2"
	if base.Equals(other) {
		t.Error("should differ on engagementID")
	}
	other = base
	other.Rule = "other.rule"
	if base.Equals(other) {
		t.Error("should differ on rule")
	}
	other = base
	other.Fingerprint = strings.Repeat("b", 64)
	if base.Equals(other) {
		t.Error("should differ on fingerprint")
	}
	other = base
	other.Inputs = []judgment.PromotionInput{{Kind: judgment.PromotionInputAttackPath, ID: "x"}}
	if base.Equals(other) {
		t.Error("should differ on inputs")
	}
	other = base
	other.Uncertainty = []string{"token"}
	if base.Equals(other) {
		t.Error("should differ on uncertainty")
	}
	other = base
	other.AppliedAt = now.Add(time.Hour)
	if !base.Equals(other) {
		t.Error("AppliedAt is generated; should still be equal")
	}
	// Verifier, VerdictScore, VerdictRationale, EvidenceID are sealed
	// provenance from the judgment — altering them means different provenance.
	other = base
	other.VerdictScore = 999
	if base.Equals(other) {
		t.Error("should differ on VerdictScore (sealed provenance)")
	}
	other = base
	other.Verifier = "attacker"
	if base.Equals(other) {
		t.Error("should differ on Verifier (sealed provenance)")
	}
	other = base
	other.VerdictRationale = "tampered"
	if base.Equals(other) {
		t.Error("should differ on VerdictRationale (sealed provenance)")
	}
	other = base
	other.EvidenceID = "ev-other"
	if base.Equals(other) {
		t.Error("should differ on EvidenceID (sealed provenance)")
	}
	other = base
	other.ID = "evt-other"
	if !base.Equals(other) {
		t.Error("EventID is regenerated; should still be equal")
	}
	other = base
	other.AppliedBy = "other-actor"
	if base.Equals(other) {
		t.Error("should differ on AppliedBy")
	}
}

func TestPromotionEventUncertaintyPreserved(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	unc := []string{"inferred_path", "unknown_reachability"}
	evt, err := promotion.NewPromotionEvent(
		"evt-unc", "eng-1", "j1", "f1", 1, 1,
		judgment.RuleUncertainCorroboration,
		judgment.PromotionFlagForReview, 3, 3,
		[]judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "in1"}},
		strings.Repeat("a", 64),
		75, "verified", "ev-1", "human:verifier",
		unc, "tester", now,
	)
	if err != nil {
		t.Fatalf("NewPromotionEvent: %v", err)
	}
	if len(evt.Uncertainty) != 2 {
		t.Fatalf("uncertainty length = %d, want 2", len(evt.Uncertainty))
	}
	unc[0] = "mutated"
	if evt.Uncertainty[0] == "mutated" {
		t.Error("uncertainty should be a defensive copy")
	}
}

func TestPromotionEventClaimValidationEnforced(t *testing.T) {
	now := time.Now()
	_, err := promotion.NewPromotionEvent(
		"evt-1", "eng-1", "j1", "f1", 1, 2,
		judgment.RuleRuntimeReachableExposed,
		judgment.PromotionEscalate, 3, 2,
		[]judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "in1"}},
		strings.Repeat("z", 64), 0, "", "", "",
		nil, "tester", now,
	)
	if err == nil {
		t.Error("want validation error for invalid fingerprint format")
	}
	_, err = promotion.NewPromotionEvent(
		"evt-1", "eng-1", "j1", "f1", 1, 2,
		judgment.RuleRuntimeReachableExposed,
		judgment.PromotionEscalate, 3, 2,
		[]judgment.PromotionInput{
			{Kind: judgment.PromotionInputReachability, ID: "b"},
			{Kind: judgment.PromotionInputAttackPath, ID: "a"},
		},
		strings.Repeat("a", 64), 0, "", "", "",
		nil, "tester", now,
	)
	if err == nil {
		t.Error("want validation error for unsorted inputs")
	}
}

func TestPromotionStoreExactReplayConflictOnAlteredFields(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()
	seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)
	cmd := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd.ExpectedPriority = 3
	cmd.ExpectedVersion = 1
	if _, err := store.Apply(ctx, "eng-1", "f1", cmd); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	altered := cmd
	altered.Rule = "promotion.altered.rule"
	altered.Effect = judgment.PromotionDeescalate
	altered.AfterPriority = 4
	if _, err := store.Apply(ctx, "eng-1", "f1", altered); !errors.Is(err, shared.ErrConflict) {
		t.Errorf("want ErrConflict for altered replay, got %v", err)
	}
}

func TestPromotionStoreReplayConflictOnAlteredProvenance(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()
	seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)
	cmd := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd.ExpectedPriority = 3
	cmd.ExpectedVersion = 1
	cmd.VerdictScore = 80
	cmd.VerdictRationale = "reachability confirmed"
	cmd.EvidenceID = "ev-1"
	cmd.Verifier = "verifier-a"
	if _, err := store.Apply(ctx, "eng-1", "f1", cmd); err != nil {
		t.Fatalf("first apply: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*ports.PromotionCommand)
	}{
		{"altered VerdictScore", func(c *ports.PromotionCommand) { c.VerdictScore = 999 }},
		{"altered Verifier", func(c *ports.PromotionCommand) { c.Verifier = "attacker" }},
		{"altered VerdictRationale", func(c *ports.PromotionCommand) { c.VerdictRationale = "tampered" }},
		{"altered EvidenceID", func(c *ports.PromotionCommand) { c.EvidenceID = "ev-other" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			altered := cmd
			tc.mutate(&altered)
			_, err := store.Apply(ctx, "eng-1", "f1", altered)
			if !errors.Is(err, shared.ErrConflict) {
				t.Errorf("want ErrConflict for %s, got %v", tc.name, err)
			}
		})
	}

	// Exact replay (same provenance) should still be idempotent.
	got, err := store.Apply(ctx, "eng-1", "f1", cmd)
	if err != nil {
		t.Fatalf("exact replay: %v", err)
	}
	if got.Priority != 2 {
		t.Errorf("replay priority = %d, want 2", got.Priority)
	}
}

func TestPromotionStoreReplayConflictsOnAppliedBy(t *testing.T) {
	findingRepo := NewFindingRepository()
	store := mustPromotionStore(t, findingRepo, defaultReader())
	ctx := tenantCtx()
	seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)
	cmd := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd.ExpectedPriority, cmd.ExpectedVersion = 3, 1
	if _, err := store.Apply(ctx, "eng-1", "f1", cmd); err != nil {
		t.Fatal(err)
	}
	altered := cmd
	altered.AppliedBy = "human:other"
	if _, err := store.Apply(ctx, "eng-1", "f1", altered); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("altered applied-by error = %v, want ErrConflict", err)
	}
}

func TestPromotionStoreReversalLineageContinuity(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()
	seedFinding(t, findingRepo, "eng-1", "f1", 4, 1)
	esc1 := sampleCmd(judgment.PromotionEscalate, 4, 3)
	esc1.ExpectedPriority = 4
	esc1.ExpectedVersion = 1
	esc1.EventID = "evt-esc1"
	esc1.FindingVersion = 1
	if _, err := store.Apply(ctx, "eng-1", "f1", esc1); err != nil {
		t.Fatalf("escalation 1: %v", err)
	}
	esc2 := sampleCmd(judgment.PromotionEscalate, 3, 2)
	esc2.ExpectedPriority = 3
	esc2.ExpectedVersion = 2
	esc2.EventID = "evt-esc2"
	esc2.JudgmentID = "j2"
	esc2.FindingVersion = 2
	esc2.Fingerprint = strings.Repeat("b", 64)
	if _, err := store.Apply(ctx, "eng-1", "f1", esc2); err != nil {
		t.Fatalf("escalation 2: %v", err)
	}
	revCmd := sampleCmd(judgment.PromotionDeescalate, 2, 4)
	revCmd.Rule = judgment.RuleCorroboratingSignalLoss
	revCmd.Inputs = []judgment.PromotionInput{
		{Kind: judgment.PromotionInputPrior, ID: "evt-esc1"},
		{Kind: judgment.PromotionInputReachability, ID: "j1"},
	}
	revCmd.JudgmentID = "j-rev"
	revCmd.EventID = "evt-rev"
	revCmd.FindingVersion = 3
	revCmd.ExpectedPriority = 2
	revCmd.ExpectedVersion = 3
	revCmd.BeforePriority = 2
	revCmd.Fingerprint = strings.Repeat("e", 64)
	if _, err := store.Apply(ctx, "eng-1", "f1", revCmd); !errors.Is(err, shared.ErrConflict) {
		t.Errorf("want ErrConflict for reversing non-latest event, got %v", err)
	}
	revCmd2 := sampleCmd(judgment.PromotionDeescalate, 2, 3)
	revCmd2.Rule = judgment.RuleCorroboratingSignalLoss
	revCmd2.Inputs = []judgment.PromotionInput{
		{Kind: judgment.PromotionInputPrior, ID: "evt-esc2"},
		{Kind: judgment.PromotionInputReachability, ID: "j1"},
	}
	revCmd2.JudgmentID = "j-rev2"
	revCmd2.EventID = "evt-rev2"
	revCmd2.FindingVersion = 3
	revCmd2.ExpectedPriority = 2
	revCmd2.ExpectedVersion = 3
	revCmd2.BeforePriority = 2
	revCmd2.Fingerprint = strings.Repeat("c", 64)
	got, err := store.Apply(ctx, "eng-1", "f1", revCmd2)
	if err != nil {
		t.Fatalf("reverse latest escalation: %v", err)
	}
	if got.Priority != 3 {
		t.Errorf("priority = %d, want 3", got.Priority)
	}
}

func TestPromotionStoreListByFindingEngagementScope(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()
	seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)
	seedFinding(t, findingRepo, "eng-2", "f1", 3, 1)
	cmd := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd.ExpectedPriority = 3
	cmd.ExpectedVersion = 1
	if _, err := store.Apply(ctx, "eng-1", "f1", cmd); err != nil {
		t.Fatalf("apply to eng-1: %v", err)
	}
	events1, _ := store.ListByFinding(ctx, "eng-1", "f1")
	if len(events1) != 1 {
		t.Errorf("eng-1 events: %d, want 1", len(events1))
	}
	events2, _ := store.ListByFinding(ctx, "eng-2", "f1")
	if len(events2) != 0 {
		t.Errorf("eng-2 events: %d, want 0", len(events2))
	}
	_, ok1, _ := store.LatestByFinding(ctx, "eng-1", "f1")
	if !ok1 {
		t.Error("eng-1 latest should exist")
	}
	_, ok2, _ := store.LatestByFinding(ctx, "eng-2", "f1")
	if ok2 {
		t.Error("eng-2 latest should not exist")
	}
}

func TestPromotionStoreStaleCASAfterReupsert(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	// Seed finding at P3, version 1.
	f := seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)
	if f.Version != 1 {
		t.Fatalf("seed version = %d, want 1", f.Version)
	}

	// Apply escalation P3->P2 with j1. Finding becomes version 2.
	cmd1 := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd1.ExpectedPriority = 3
	cmd1.ExpectedVersion = 1
	cmd1.VerdictScore = 80
	cmd1.VerdictRationale = "verified"
	cmd1.EvidenceID = "evidence-1"
	cmd1.Verifier = "v1"
	got1, err := store.Apply(ctx, "eng-1", "f1", cmd1)
	if err != nil {
		t.Fatalf("first escalation: %v", err)
	}
	if got1.Version != 2 {
		t.Fatalf("version after escalation = %d, want 2", got1.Version)
	}

	// Re-upsert the finding (simulates a re-scan). Version bumps to 3,
	// promoted priority (2) is preserved.
	fRescan := finding.Finding{
		ID: "f1", EngagementID: "eng-1", Title: "test finding",
		Severity: shared.SeverityHigh, Status: finding.StatusConfirmed,
		Kind: finding.KindSCA, Priority: 2,
		DedupKey: "test:f1",
		Audit:    shared.Audit{CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}
	if err := findingRepo.Upsert(ctx, []finding.Finding{fRescan}); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	fAfter, err := findingRepo.getFinding("eng-1", "f1")
	if err != nil {
		t.Fatalf("get finding after re-upsert: %v", err)
	}
	if fAfter.Version != 3 {
		t.Fatalf("version after re-upsert = %d, want 3", fAfter.Version)
	}
	if fAfter.Priority != 2 {
		t.Fatalf("priority after re-upsert = %d, want 2 (preserved)", fAfter.Priority)
	}

	// Now try to apply j2 escalation P2->P1 with ExpectedVersion=2 (stale).
	// Should fail CAS because stored version is now 3.
	cmd2 := sampleCmd(judgment.PromotionEscalate, 2, 1)
	cmd2.JudgmentID = "j2"
	cmd2.EventID = "evt-stale"
	cmd2.Fingerprint = strings.Repeat("b", 64)
	cmd2.ExpectedPriority = 2
	cmd2.ExpectedVersion = 2 // stale: actual is 3
	cmd2.VerdictScore = 90
	cmd2.Verifier = "v2"
	_, err = store.Apply(ctx, "eng-1", "f1", cmd2)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("want ErrConflict for stale CAS after re-upsert, got %v", err)
	}

	// Exact replay of j1 should still succeed (idempotent path).
	replay, err := store.Apply(ctx, "eng-1", "f1", cmd1)
	if err != nil {
		t.Fatalf("j1 idempotent replay after re-upsert: %v", err)
	}
	if replay.Priority != 2 {
		t.Errorf("replay priority = %d, want 2", replay.Priority)
	}
}

func TestPromotionStoreEventIDCollisionConflict(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	// Seed two findings in the same engagement.
	seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)
	seedFinding(t, findingRepo, "eng-1", "f2", 3, 1)

	// Apply escalation to f1 with EventID "evt-shared".
	cmd1 := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd1.ExpectedPriority = 3
	cmd1.ExpectedVersion = 1
	cmd1.EventID = "evt-shared"
	if _, err := store.Apply(ctx, "eng-1", "f1", cmd1); err != nil {
		t.Fatalf("first apply: %v", err)
	}

	// Try to apply a DIFFERENT event to f2 with the same EventID.
	// Must return ErrConflict before any mutation.
	cmd2 := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd2.JudgmentID = "j2"
	cmd2.EventID = "evt-shared" // collision
	cmd2.Fingerprint = strings.Repeat("b", 64)
	cmd2.ExpectedPriority = 3
	cmd2.ExpectedVersion = 1
	_, err := store.Apply(ctx, "eng-1", "f2", cmd2)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("want ErrConflict for EventID collision, got %v", err)
	}

	// f2 must not have been mutated: no event persisted, priority and
	// version must be unchanged from the seeded state.
	events2, _ := store.ListByFinding(ctx, "eng-1", "f2")
	if len(events2) != 0 {
		t.Errorf("f2 events after collision: %d, want 0", len(events2))
	}
	f2After, err := findingRepo.getFinding("eng-1", "f2")
	if err != nil {
		t.Fatalf("get f2 after collision: %v", err)
	}
	if f2After.Priority != 3 {
		t.Errorf("f2 priority after collision = %d, want 3 (unchanged)", f2After.Priority)
	}
	if f2After.Version != 1 {
		t.Errorf("f2 version after collision = %d, want 1 (unchanged)", f2After.Version)
	}

	// f1 must also be unaffected by the collision attempt.
	f1After, err := findingRepo.getFinding("eng-1", "f1")
	if err != nil {
		t.Fatalf("get f1 after collision: %v", err)
	}
	if f1After.Priority != 2 {
		t.Errorf("f1 priority after collision = %d, want 2", f1After.Priority)
	}
	if f1After.Version != 2 {
		t.Errorf("f1 version after collision = %d, want 2", f1After.Version)
	}

	// Exact semantic replay with same EventID should succeed (idempotent).
	replay, err := store.Apply(ctx, "eng-1", "f1", cmd1)
	if err != nil {
		t.Fatalf("exact replay with same EventID: %v", err)
	}
	if replay.Priority != 2 {
		t.Errorf("replay priority = %d, want 2", replay.Priority)
	}
}

func TestPromotionStoreReversalAfterFlagForReview(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	// Seed finding at P4, version 1.
	f := seedFinding(t, findingRepo, "eng-1", "f1", 4, 1)

	// 1. Escalate P4->P3. Finding becomes version 2.
	escCmd := sampleCmd(judgment.PromotionEscalate, 4, 3)
	escCmd.ExpectedPriority = 4
	escCmd.ExpectedVersion = f.Version
	escCmd.EventID = "prior-evt"
	if _, err := store.Apply(ctx, "eng-1", "f1", escCmd); err != nil {
		t.Fatalf("escalation: %v", err)
	}

	// 2. flag_for_review (non-mutating). Version stays 2.
	reviewCmd := sampleCmd(judgment.PromotionFlagForReview, 3, 3)
	reviewCmd.Rule = judgment.RuleUncertainCorroboration
	reviewCmd.JudgmentID = "j-review"
	reviewCmd.EventID = "review-evt"
	reviewCmd.Fingerprint = strings.Repeat("b", 64)
	reviewCmd.FindingVersion = 2
	reviewCmd.ExpectedPriority = 3
	reviewCmd.ExpectedVersion = 2
	if _, err := store.Apply(ctx, "eng-1", "f1", reviewCmd); err != nil {
		t.Fatalf("flag_for_review: %v", err)
	}

	// 3. Exact reversal should succeed even though a flag_for_review event
	// was inserted between the escalation and the reversal. flag_for_review
	// is non-mutating and does not block the reversal lineage.
	revCmd := sampleCmd(judgment.PromotionDeescalate, 3, 4)
	revCmd.Rule = judgment.RuleCorroboratingSignalLoss
	revCmd.Inputs = []judgment.PromotionInput{
		{Kind: judgment.PromotionInputPrior, ID: "prior-evt"},
		{Kind: judgment.PromotionInputReachability, ID: "j1"},
	}
	revCmd.JudgmentID = "j-rev"
	revCmd.EventID = "evt-rev"
	revCmd.Fingerprint = strings.Repeat("c", 64)
	revCmd.FindingVersion = 2
	revCmd.ExpectedPriority = 3
	revCmd.ExpectedVersion = 2
	got, err := store.Apply(ctx, "eng-1", "f1", revCmd)
	if err != nil {
		t.Fatalf("reversal after review: %v", err)
	}
	if got.Priority != 4 {
		t.Errorf("priority = %d, want 4 (exact reversal)", got.Priority)
	}
	if got.Version != 3 {
		t.Errorf("version = %d, want 3 (bumped)", got.Version)
	}
}

func TestPromotionStoreReversalBlockedByLaterEscalation(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()

	// Seed finding at P4, version 1.
	f := seedFinding(t, findingRepo, "eng-1", "f1", 4, 1)

	// 1. Escalation A: P4->P3.
	escA := sampleCmd(judgment.PromotionEscalate, 4, 3)
	escA.ExpectedPriority = 4
	escA.ExpectedVersion = f.Version
	escA.EventID = "evt-escA"
	if _, err := store.Apply(ctx, "eng-1", "f1", escA); err != nil {
		t.Fatalf("escalation A: %v", err)
	}

	// 2. Escalation B: P3->P2.
	escB := sampleCmd(judgment.PromotionEscalate, 3, 2)
	escB.JudgmentID = "j2"
	escB.EventID = "evt-escB"
	escB.Fingerprint = strings.Repeat("b", 64)
	escB.FindingVersion = 2
	escB.ExpectedPriority = 3
	escB.ExpectedVersion = 2
	if _, err := store.Apply(ctx, "eng-1", "f1", escB); err != nil {
		t.Fatalf("escalation B: %v", err)
	}

	// 3. Try to reverse escalation A. Must fail because escalation B
	// is a later MUTATING event.
	revCmd := sampleCmd(judgment.PromotionDeescalate, 2, 4)
	revCmd.Rule = judgment.RuleCorroboratingSignalLoss
	revCmd.Inputs = []judgment.PromotionInput{
		{Kind: judgment.PromotionInputPrior, ID: "evt-escA"},
		{Kind: judgment.PromotionInputReachability, ID: "j1"},
	}
	revCmd.JudgmentID = "j-rev"
	revCmd.EventID = "evt-rev"
	revCmd.Fingerprint = strings.Repeat("c", 64)
	revCmd.FindingVersion = 3
	revCmd.ExpectedPriority = 2
	revCmd.ExpectedVersion = 3
	_, err := store.Apply(ctx, "eng-1", "f1", revCmd)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("want ErrConflict for reversing non-latest mutating event, got %v", err)
	}
}

func TestPromotionStorePendingAuditRecovery(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	ctx := tenantCtx()
	f := seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)
	cmd := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd.ExpectedPriority, cmd.ExpectedVersion = f.Priority, f.Version
	if _, err := store.Apply(ctx, "eng-1", "f1", cmd); err != nil {
		t.Fatal(err)
	}
	pending, err := store.ListPendingAudits(ctx, "eng-1")
	if err != nil || len(pending) != 1 || pending[0].ID != cmd.EventID {
		t.Fatalf("pending audits = %#v, %v", pending, err)
	}
	if err := store.MarkAuditComplete(ctx, cmd.EventID); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkAuditComplete(ctx, cmd.EventID); err != nil {
		t.Fatalf("idempotent acknowledgement: %v", err)
	}
	pending, err = store.ListPendingAudits(ctx, "eng-1")
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending audits after acknowledgement = %#v, %v", pending, err)
	}
}

func TestPromotionStorePendingAuditsIsolateSameEventIDAcrossTenants(t *testing.T) {
	findingRepo := NewFindingRepository()
	reader := defaultReader()
	store := mustPromotionStore(t, findingRepo, reader)
	tenantA := shared.WithTenant(context.Background(), "tenant-a")
	tenantB := shared.WithTenant(context.Background(), "tenant-b")
	seedFinding(t, findingRepo, "eng-a", "finding-a", 3, 1)
	seedFinding(t, findingRepo, "eng-b", "finding-b", 3, 1)

	for _, tc := range []struct {
		ctx                   context.Context
		engagement, finding   shared.ID
		judgment, fingerprint shared.ID
	}{
		{tenantA, "eng-a", "finding-a", "judgment-a", shared.ID(strings.Repeat("a", 64))},
		{tenantB, "eng-b", "finding-b", "judgment-b", shared.ID(strings.Repeat("b", 64))},
	} {
		cmd := sampleCmd(judgment.PromotionEscalate, 3, 2)
		cmd.EventID = "shared-event-id"
		cmd.JudgmentID = tc.judgment
		cmd.Fingerprint = string(tc.fingerprint)
		cmd.ExpectedPriority, cmd.ExpectedVersion = 3, 1
		if _, err := store.Apply(tc.ctx, tc.engagement, tc.finding, cmd); err != nil {
			t.Fatalf("apply %s: %v", tc.engagement, err)
		}
	}

	for _, tc := range []struct {
		ctx                 context.Context
		engagement, finding shared.ID
	}{
		{tenantA, "eng-a", "finding-a"},
		{tenantB, "eng-b", "finding-b"},
	} {
		pending, err := store.ListPendingAudits(tc.ctx, tc.engagement)
		if err != nil || len(pending) != 1 || pending[0].ID != "shared-event-id" || pending[0].FindingID != tc.finding {
			t.Fatalf("pending audits for %s = %#v, %v", tc.engagement, pending, err)
		}
	}

	if err := store.MarkAuditComplete(tenantA, "shared-event-id"); err != nil {
		t.Fatalf("acknowledge tenant A: %v", err)
	}
	pendingA, err := store.ListPendingAudits(tenantA, "eng-a")
	if err != nil || len(pendingA) != 0 {
		t.Fatalf("tenant A pending audits = %#v, %v", pendingA, err)
	}
	pendingB, err := store.ListPendingAudits(tenantB, "eng-b")
	if err != nil || len(pendingB) != 1 || pendingB[0].FindingID != "finding-b" {
		t.Fatalf("tenant B pending audits = %#v, %v", pendingB, err)
	}
}

type promotionIntegrationClock struct{ t time.Time }

func (c *promotionIntegrationClock) Now() time.Time { return c.t }

type promotionIntegrationIDs struct{ next int }

func (g *promotionIntegrationIDs) NewID() shared.ID {
	g.next++
	return shared.ID(fmt.Sprintf("integration-id-%d", g.next))
}

type promotionIntegrationAudit struct {
	entries []ports.AuditEntry
	fail    int
	seen    map[string]struct{}
}

func (a *promotionIntegrationAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	a.entries = append(a.entries, entry)
	return nil
}

func (a *promotionIntegrationAudit) RecordOnce(ctx context.Context, entry ports.AuditEntry) error {
	if a.fail > 0 {
		a.fail--
		return errors.New("audit unavailable")
	}
	if a.seen == nil {
		a.seen = make(map[string]struct{})
	}
	key := entry.Action + ":" + entry.Metadata["idempotency_key"]
	if _, ok := a.seen[key]; ok {
		return nil
	}
	a.seen[key] = struct{}{}
	return a.Record(ctx, entry)
}

func TestPromotionIntegrationRecoversAudit(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant-1")
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	engagements := NewEngagementRepository()
	eng, err := engagement.New("eng-1", "tenant-1", "promotion recovery", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := engagements.Create(ctx, eng); err != nil {
		t.Fatal(err)
	}
	findings := NewFindingRepository()
	f := integrationFinding(eng.ID, now)
	if err := findings.Upsert(ctx, []finding.Finding{f}); err != nil {
		t.Fatal(err)
	}
	promotions := mustPromotionStore(t, findings, engagements)
	audit := &promotionIntegrationAudit{fail: 1}
	evidenceStore := NewEvidenceStore()
	clock := &promotionIntegrationClock{t: now}
	evidenceService, err := evidenceuc.NewService(evidenceStore, nil, audit, clock, &promotionIntegrationIDs{})
	if err != nil {
		t.Fatal(err)
	}
	recorder, err := promotionuc.NewConfirmedRecorder(evidenceService, promotions, findings, engagements, audit, clock)
	if err != nil {
		t.Fatal(err)
	}
	j := integrationRecoveryJudgment()
	if err := recorder.RecordConfirmed(ctx, j); err == nil {
		t.Fatal("first audit failure must be returned")
	}
	integrationAssertPriority(t, findings, ctx, j.EngagementID, j.SubjectID, 2, 2)
	if err := recorder.RecordConfirmed(ctx, j); err != nil {
		t.Fatalf("retry audit: %v", err)
	}
	events, err := promotions.ListByFinding(ctx, j.EngagementID, j.SubjectID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("lifecycle events = %d, want 1", len(events))
	}
	links, err := evidenceStore.ListByEngagement(ctx, j.EngagementID)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || len(audit.entries) != 1 {
		t.Fatalf("recovery = links %d audits %d, want 1/1", len(links), len(audit.entries))
	}
}

func TestPromotionIntegrationLifecycleReevaluatesAndRestoresPriority(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant-1")
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &promotionIntegrationClock{t: now}
	ids := &promotionIntegrationIDs{}
	engagements := NewEngagementRepository()
	eng, err := engagement.New("eng-1", "tenant-1", "promotion lifecycle", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := engagements.Create(ctx, eng); err != nil {
		t.Fatal(err)
	}
	findings := NewFindingRepository()
	initial := integrationFinding(eng.ID, now)
	initial.ID, initial.DedupKey = "finding-1", "finding-1"
	if err := findings.Upsert(ctx, []finding.Finding{initial}); err != nil {
		t.Fatal(err)
	}
	assets := NewAssetStore()
	exposure, err := asset.New("exposure-1", "tenant-1", asset.KindExposure, "internet", "Internet", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	target, err := asset.New("asset-1", "tenant-1", asset.KindHost, "host-1", "Host", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := assets.UpsertAsset(ctx, exposure); err != nil {
		t.Fatal(err)
	}
	if err := assets.UpsertAsset(ctx, target); err != nil {
		t.Fatal(err)
	}
	edge, err := asset.NewEdge("tenant-1", exposure.ID, target.ID, asset.EdgeReaches, "edge-1", asset.EdgeObserved)
	if err != nil {
		t.Fatal(err)
	}
	if err := assets.UpsertEdge(ctx, edge); err != nil {
		t.Fatal(err)
	}
	bindings := NewAttackPathStore()
	if err := bindings.ReplaceBindings(ctx, "tenant-1", eng.ID, "scanner-1", []attackpath.Binding{{TenantID: "tenant-1", EngagementID: eng.ID, AssetID: target.ID, FindingID: initial.ID, TargetKind: attackpath.TargetCanonical, Producer: "scanner-1", Provenance: "binding-1", Confidence: asset.EdgeObserved}}); err != nil {
		t.Fatal(err)
	}
	detections := NewDetectionRecordStore()
	detections.SetClock(clock.Now)
	detectionRule, ok := detection.Lookup("det.process_enumeration")
	if !ok {
		t.Fatal("missing detection rule fixture")
	}
	detected, err := detection.NewDetection(detectionRule, "host-1", "agent-1", []detection.Event{{Class: detection.ClassProcess, At: now, Host: "host-1", Process: &detection.ProcessEvent{PID: 1, Comm: "ps", Path: "/usr/bin/ps"}}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := detections.AppendDetection(ctx, detection.Record{ID: "detection-1", TenantID: "tenant-1", EngagementID: eng.ID, AssetID: target.ID, AgentID: "agent-1", Detection: detected, EvidenceID: "detection-evidence-1", BatchSeq: 1, RecordedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	audit := &promotionIntegrationAudit{}
	evidenceStore := NewEvidenceStore()
	evidenceService, err := evidenceuc.NewService(evidenceStore, nil, audit, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	judgments := NewJudgmentStore()
	analysisService, err := analysis.NewService(judgments, evidenceService, audit, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	promotions := mustPromotionStore(t, findings, engagements)
	recorder, err := promotionuc.NewConfirmedRecorder(evidenceService, promotions, findings, engagements, audit, clock)
	if err != nil {
		t.Fatal(err)
	}
	analysisService.SetPromotionRecorder(recorder)
	evaluator, err := promotionuc.NewEvaluator(analysisService, findings, judgments, bindings, assets, detections, engagements, promotions, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	reachability, err := analysisService.Propose(ctx, "system:jsimport-scan", eng.ID, judgment.CapReachability, judgment.SubjectFinding, initial.ID, judgment.ReachabilityClaim{Reachable: judgment.Reachable, Tier: judgment.Tier1})
	if err != nil {
		t.Fatalf("propose reachability: %v", err)
	}
	if _, err := analysisService.Verify(ctx, "system:jsimport-engine", eng.ID, reachability.ID, 90, "first-party import proof", reachability.Version); err != nil {
		t.Fatalf("confirm reachability: %v", err)
	}
	if proposed, err := evaluator.Evaluate(ctx, eng.ID); err != nil || proposed != 1 {
		t.Fatalf("escalation reevaluation = (%d, %v), want (1, nil)", proposed, err)
	}
	escalation := integrationLatestPromotionJudgment(t, integrationListJudgments(t, analysisService, ctx, eng.ID))
	if proposed, err := evaluator.Evaluate(ctx, eng.ID); err != nil || proposed != 0 {
		t.Fatalf("unchanged reevaluation = (%d, %v), want (0, nil)", proposed, err)
	}
	if _, err := analysisService.Verify(ctx, "human:reviewer", eng.ID, escalation.ID, 75, "confirmed escalation", escalation.Version); err != nil {
		t.Fatalf("confirm escalation: %v", err)
	}
	integrationAssertPriority(t, findings, ctx, eng.ID, initial.ID, 2, 2)
	clock.t = now.Add(2 * time.Hour)
	if proposed, err := evaluator.Evaluate(ctx, eng.ID); err != nil || proposed != 1 {
		t.Fatalf("signal-loss reevaluation = (%d, %v), want (1, nil)", proposed, err)
	}
	reversal := integrationLatestPromotionJudgment(t, integrationListJudgments(t, analysisService, ctx, eng.ID))
	if reversal.ID == escalation.ID {
		t.Fatal("signal loss must propose a distinct reversal judgment")
	}
	if _, err := analysisService.Verify(ctx, "human:reviewer", eng.ID, reversal.ID, 75, "confirmed reversal", reversal.Version); err != nil {
		t.Fatalf("confirm reversal: %v", err)
	}
	integrationAssertPriority(t, findings, ctx, eng.ID, initial.ID, initial.Priority, 3)
	if proposed, err := evaluator.Evaluate(ctx, eng.ID); err != nil || proposed != 0 {
		t.Fatalf("reversal retry = (%d, %v), want (0, nil)", proposed, err)
	}
	confirmed := integrationLatestPromotionJudgment(t, integrationListJudgments(t, analysisService, ctx, eng.ID))
	if _, err := analysisService.Verify(ctx, "human:reviewer", eng.ID, reversal.ID, 75, "confirmed reversal", confirmed.Version); err != nil {
		t.Fatalf("confirmed reversal retry: %v", err)
	}
	integrationAssertPriority(t, findings, ctx, eng.ID, initial.ID, initial.Priority, 3)
	events, err := promotions.ListByFinding(ctx, eng.ID, initial.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].AfterPriority != initial.Priority {
		t.Fatalf("events = %#v, want one escalation and exact-priority reversal", events)
	}
	links, err := evidenceStore.ListByEngagement(ctx, eng.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 8 || integrationAuditCount(audit.entries, "promotion.applied") != 2 {
		t.Fatalf("lifecycle idempotency = links %d audits %d, want 8/2", len(links), integrationAuditCount(audit.entries, "promotion.applied"))
	}
}

func TestPromotionIntegrationRecoveryRejectsAlteredProvenance(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant-1")
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	engagements := NewEngagementRepository()
	eng, err := engagement.New("eng-1", "tenant-1", "promotion recovery", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := engagements.Create(ctx, eng); err != nil {
		t.Fatal(err)
	}
	findings := NewFindingRepository()
	if err := findings.Upsert(ctx, []finding.Finding{integrationFinding(eng.ID, now)}); err != nil {
		t.Fatal(err)
	}
	promotions := mustPromotionStore(t, findings, engagements)
	audit := &promotionIntegrationAudit{fail: 1}
	clock := &promotionIntegrationClock{t: now}
	evidenceService, err := evidenceuc.NewService(NewEvidenceStore(), nil, audit, clock, &promotionIntegrationIDs{})
	if err != nil {
		t.Fatal(err)
	}
	recorder, err := promotionuc.NewConfirmedRecorder(evidenceService, promotions, findings, engagements, audit, clock)
	if err != nil {
		t.Fatal(err)
	}
	j := integrationRecoveryJudgment()
	if err := recorder.RecordConfirmed(ctx, j); err == nil {
		t.Fatal("first audit failure must be returned")
	}
	for _, altered := range []judgment.Judgment{
		func() judgment.Judgment { replay := j; replay.VerdictRationale = "altered provenance"; return replay }(),
		func() judgment.Judgment {
			replay := j
			replay.Claim = judgment.PromotionClaim{FindingID: "find-1", Rule: judgment.RuleRuntimeReachableExposed, Inputs: []judgment.PromotionInput{{Kind: judgment.PromotionInputDetection, ID: "altered-input"}}, Proposed: judgment.PromotionEscalate, FindingVersion: 1, BeforePriority: 3, AfterPriority: 2, Fingerprint: strings.Repeat("1", 64)}
			return replay
		}(),
	} {
		if err := recorder.RecordConfirmed(ctx, altered); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("altered recovery = %v, want ErrConflict", err)
		}
	}
	events, err := promotions.ListByFinding(ctx, j.EngagementID, j.SubjectID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || len(audit.entries) != 0 {
		t.Fatalf("altered recovery changed state: events=%d audits=%d", len(events), len(audit.entries))
	}
}

func TestPromotionIntegrationReconcilerAppliesConfirmedPromotionIdempotently(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant-1")
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	engagements := NewEngagementRepository()
	eng, err := engagement.New("eng-1", "tenant-1", "promotion reconciliation", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := engagements.Create(ctx, eng); err != nil {
		t.Fatal(err)
	}
	findings := NewFindingRepository()
	f := integrationFinding(eng.ID, now)
	if err := findings.Upsert(ctx, []finding.Finding{f}); err != nil {
		t.Fatal(err)
	}
	judgments := NewJudgmentStore()
	j := integrationRecoveryJudgment()
	if err := judgments.Save(ctx, j); err != nil {
		t.Fatal(err)
	}
	promotions := mustPromotionStore(t, findings, engagements)
	audit := &promotionIntegrationAudit{}
	clock := &promotionIntegrationClock{t: now}
	evidenceService, err := evidenceuc.NewService(NewEvidenceStore(), nil, audit, clock, &promotionIntegrationIDs{})
	if err != nil {
		t.Fatal(err)
	}
	recorder, err := promotionuc.NewConfirmedRecorder(evidenceService, promotions, findings, engagements, audit, clock)
	if err != nil {
		t.Fatal(err)
	}
	reconciler, err := promotionuc.NewReconciler(judgments, promotions, recorder, audit, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Reconcile(ctx, eng.ID); err != nil {
		t.Fatalf("reconcile confirmed promotion: %v", err)
	}
	integrationAssertPriority(t, findings, ctx, eng.ID, f.ID, 2, 2)
	if integrationAuditCount(audit.entries, "promotion.applied") != 1 {
		t.Fatalf("promotion audit records = %d, want 1", integrationAuditCount(audit.entries, "promotion.applied"))
	}
	if err := reconciler.Reconcile(ctx, eng.ID); err != nil {
		t.Fatalf("idempotent reconciliation: %v", err)
	}
	events, err := promotions.ListByFinding(ctx, eng.ID, f.ID)
	if err != nil || len(events) != 1 {
		t.Fatalf("reconciliation duplicated lifecycle event: (%d, %v)", len(events), err)
	}
}

func TestPromotionIntegrationReconcilerRecoversAppliedAudit(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant-1")
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	engagements := NewEngagementRepository()
	eng, err := engagement.New("eng-1", "tenant-1", "promotion audit reconciliation", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := engagements.Create(ctx, eng); err != nil {
		t.Fatal(err)
	}
	findings := NewFindingRepository()
	f := integrationFinding(eng.ID, now)
	if err := findings.Upsert(ctx, []finding.Finding{f}); err != nil {
		t.Fatal(err)
	}
	judgments := NewJudgmentStore()
	j := integrationRecoveryJudgment()
	if err := judgments.Save(ctx, j); err != nil {
		t.Fatal(err)
	}
	promotions := mustPromotionStore(t, findings, engagements)
	audit := &promotionIntegrationAudit{fail: 1}
	clock := &promotionIntegrationClock{t: now}
	evidenceService, err := evidenceuc.NewService(NewEvidenceStore(), nil, audit, clock, &promotionIntegrationIDs{})
	if err != nil {
		t.Fatal(err)
	}
	recorder, err := promotionuc.NewConfirmedRecorder(evidenceService, promotions, findings, engagements, audit, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := recorder.RecordConfirmed(ctx, j); err == nil {
		t.Fatal("applied promotion with failed audit must return an error")
	}
	integrationAssertPriority(t, findings, ctx, eng.ID, f.ID, 2, 2)
	pending, err := promotions.ListPendingAudits(ctx, eng.ID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending promotion audits = %#v, %v", pending, err)
	}
	reconciler, err := promotionuc.NewReconciler(judgments, promotions, recorder, audit, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Reconcile(ctx, eng.ID); err != nil {
		t.Fatalf("recover applied promotion audit: %v", err)
	}
	pending, err = promotions.ListPendingAudits(ctx, eng.ID)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending promotion audits after recovery = %#v, %v", pending, err)
	}
	if integrationAuditCount(audit.entries, "promotion.applied") != 1 {
		t.Fatalf("promotion audit records = %d, want one recovered idempotent record", integrationAuditCount(audit.entries, "promotion.applied"))
	}
	events, err := promotions.ListByFinding(ctx, eng.ID, f.ID)
	if err != nil || len(events) != 1 {
		t.Fatalf("audit reconciliation duplicated lifecycle event: (%d, %v)", len(events), err)
	}
}

func integrationFinding(engagementID shared.ID, now time.Time) finding.Finding {
	return finding.Finding{ID: "find-1", EngagementID: engagementID, Title: "reachable finding", Kind: finding.KindSCA, Priority: 3, Version: 1, DedupKey: "find-1", Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}}
}

func integrationRecoveryJudgment() judgment.Judgment {
	return judgment.Judgment{
		ID: "recovery-judgment", EngagementID: "eng-1", Capability: judgment.CapPromotion, SubjectKind: judgment.SubjectFinding, SubjectID: "find-1",
		State: judgment.StateConfirmed, EvidenceScore: 75, ProposedBy: "agent:proposer", VerifiedBy: "human:verifier", VerdictRationale: "confirmed",
		Claim: judgment.PromotionClaim{FindingID: "find-1", Rule: judgment.RuleRuntimeReachableExposed, Inputs: []judgment.PromotionInput{{Kind: judgment.PromotionInputDetection, ID: "det-1"}}, Proposed: judgment.PromotionEscalate, FindingVersion: 1, BeforePriority: 3, AfterPriority: 2, Fingerprint: strings.Repeat("1", 64)},
	}
}

func integrationListJudgments(t *testing.T, service *analysis.Service, ctx context.Context, engagementID shared.ID) []judgment.Judgment {
	t.Helper()
	judgments, err := service.List(ctx, engagementID)
	if err != nil {
		t.Fatal(err)
	}
	return judgments
}

func integrationLatestPromotionJudgment(t *testing.T, judgments []judgment.Judgment) judgment.Judgment {
	t.Helper()
	for i := len(judgments) - 1; i >= 0; i-- {
		if judgments[i].Capability == judgment.CapPromotion {
			return judgments[i]
		}
	}
	t.Fatal("missing promotion judgment")
	return judgment.Judgment{}
}

func integrationAssertPriority(t *testing.T, findings ports.FindingRepository, ctx context.Context, engagementID, findingID shared.ID, priority, version int) {
	t.Helper()
	got, err := findings.GetByEngagementAndID(ctx, engagementID, findingID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Priority != priority || got.Version != version {
		t.Fatalf("finding = priority %d version %d, want %d/%d", got.Priority, got.Version, priority, version)
	}
}

func integrationAuditCount(entries []ports.AuditEntry, action string) int {
	count := 0
	for _, entry := range entries {
		if entry.Action == action {
			count++
		}
	}
	return count
}

func TestPromotionStoreApplyCanceledDoesNotMutate(t *testing.T) {
	findingRepo := NewFindingRepository()
	store := mustPromotionStore(t, findingRepo, defaultReader())
	f := seedFinding(t, findingRepo, "eng-1", "f1", 3, 1)
	cmd := sampleCmd(judgment.PromotionEscalate, 3, 2)
	cmd.ExpectedPriority, cmd.ExpectedVersion = f.Priority, f.Version
	ctx, cancel := context.WithCancel(tenantCtx())
	cancel()
	if _, err := store.Apply(ctx, "eng-1", "f1", cmd); !errors.Is(err, context.Canceled) {
		t.Fatalf("Apply canceled error = %v", err)
	}
	got, err := findingRepo.GetByEngagementAndID(tenantCtx(), "eng-1", "f1")
	if err != nil || got.Priority != 3 || got.Version != 1 {
		t.Fatalf("canceled Apply mutated finding: %#v, %v", got, err)
	}
	events, err := store.ListByFinding(tenantCtx(), "eng-1", "f1")
	if err != nil || len(events) != 0 {
		t.Fatalf("canceled Apply appended events: %#v, %v", events, err)
	}
}
