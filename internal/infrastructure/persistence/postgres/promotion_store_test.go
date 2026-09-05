package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func mustPromotionStore(t *testing.T, pool *pgxpool.Pool) *PromotionStore {
	t.Helper()
	store, err := NewPromotionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestPromotionStore(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	ctx = shared.WithTenant(ctx, "default")
	// A promotion fingerprint is unique for the life of the database: the store refuses to apply
	// one that another judgment already used. Fixed fingerprints therefore made this test pass only
	// against a database it had never run on, so a second run, or `go test -count=2`, failed with a
	// conflict that had nothing to do with what was under test. Each run gets its own namespace.
	fp := promotionFingerprint(t)
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	// Create engagement fixture.
	eid := shared.ID("promo-eng-" + randHex(t))
	e, err := engagement.New(eid, "", "promotion-test", "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := NewEngagementRepository(pool).Create(ctx, e); err != nil {
		t.Fatalf("create engagement: %v", err)
	}
	t.Cleanup(func() {
		// finding_promotion_events cascade-deletes via engagement FK.
		_, _ = pool.Exec(ctx, "DELETE FROM judgments WHERE engagement_id=$1", eid.String())
		_, _ = pool.Exec(ctx, "DELETE FROM findings WHERE engagement_id=$1", eid.String())
		_, _ = pool.Exec(ctx, "DELETE FROM engagements WHERE id=$1", eid.String())
	})

	fRepo := NewFindingRepository(pool)
	jRepo := NewJudgmentRepository(pool)
	pStore := mustPromotionStore(t, pool)
	now := time.Now().UTC().Truncate(time.Second)

	// Seed a finding at P3, version 1.
	fid := shared.ID("promo-f-" + randHex(t))
	f := finding.Finding{
		ID: fid, EngagementID: eid, Title: "CVE-2025-0001 in x@1",
		Severity: shared.SeverityHigh, Status: finding.StatusConfirmed,
		Kind: finding.KindSCA, Priority: 3,
		DedupKey: "vuln:CVE-2025-0001:x:1",
		Audit:    shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
	if err := fRepo.Upsert(ctx, []finding.Finding{f}); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	// Seed a judgment for the finding.
	jid := shared.ID("promo-j-" + randHex(t))
	j := judgment.Judgment{
		ID: jid, EngagementID: eid,
		Capability:  judgment.CapPromotion,
		SubjectKind: judgment.SubjectFinding,
		SubjectID:   fid,
		Claim: &judgment.PromotionClaim{
			FindingID:      fid,
			Rule:           judgment.RuleRuntimeReachableExposed,
			Inputs:         []judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "reach-1"}},
			Proposed:       judgment.PromotionEscalate,
			Fingerprint:    fp("a"),
			FindingVersion: 1,
			BeforePriority: 3,
			AfterPriority:  2,
		},
		State: judgment.StateConfirmed,
		Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
	if err := jRepo.Save(ctx, j); err != nil {
		t.Fatalf("seed judgment: %v", err)
	}

	t.Run("apply escalation", func(t *testing.T) {
		cmd := ports.PromotionCommand{
			ExpectedPriority: 3,
			ExpectedVersion:  1,
			EventID:          shared.ID("evt-" + randHex(t)),
			JudgmentID:       jid,
			FindingVersion:   1,
			Rule:             judgment.RuleRuntimeReachableExposed,
			Effect:           judgment.PromotionEscalate,
			BeforePriority:   3,
			AfterPriority:    2,
			Inputs: []judgment.PromotionInput{
				{Kind: judgment.PromotionInputReachability, ID: "reach-1"},
			},
			Fingerprint:      fp("a"),
			VerdictScore:     80,
			AppliedBy:        "tester",
			VerdictRationale: "verified",
			EvidenceID:       "evidence-1",
			Verifier:         "human:verifier",
		}
		got, err := pStore.Apply(ctx, eid, fid, cmd)
		if err != nil {
			t.Fatalf("Apply escalation: %v", err)
		}
		if got.Priority != 2 {
			t.Errorf("priority = %d, want 2", got.Priority)
		}
		if got.Version != 2 {
			t.Errorf("version = %d, want 2 (bumped)", got.Version)
		}
	})

	t.Run("pending audit status", func(t *testing.T) {
		pending, err := pStore.ListPendingAudits(ctx, eid)
		if err != nil {
			t.Fatalf("list pending promotion audits: %v", err)
		}
		if len(pending) != 1 || pending[0].JudgmentID != jid {
			t.Fatalf("pending promotion audits = %#v, want event for %s", pending, jid)
		}
		if err := pStore.MarkAuditComplete(ctx, pending[0].ID); err != nil {
			t.Fatalf("mark promotion audit complete: %v", err)
		}
		if err := pStore.MarkAuditComplete(ctx, pending[0].ID); err != nil {
			t.Fatalf("idempotent promotion audit completion: %v", err)
		}
		pending, err = pStore.ListPendingAudits(ctx, eid)
		if err != nil || len(pending) != 0 {
			t.Fatalf("pending promotion audits after completion = %#v, %v", pending, err)
		}
	})

	t.Run("apply escalation idempotent", func(t *testing.T) {
		// Idempotent replay: same judgment, same fingerprint. The replay path
		// returns early at judgment-level idempotency before CAS binding.
		cmd := ports.PromotionCommand{
			ExpectedPriority: 2,
			ExpectedVersion:  2,
			EventID:          shared.ID("evt-" + randHex(t)),
			JudgmentID:       jid, // same judgment
			FindingVersion:   1,
			Rule:             judgment.RuleRuntimeReachableExposed,
			Effect:           judgment.PromotionEscalate,
			BeforePriority:   3,
			AfterPriority:    2,
			Inputs: []judgment.PromotionInput{
				{Kind: judgment.PromotionInputReachability, ID: "reach-1"},
			},
			Fingerprint:      fp("a"), // same fingerprint
			VerdictScore:     80,
			AppliedBy:        "tester",
			VerdictRationale: "verified",
			EvidenceID:       "evidence-1",
			Verifier:         "human:verifier",
		}
		got, err := pStore.Apply(ctx, eid, fid, cmd)
		if err != nil {
			t.Fatalf("idempotent re-apply: %v", err)
		}
		if got.Priority != 2 {
			t.Errorf("priority = %d, want 2 (unchanged)", got.Priority)
		}
	})

	t.Run("replay target mismatch", func(t *testing.T) {
		// Same judgment but try to apply against a different finding: should
		// fail because the replay detects the engagement/finding mismatch.
		fid2 := shared.ID("promo-f2-" + randHex(t))
		f2 := finding.Finding{
			ID: fid2, EngagementID: eid, Title: "other finding",
			Severity: shared.SeverityMedium, Status: finding.StatusConfirmed,
			Kind: finding.KindSCA, Priority: 3,
			DedupKey: "vuln:other:x:1",
			Audit:    shared.Audit{CreatedAt: now, UpdatedAt: now},
		}
		if err := fRepo.Upsert(ctx, []finding.Finding{f2}); err != nil {
			t.Fatalf("seed finding 2: %v", err)
		}

		cmd := ports.PromotionCommand{
			ExpectedPriority: 3,
			ExpectedVersion:  1,
			EventID:          shared.ID("evt-" + randHex(t)),
			JudgmentID:       jid, // same judgment as the escalation
			FindingVersion:   1,
			Rule:             judgment.RuleRuntimeReachableExposed,
			Effect:           judgment.PromotionEscalate,
			BeforePriority:   3,
			AfterPriority:    2,
			Inputs: []judgment.PromotionInput{
				{Kind: judgment.PromotionInputReachability, ID: "reach-1"},
			},
			Fingerprint:      fp("a"),
			AppliedBy:        "tester",
			VerdictRationale: "verified",
			EvidenceID:       "evidence-1",
			Verifier:         "human:verifier",
		}
		_, err := pStore.Apply(ctx, eid, fid2, cmd)
		if !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("want ErrConflict for replay target mismatch, got %v", err)
		}
	})

	t.Run("fingerprint conflict with different judgment", func(t *testing.T) {
		jid2 := shared.ID("promo-j2-" + randHex(t))
		j2 := judgment.Judgment{
			ID: jid2, EngagementID: eid,
			Capability:  judgment.CapPromotion,
			SubjectKind: judgment.SubjectFinding,
			SubjectID:   fid,
			Claim: &judgment.PromotionClaim{
				FindingID:      fid,
				Rule:           judgment.RuleRuntimeReachableExposed,
				Inputs:         []judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "reach-2"}},
				Proposed:       judgment.PromotionEscalate,
				Fingerprint:    fp("b"),
				FindingVersion: 1,
				BeforePriority: 3,
				AfterPriority:  2,
			},
			State: judgment.StateConfirmed,
			Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
		}
		if err := jRepo.Save(ctx, j2); err != nil {
			t.Fatalf("seed judgment 2: %v", err)
		}

		// Same fingerprint as first apply but different judgment -> conflict.
		cmd := ports.PromotionCommand{
			ExpectedPriority: 2,
			ExpectedVersion:  2,
			EventID:          shared.ID("evt-" + randHex(t)),
			JudgmentID:       jid2,
			FindingVersion:   2,
			Rule:             judgment.RuleRuntimeReachableExposed,
			Effect:           judgment.PromotionEscalate,
			BeforePriority:   2,
			AfterPriority:    1,
			Inputs: []judgment.PromotionInput{
				{Kind: judgment.PromotionInputReachability, ID: "reach-2"},
			},
			Fingerprint:      fp("a"), // same as first
			AppliedBy:        "tester",
			VerdictRationale: "verified",
			EvidenceID:       "evidence-1",
			Verifier:         "human:verifier",
		}
		_, err := pStore.Apply(ctx, eid, fid, cmd)
		if !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("want ErrConflict for fingerprint conflict, got %v", err)
		}
	})

	t.Run("CAS version mismatch", func(t *testing.T) {
		jid3 := shared.ID("promo-j3-" + randHex(t))
		j3 := judgment.Judgment{
			ID: jid3, EngagementID: eid,
			Capability:  judgment.CapPromotion,
			SubjectKind: judgment.SubjectFinding,
			SubjectID:   fid,
			Claim: &judgment.PromotionClaim{
				FindingID:      fid,
				Rule:           judgment.RuleDeterministicUnreachable,
				Inputs:         []judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "reach-3"}},
				Proposed:       judgment.PromotionDeescalate,
				Fingerprint:    fp("c"),
				FindingVersion: 1,
				BeforePriority: 3,
				AfterPriority:  4,
			},
			State: judgment.StateConfirmed,
			Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
		}
		if err := jRepo.Save(ctx, j3); err != nil {
			t.Fatalf("seed judgment 3: %v", err)
		}

		cmd := ports.PromotionCommand{
			ExpectedPriority: 2,
			ExpectedVersion:  1, // stale: actual is 2
			EventID:          shared.ID("evt-" + randHex(t)),
			JudgmentID:       jid3,
			FindingVersion:   1,
			Rule:             judgment.RuleDeterministicUnreachable,
			Effect:           judgment.PromotionDeescalate,
			BeforePriority:   2,
			AfterPriority:    3,
			Inputs: []judgment.PromotionInput{
				{Kind: judgment.PromotionInputReachability, ID: "reach-3"},
			},
			Fingerprint:      fp("c"),
			AppliedBy:        "tester",
			VerdictRationale: "verified",
			EvidenceID:       "evidence-1",
			Verifier:         "human:verifier",
		}
		_, err := pStore.Apply(ctx, eid, fid, cmd)
		if !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("want ErrConflict for CAS mismatch, got %v", err)
		}
	})

	t.Run("CAS binding FindingVersion mismatch", func(t *testing.T) {
		jid4 := shared.ID("promo-j4-" + randHex(t))
		j4 := judgment.Judgment{
			ID: jid4, EngagementID: eid,
			Capability:  judgment.CapPromotion,
			SubjectKind: judgment.SubjectFinding,
			SubjectID:   fid,
			Claim: &judgment.PromotionClaim{
				FindingID:      fid,
				Rule:           judgment.RuleDeterministicUnreachable,
				Inputs:         []judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "reach-4"}},
				Proposed:       judgment.PromotionDeescalate,
				Fingerprint:    fp("d"),
				FindingVersion: 1,
				BeforePriority: 2,
				AfterPriority:  3,
			},
			State: judgment.StateConfirmed,
			Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
		}
		if err := jRepo.Save(ctx, j4); err != nil {
			t.Fatalf("seed judgment 4: %v", err)
		}

		cmd := ports.PromotionCommand{
			ExpectedPriority: 2,
			ExpectedVersion:  2,
			EventID:          shared.ID("evt-" + randHex(t)),
			JudgmentID:       jid4,
			FindingVersion:   5, // does not match ExpectedVersion=2
			Rule:             judgment.RuleDeterministicUnreachable,
			Effect:           judgment.PromotionDeescalate,
			BeforePriority:   2,
			AfterPriority:    3,
			Inputs: []judgment.PromotionInput{
				{Kind: judgment.PromotionInputReachability, ID: "reach-4"},
			},
			Fingerprint:      fp("d"),
			AppliedBy:        "tester",
			VerdictRationale: "verified",
			EvidenceID:       "evidence-1",
			Verifier:         "human:verifier",
		}
		_, err := pStore.Apply(ctx, eid, fid, cmd)
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want ErrValidation for FindingVersion mismatch, got %v", err)
		}
	})

	t.Run("CAS binding BeforePriority mismatch", func(t *testing.T) {
		jid5 := shared.ID("promo-j5-" + randHex(t))
		j5 := judgment.Judgment{
			ID: jid5, EngagementID: eid,
			Capability:  judgment.CapPromotion,
			SubjectKind: judgment.SubjectFinding,
			SubjectID:   fid,
			Claim: &judgment.PromotionClaim{
				FindingID:      fid,
				Rule:           judgment.RuleDeterministicUnreachable,
				Inputs:         []judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "reach-5"}},
				Proposed:       judgment.PromotionDeescalate,
				Fingerprint:    fp("e"),
				FindingVersion: 1,
				BeforePriority: 2,
				AfterPriority:  3,
			},
			State: judgment.StateConfirmed,
			Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
		}
		if err := jRepo.Save(ctx, j5); err != nil {
			t.Fatalf("seed judgment 5: %v", err)
		}

		cmd := ports.PromotionCommand{
			ExpectedPriority: 2,
			ExpectedVersion:  2,
			EventID:          shared.ID("evt-" + randHex(t)),
			JudgmentID:       jid5,
			FindingVersion:   2,
			Rule:             judgment.RuleDeterministicUnreachable,
			Effect:           judgment.PromotionDeescalate,
			BeforePriority:   1, // does not match ExpectedPriority=2
			AfterPriority:    3,
			Inputs: []judgment.PromotionInput{
				{Kind: judgment.PromotionInputReachability, ID: "reach-5"},
			},
			Fingerprint:      fp("e"),
			AppliedBy:        "tester",
			VerdictRationale: "verified",
			EvidenceID:       "evidence-1",
			Verifier:         "human:verifier",
		}
		_, err := pStore.Apply(ctx, eid, fid, cmd)
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want ErrValidation for BeforePriority mismatch, got %v", err)
		}
	})

	t.Run("reversal missing prior input", func(t *testing.T) {
		jid6 := shared.ID("promo-j6-" + randHex(t))
		j6 := judgment.Judgment{
			ID: jid6, EngagementID: eid,
			Capability:  judgment.CapPromotion,
			SubjectKind: judgment.SubjectFinding,
			SubjectID:   fid,
			Claim: &judgment.PromotionClaim{
				FindingID:      fid,
				Rule:           judgment.RuleCorroboratingSignalLoss,
				Inputs:         []judgment.PromotionInput{{Kind: judgment.PromotionInputPrior, ID: "prior-for-claim"}, {Kind: judgment.PromotionInputReachability, ID: "reach-6"}},
				Proposed:       judgment.PromotionDeescalate,
				Fingerprint:    fp("6"),
				FindingVersion: 1,
				BeforePriority: 2,
				AfterPriority:  3,
			},
			State: judgment.StateConfirmed,
			Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
		}
		if err := jRepo.Save(ctx, j6); err != nil {
			t.Fatalf("seed judgment 6: %v", err)
		}

		cmd := ports.PromotionCommand{
			ExpectedPriority: 2,
			ExpectedVersion:  2,
			EventID:          shared.ID("evt-" + randHex(t)),
			JudgmentID:       jid6,
			FindingVersion:   2,
			Rule:             judgment.RuleCorroboratingSignalLoss,
			Effect:           judgment.PromotionDeescalate,
			BeforePriority:   2,
			AfterPriority:    3,
			Inputs: []judgment.PromotionInput{
				{Kind: judgment.PromotionInputReachability, ID: "reach-6"},
				// No prior_promotion input.
			},
			Fingerprint:      fp("6"),
			AppliedBy:        "tester",
			VerdictRationale: "verified",
			EvidenceID:       "evidence-1",
			Verifier:         "human:verifier",
		}
		_, err := pStore.Apply(ctx, eid, fid, cmd)
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want ErrValidation for missing prior input, got %v", err)
		}
	})

	t.Run("reversal missing prior event", func(t *testing.T) {
		jid7 := shared.ID("promo-j7-" + randHex(t))
		j7 := judgment.Judgment{
			ID: jid7, EngagementID: eid,
			Capability:  judgment.CapPromotion,
			SubjectKind: judgment.SubjectFinding,
			SubjectID:   fid,
			Claim: &judgment.PromotionClaim{
				FindingID:      fid,
				Rule:           judgment.RuleCorroboratingSignalLoss,
				Inputs:         []judgment.PromotionInput{{Kind: judgment.PromotionInputPrior, ID: "nonexistent-event"}, {Kind: judgment.PromotionInputReachability, ID: "reach-7"}},
				Proposed:       judgment.PromotionDeescalate,
				Fingerprint:    fp("7"),
				FindingVersion: 1,
				BeforePriority: 2,
				AfterPriority:  3,
			},
			State: judgment.StateConfirmed,
			Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
		}
		if err := jRepo.Save(ctx, j7); err != nil {
			t.Fatalf("seed judgment 7: %v", err)
		}

		cmd := ports.PromotionCommand{
			ExpectedPriority: 2,
			ExpectedVersion:  2,
			EventID:          shared.ID("evt-" + randHex(t)),
			JudgmentID:       jid7,
			FindingVersion:   2,
			Rule:             judgment.RuleCorroboratingSignalLoss,
			Effect:           judgment.PromotionDeescalate,
			BeforePriority:   2,
			AfterPriority:    3,
			Inputs: []judgment.PromotionInput{
				{Kind: judgment.PromotionInputReachability, ID: "reach-7"},
				{Kind: judgment.PromotionInputPrior, ID: "nonexistent-event"},
			},
			Fingerprint:      fp("7"),
			AppliedBy:        "tester",
			VerdictRationale: "verified",
			EvidenceID:       "evidence-1",
			Verifier:         "human:verifier",
		}
		_, err := pStore.Apply(ctx, eid, fid, cmd)
		if !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("want ErrNotFound for missing prior event, got %v", err)
		}
	})

	t.Run("list and latest", func(t *testing.T) {
		events, err := pStore.ListByFinding(ctx, eid, fid)
		if err != nil {
			t.Fatalf("ListByFinding: %v", err)
		}
		if len(events) < 1 {
			t.Fatalf("expected at least 1 event, got %d", len(events))
		}
		if events[0].JudgmentID != jid {
			t.Errorf("event JudgmentID = %s, want %s", events[0].JudgmentID, jid)
		}
		if events[0].VerdictScore != 80 {
			t.Errorf("event VerdictScore = %d, want 80", events[0].VerdictScore)
		}

		latest, ok, err := pStore.LatestByFinding(ctx, eid, fid)
		if err != nil || !ok {
			t.Fatalf("LatestByFinding: ok=%v err=%v", ok, err)
		}
		if latest.ID != events[len(events)-1].ID {
			t.Errorf("latest ID = %s, want %s", latest.ID, events[len(events)-1].ID)
		}
	})

	t.Run("not found", func(t *testing.T) {
		cmd := ports.PromotionCommand{
			ExpectedPriority: 3,
			ExpectedVersion:  1,
			EventID:          shared.ID("evt-" + randHex(t)),
			JudgmentID:       shared.ID("nonexistent-j"),
			FindingVersion:   1,
			Rule:             judgment.RuleRuntimeReachableExposed,
			Effect:           judgment.PromotionEscalate,
			BeforePriority:   3,
			AfterPriority:    2,
			Inputs:           []judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "j1"}},
			Fingerprint:      fp("f"),
		}
		_, err := pStore.Apply(ctx, eid, shared.ID("nonexistent-f"), cmd)
		if !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
}

// TestPromotionStoreAuditStatusLifecycle verifies that Apply creates the pending
// audit status in its transaction, and acknowledgement removes it from recovery.
func TestPromotionStoreAuditStatusLifecycle(t *testing.T) {
	fp := promotionFingerprint(t)
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := shared.WithTenant(context.Background(), "default")
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	eid := shared.ID("promo-audit-eng-" + randHex(t))
	e, err := engagement.New(eid, "", "promotion audit status", "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := NewEngagementRepository(pool).Create(ctx, e); err != nil {
		t.Fatalf("create engagement: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM findings WHERE engagement_id=$1", eid.String())
		_, _ = pool.Exec(ctx, "DELETE FROM engagements WHERE id=$1", eid.String())
	})

	fid := shared.ID("promo-audit-f-" + randHex(t))
	now := time.Now().UTC()
	jid := shared.ID("promo-audit-j-" + randHex(t))
	if err := NewFindingRepository(pool).Upsert(ctx, []finding.Finding{{
		ID: fid, EngagementID: eid, Title: "promotion audit finding",
		Severity: shared.SeverityHigh, Status: finding.StatusConfirmed,
		Kind: finding.KindSCA, Priority: 3, DedupKey: "promotion-audit:" + fid.String(),
		Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}}); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	store := mustPromotionStore(t, pool)
	cmd := ports.PromotionCommand{
		ExpectedPriority: 3, ExpectedVersion: 1,
		EventID: shared.ID("promo-audit-evt-" + randHex(t)), JudgmentID: jid,
		FindingVersion: 1, Rule: judgment.RuleRuntimeReachableExposed, Effect: judgment.PromotionEscalate,
		BeforePriority: 3, AfterPriority: 2,
		Inputs:      []judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "reach-1"}},
		Fingerprint: fp("2"), VerdictScore: 80, VerdictRationale: "verified",
		EvidenceID: "evidence-1", Verifier: "human:verifier", AppliedBy: "tester",
	}
	if err := NewJudgmentRepository(pool).Save(ctx, judgment.Judgment{
		ID: jid, EngagementID: eid, Capability: judgment.CapPromotion,
		SubjectKind: judgment.SubjectFinding, SubjectID: fid,
		Claim: &judgment.PromotionClaim{
			FindingID: fid, Rule: judgment.RuleRuntimeReachableExposed,
			Inputs:   []judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "reach-1"}},
			Proposed: judgment.PromotionEscalate, Fingerprint: cmd.Fingerprint,
			FindingVersion: 1, BeforePriority: 3, AfterPriority: 2,
		},
		State: judgment.StateConfirmed, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}); err != nil {
		t.Fatalf("seed judgment: %v", err)
	}
	if _, err := store.Apply(ctx, eid, fid, cmd); err != nil {
		t.Fatalf("apply promotion: %v", err)
	}
	pending, err := store.ListPendingAudits(ctx, eid)
	if err != nil || len(pending) != 1 || pending[0].ID != cmd.EventID {
		t.Fatalf("pending audits = %#v, %v", pending, err)
	}
	if err := store.MarkAuditComplete(ctx, cmd.EventID); err != nil {
		t.Fatalf("acknowledge audit: %v", err)
	}
	pending, err = store.ListPendingAudits(ctx, eid)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending audits after acknowledgement = %#v, %v", pending, err)
	}
}

func TestPromotionStoreFindByJudgmentUsesRLSTenant(t *testing.T) {
	fp := promotionFingerprint(t)
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := shared.WithTenant(context.Background(), "default")
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	eid := shared.ID("promo-find-eng-" + randHex(t))
	e, err := engagement.New(eid, "", "promotion find", "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := NewEngagementRepository(pool).Create(ctx, e); err != nil {
		t.Fatalf("create engagement: %v", err)
	}
	fid := shared.ID("promo-find-f-" + randHex(t))
	now := time.Now().UTC()
	if err := NewFindingRepository(pool).Upsert(ctx, []finding.Finding{{
		ID: fid, EngagementID: eid, Title: "promotion find finding",
		Severity: shared.SeverityHigh, Status: finding.StatusConfirmed,
		Kind: finding.KindSCA, Priority: 3, DedupKey: "promotion-find:" + fid.String(),
		Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}}); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM findings WHERE engagement_id=$1", eid.String())
		_, _ = pool.Exec(ctx, "DELETE FROM engagements WHERE id=$1", eid.String())
	})

	store := mustPromotionStore(t, pool)
	jid := shared.ID("promo-find-j-" + randHex(t))
	cmd := ports.PromotionCommand{
		ExpectedPriority: 3, ExpectedVersion: 1,
		EventID: shared.ID("promo-find-evt-" + randHex(t)), JudgmentID: jid,
		FindingVersion: 1, Rule: judgment.RuleRuntimeReachableExposed, Effect: judgment.PromotionEscalate,
		BeforePriority: 3, AfterPriority: 2,
		Inputs:      []judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "reach-1"}},
		Fingerprint: fp("3"), VerdictScore: 80, VerdictRationale: "verified",
		EvidenceID: "evidence-1", Verifier: "human:verifier", AppliedBy: "tester",
	}
	if err := NewJudgmentRepository(pool).Save(ctx, judgment.Judgment{
		ID: jid, EngagementID: eid, Capability: judgment.CapPromotion,
		SubjectKind: judgment.SubjectFinding, SubjectID: fid,
		Claim: &judgment.PromotionClaim{
			FindingID: fid, Rule: judgment.RuleRuntimeReachableExposed,
			Inputs:   []judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "reach-1"}},
			Proposed: judgment.PromotionEscalate, Fingerprint: cmd.Fingerprint,
			FindingVersion: 1, BeforePriority: 3, AfterPriority: 2,
		},
		State: judgment.StateConfirmed, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}); err != nil {
		t.Fatalf("seed judgment: %v", err)
	}
	if _, err := store.Apply(ctx, eid, fid, cmd); err != nil {
		t.Fatalf("apply promotion: %v", err)
	}

	if _, ok, err := store.FindByJudgment(ctx, eid, fid, jid); err != nil || !ok {
		t.Fatalf("same-tenant recovery lookup = ok:%t err:%v", ok, err)
	}
	otherTenantID := shared.ID("promo-find-tenant-b-" + randHex(t))
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $1)`, otherTenantID.String()); err != nil {
		t.Fatalf("seed tenant B: %v", err)
	}
	// uniqueProbeRole owns the drop and opens its own connection for it, so it survives this
	// test's deferred pool close.
	role := uniqueProbeRole(t, dsn, "promo_find_rls")
	for _, query := range []string{
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT ON finding_promotion_events TO ` + role,
	} {
		if _, err := pool.Exec(ctx, query); err != nil {
			t.Fatalf("create RLS test role: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, otherTenantID.String())
	})
	otherCtx := shared.WithTenant(context.Background(), otherTenantID)
	if err := WithContextTenant(otherCtx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(otherCtx, `SET LOCAL ROLE `+role); err != nil {
			return err
		}
		var visible int
		if err := tx.QueryRow(otherCtx, `SELECT COUNT(*) FROM finding_promotion_events WHERE judgment_id = $1`, jid.String()).Scan(&visible); err != nil {
			return err
		}
		if visible != 0 {
			t.Fatalf("tenant B sees %d tenant A promotion events", visible)
		}
		return nil
	}); err != nil {
		t.Fatalf("cross-tenant RLS lookup: %v", err)
	}
}

// promotionFingerprint returns a fingerprint generator whose values are unique to this test run.
//
// A promotion fingerprint is unique for the life of the database: the store refuses to apply one
// that another judgment already used. Fixed fingerprints therefore made these tests pass only
// against a database they had never run on, so a second run, or `go test -count=2`, failed with a
// conflict that had nothing to do with what was under test. The value stays a 64-character
// lowercase hex digest, which the domain validates.
func promotionFingerprint(t *testing.T) func(seed string) string {
	t.Helper()
	run := randHex(t)
	return func(seed string) string { return strings.Repeat(seed, 64-len(run)) + run }
}
