package aitriagereviewuc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aitriagereview"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type seqIDs struct{ n int }

func (s *seqIDs) NewID() shared.ID { s.n++; return shared.ID("id-" + string(rune('0'+s.n))) }

type auditFake struct{ entries []ports.AuditEntry }

func (a *auditFake) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

type findingDecisionFake struct {
	accepted bool
	calls    int
}

type decisionFailStore struct {
	*memory.AITriageReviewStore
	fail bool
}

func (s *decisionFailStore) SaveDecision(ctx context.Context, review aitriagereview.Review, expectedVersion int) error {
	if s.fail {
		return errors.New("decision store unavailable")
	}
	return s.AITriageReviewStore.SaveDecision(ctx, review, expectedVersion)
}

func (f *findingDecisionFake) ApplyAITriageReview(_ context.Context, _ string, _, _ shared.ID, accepted bool, _ string) error {
	f.accepted = accepted
	f.calls++
	return nil
}

func TestAcceptNeverExemptsBeforeDecisionIsDurable(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(100, 0).UTC()
	engagements := memory.NewEngagementRepository()
	e, err := engagement.New("e1", shared.DefaultTenant, "Project context", "client", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := engagements.Create(ctx, e); err != nil {
		t.Fatal(err)
	}
	store := &decisionFailStore{AITriageReviewStore: memory.NewAITriageReviewStore()}
	decisions := &findingDecisionFake{}
	svc, err := NewService(store, engagements, decisions, &auditFake{}, fixedClock{now}, &seqIDs{})
	if err != nil {
		t.Fatal(err)
	}
	item := finding.Finding{ID: "f1", EngagementID: "e1", DedupKey: "sast:key", Title: "SQL injection", Severity: shared.SeverityHigh, Kind: finding.KindSAST, Status: finding.StatusOpen}
	critique := ports.AICritique{DedupKey: item.DedupKey, Verdict: "refuted", Driver: "sanitizer", Confidence: 90, SuspectedFP: true, ProposerModel: "model-a", PromptVersion: "fp-triage-v1", PolicyVersion: "fp-gate-v3", PolicyReason: "severity_requires_human", ReviewRequired: true}
	if err := svc.RecordScan(ctx, e.ID, "ev1", []finding.Finding{item}, []ports.AICritique{critique}); err != nil {
		t.Fatal(err)
	}
	queue, err := svc.List(ctx, shared.DefaultTenant, ports.AITriageReviewFilter{})
	if err != nil || len(queue) != 1 {
		t.Fatalf("queue=%+v err=%v", queue, err)
	}
	claimed, err := svc.Claim(ctx, shared.DefaultTenant, queue[0].ID, "reviewer", queue[0].Version)
	if err != nil {
		t.Fatal(err)
	}
	store.fail = true
	if _, err := svc.Decide(ctx, shared.DefaultTenant, claimed.ID, "reviewer", aitriagereview.DecisionAccept, "fixture is unreachable", claimed.Version); err == nil {
		t.Fatal("accept should fail when the durable decision cannot be written")
	}
	if decisions.calls != 0 {
		t.Fatalf("finding was exempted before durable decision: calls=%d", decisions.calls)
	}
}

func TestRecordAndDecideReview(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(100, 0).UTC()
	engagements := memory.NewEngagementRepository()
	e, err := engagement.New("e1", shared.DefaultTenant, "Project context", "client", now)
	if err != nil {
		t.Fatal(err)
	}
	e.ProjectID = "p1"
	if err := engagements.Create(ctx, e); err != nil {
		t.Fatal(err)
	}
	store := memory.NewAITriageReviewStore()
	audit := &auditFake{}
	decisions := &findingDecisionFake{}
	ids := &seqIDs{}
	svc, err := NewService(store, engagements, decisions, audit, fixedClock{now}, ids)
	if err != nil {
		t.Fatal(err)
	}
	item := finding.Finding{ID: "f1", EngagementID: "e1", DedupKey: "sast:key", Title: "SQL injection", Severity: shared.SeverityHigh, Kind: finding.KindSAST, Status: finding.StatusOpen}
	critique := ports.AICritique{FindingID: "f1", DedupKey: "sast:key", Verdict: "refuted", Driver: "sanitizer", Confidence: 90, SuspectedFP: true,
		ProposerModel: "model-a", ProposerProvider: "openai", ProposerModelFamily: "model-a",
		VerifierModel: "model-b", VerifierProvider: "anthropic", VerifierModelFamily: "model-b",
		IndependencePolicy: ports.AIIndependenceProvider, PromptVersion: "fp-triage-v2", PolicyVersion: "fp-gate-v4",
		PolicyReason: "severity_requires_human", ReviewRequired: true}
	if err := svc.RecordScan(ctx, "e1", "ev1", []finding.Finding{item}, []ports.AICritique{critique}); err != nil {
		t.Fatal(err)
	}
	queue, err := svc.List(ctx, "", ports.AITriageReviewFilter{State: aitriagereview.StatePending})
	if err != nil || len(queue) != 1 {
		t.Fatalf("queue=%+v err=%v", queue, err)
	}
	claimed, err := svc.Claim(ctx, "", queue[0].ID, "reviewer", queue[0].Version)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RecordScan(ctx, "e1", "ev2", []finding.Finding{item}, []ports.AICritique{critique}); err != nil {
		t.Fatal(err)
	}
	queue, err = svc.List(ctx, "", ports.AITriageReviewFilter{State: aitriagereview.StatePending})
	if err != nil || len(queue) != 1 || queue[0].Owner != "reviewer" || queue[0].EvidenceRef != "ev2" || queue[0].Version != claimed.Version+1 {
		t.Fatalf("rescan must preserve owner, refresh evidence, and invalidate stale versions: queue=%+v err=%v", queue, err)
	}
	updated, err := svc.Decide(ctx, "", queue[0].ID, "reviewer", aitriagereview.DecisionReject, "this path is reachable", queue[0].Version)
	if err != nil {
		t.Fatal(err)
	}
	if updated.State != aitriagereview.StateRejected || decisions.accepted || decisions.calls != 1 {
		t.Fatalf("decision not applied: %+v fake=%+v", updated, decisions)
	}
	if len(audit.entries) != 2 || audit.entries[1].Metadata["evidence_ref"] != "ev2" || audit.entries[1].Metadata["prompt_version"] != "fp-triage-v2" ||
		audit.entries[1].Metadata["proposer_provider"] != "openai" || audit.entries[1].Metadata["verifier_provider"] != "anthropic" ||
		audit.entries[1].Metadata["independence_policy"] != "provider" {
		t.Fatalf("decision audit missing evidence: %+v", audit.entries)
	}

	// A provider/policy change is a new recommendation identity. A terminal review of the old pair
	// must not swallow it, even when finding, prompt, raw models, and gate-policy version are unchanged.
	critique.VerifierProvider = "bedrock"
	if err := svc.RecordScan(ctx, "e1", "ev3", []finding.Finding{item}, []ports.AICritique{critique}); err != nil {
		t.Fatal(err)
	}
	pending, err := svc.List(ctx, "", ports.AITriageReviewFilter{State: aitriagereview.StatePending})
	if err != nil || len(pending) != 1 || pending[0].VerifierProvider != "bedrock" {
		t.Fatalf("new provider identity must create a fresh pending review: pending=%+v err=%v", pending, err)
	}
}
