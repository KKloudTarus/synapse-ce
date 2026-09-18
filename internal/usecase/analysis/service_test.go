package analysis

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// --- in-package fakes (no infra import from a use-case test) ---

type fakeStore struct {
	saved   []judgment.Judgment
	pending []ports.PendingJudgmentAudit
}

func (f *fakeStore) Save(_ context.Context, j judgment.Judgment) error {
	for i := range f.saved {
		if f.saved[i].ID == j.ID {
			f.saved[i] = j
			return nil
		}
	}
	f.saved = append(f.saved, j)
	return nil
}
func (f *fakeStore) ListByEngagement(_ context.Context, eng shared.ID) ([]judgment.Judgment, error) {
	var out []judgment.Judgment
	for _, j := range f.saved {
		if j.EngagementID == eng {
			out = append(out, j)
		}
	}
	return out, nil
}
func (f *fakeStore) ListBySubject(_ context.Context, eng, subject shared.ID) ([]judgment.Judgment, error) {
	var out []judgment.Judgment
	for _, j := range f.saved {
		if j.EngagementID == eng && j.SubjectID == subject {
			out = append(out, j)
		}
	}
	return out, nil
}
func (f *fakeStore) SetScoreState(_ context.Context, _, id shared.ID, score int, state judgment.State, expectedVersion int) (judgment.Judgment, error) {
	for i := range f.saved {
		if f.saved[i].ID == id {
			if f.saved[i].Version != expectedVersion {
				return judgment.Judgment{}, shared.ErrConflict
			}
			f.saved[i].EvidenceScore = score
			f.saved[i].State = state
			f.saved[i].Version++
			return f.saved[i], nil
		}
	}
	return judgment.Judgment{}, shared.ErrNotFound
}
func (f *fakeStore) SetVerdictState(_ context.Context, _, id shared.ID, score int, state judgment.State, verifiedBy, verdictRationale string, expectedVersion int) (judgment.Judgment, error) {
	for i := range f.saved {
		if f.saved[i].ID == id {
			if f.saved[i].Version != expectedVersion {
				return judgment.Judgment{}, shared.ErrConflict
			}
			f.saved[i].EvidenceScore = score
			f.saved[i].State = state
			f.saved[i].VerifiedBy = verifiedBy
			f.saved[i].VerdictRationale = verdictRationale
			f.saved[i].Version++
			return f.saved[i], nil
		}
	}
	return judgment.Judgment{}, shared.ErrNotFound
}

func (f *fakeStore) SaveWithProposalAudit(_ context.Context, j judgment.Judgment, entry ports.AuditEntry) error {
	if err := f.Save(context.Background(), j); err != nil {
		return err
	}
	f.pending = append(f.pending, ports.PendingJudgmentAudit{Kind: ports.JudgmentProposalAudit, JudgmentID: j.ID, Version: j.Version, EngagementID: j.EngagementID, Entry: entry})
	return nil
}
func (f *fakeStore) SetVerdictStateWithAudit(_ context.Context, eng, id shared.ID, score int, state judgment.State, by, rationale string, expectedVersion int, entry ports.AuditEntry) (judgment.Judgment, error) {
	j, err := f.SetVerdictState(context.Background(), eng, id, score, state, by, rationale, expectedVersion)
	if err != nil {
		return judgment.Judgment{}, err
	}
	f.pending = append(f.pending, ports.PendingJudgmentAudit{Kind: ports.JudgmentVerdictAudit, JudgmentID: id, Version: j.Version, EngagementID: eng, Entry: entry})
	return j, nil
}
func (f *fakeStore) ListPendingJudgmentAudits(_ context.Context, eng shared.ID) ([]ports.PendingJudgmentAudit, error) {
	var out []ports.PendingJudgmentAudit
	for _, p := range f.pending {
		if p.EngagementID == eng {
			out = append(out, p)
		}
	}
	return out, nil
}
func (f *fakeStore) AcknowledgeJudgmentAudit(_ context.Context, kind ports.JudgmentAuditKind, id shared.ID, version int) error {
	for i, p := range f.pending {
		if p.Kind == kind && p.JudgmentID == id && p.Version == version {
			f.pending = append(f.pending[:i], f.pending[i+1:]...)
			return nil
		}
	}
	return nil
}

type fakeSealer struct {
	kinds []string
	err   error
}

func (f *fakeSealer) Seal(_ context.Context, _ shared.ID, kind string, _ []byte, _ string) (evidence.Evidence, error) {
	if f.err != nil {
		return evidence.Evidence{}, f.err
	}
	f.kinds = append(f.kinds, kind)
	return evidence.Evidence{}, nil
}

type fakeAudit struct {
	actions []string
	fail    bool
	once    int
}

func (f *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	f.actions = append(f.actions, e.Action)
	return nil
}
func (f *fakeAudit) RecordOnce(ctx context.Context, e ports.AuditEntry) error {
	f.once++
	if f.fail {
		return errors.New("audit unavailable")
	}
	return f.Record(ctx, e)
}

type fakePromotionRecorder struct {
	attempts int
	calls    []judgment.Judgment
	err      error
	check    func(j judgment.Judgment) error
}

func (f *fakePromotionRecorder) RecordConfirmed(_ context.Context, j judgment.Judgment) error {
	f.attempts++
	if f.check != nil {
		if err := f.check(j); err != nil {
			return err
		}
	}
	if f.err != nil {
		err := f.err
		f.err = nil
		return err
	}
	f.calls = append(f.calls, j)
	return nil
}

type fakeClock struct{}

func (fakeClock) Now() time.Time { return time.Unix(0, 0).UTC() }

type fakeIDs struct{ n int }

func (f *fakeIDs) NewID() shared.ID { f.n++; return shared.ID(fmt.Sprintf("j%d", f.n)) }

func newSvc() (*Service, *fakeStore, *fakeSealer, *fakeAudit) {
	store, sealer, audit := &fakeStore{}, &fakeSealer{}, &fakeAudit{}
	svc, err := NewService(store, sealer, audit, fakeClock{}, &fakeIDs{})
	if err != nil {
		panic(err)
	}
	return svc, store, sealer, audit
}

func reach() judgment.Claim {
	return judgment.ReachabilityClaim{Reachable: "not_reachable", Tier: "tier-1.5", Confidence: 90}
}
func narr() judgment.Claim {
	return judgment.RiskNarrativeClaim{Drivers: []string{"kev"}, Priority: 1}
}

func promo() judgment.Claim {
	return judgment.PromotionClaim{
		FindingID: "f1",
		Rule:      judgment.RuleRuntimeReachableExposed,
		Inputs: []judgment.PromotionInput{
			{Kind: judgment.PromotionInputAttackPath, ID: "path1"},
			{Kind: judgment.PromotionInputDetection, ID: "det1"},
			{Kind: judgment.PromotionInputReachability, ID: "reach1"},
		},
		Proposed:       judgment.PromotionEscalate,
		Fingerprint:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		FindingVersion: 1,
		BeforePriority: 3,
		AfterPriority:  2,
	}
}

func TestProposeRecordsAtScoreZero(t *testing.T) {
	svc, store, sealer, audit := newSvc()
	j, err := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapReachability, judgment.SubjectFinding, "f1", reach())
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if j.State != judgment.StateProposed || j.EvidenceScore != 0 {
		t.Fatalf("want proposed/0, got %s/%d", j.State, j.EvidenceScore)
	}
	if len(store.saved) != 1 {
		t.Fatalf("want 1 saved, got %d", len(store.saved))
	}
	if len(sealer.kinds) != 1 || sealer.kinds[0] != ProposedEvidenceKind {
		t.Fatalf("want proposed seal, got %v", sealer.kinds)
	}
	if len(audit.actions) != 1 || audit.actions[0] != "judgment.proposed" {
		t.Fatalf("want proposed audit, got %v", audit.actions)
	}
	if _, err := svc.Propose(context.Background(), "", "e1", judgment.CapReachability, judgment.SubjectFinding, "f1", reach()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty proposer: want ErrValidation, got %v", err)
	}
	if _, err := svc.Propose(context.Background(), "agent:s1", "", judgment.CapReachability, judgment.SubjectFinding, "f1", reach()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty engagement: want ErrValidation, got %v", err)
	}
}

func TestVerifyConfirmsSealFirst(t *testing.T) {
	svc, store, sealer, _ := newSvc()
	j, _ := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapReachability, judgment.SubjectFinding, "f1", reach())

	got, err := svc.Verify(context.Background(), "human:bob", "e1", j.ID, 80, "holds", j.Version)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.State != judgment.StateConfirmed || got.EvidenceScore != 80 || !got.Publishable() {
		t.Fatalf("want confirmed/80/publishable, got %s/%d/%v", got.State, got.EvidenceScore, got.Publishable())
	}
	if got.VerifiedBy != "human:bob" || got.VerdictRationale != "holds" || store.saved[0].VerifiedBy != "human:bob" || store.saved[0].VerdictRationale != "holds" {
		t.Fatalf("sealed verdict provenance was not persisted: got=%#v stored=%#v", got, store.saved[0])
	}
	// seal order: proposed BEFORE verdict
	if len(sealer.kinds) != 2 || sealer.kinds[0] != ProposedEvidenceKind || sealer.kinds[1] != VerdictEvidenceKind {
		t.Fatalf("seal order wrong: %v", sealer.kinds)
	}
	_ = store
}

func TestVerifyFailClosedOnSealError(t *testing.T) {
	svc, store, sealer, _ := newSvc()
	j, _ := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapReachability, judgment.SubjectFinding, "f1", reach())
	sealer.err = errors.New("evidence chain down") // verdict seal will fail

	if _, err := svc.Verify(context.Background(), "human:bob", "e1", j.ID, 80, "holds", j.Version); err == nil {
		t.Fatal("want error when verdict seal fails")
	}
	// fail-closed: score/state NOT moved because the seal failed before SetScoreState
	if store.saved[0].State != judgment.StateProposed || store.saved[0].EvidenceScore != 0 {
		t.Fatalf("score moved despite seal failure: %s/%d", store.saved[0].State, store.saved[0].EvidenceScore)
	}
}

func TestVerifyRejectsSelfConfirmAndUngated(t *testing.T) {
	svc, store, sealer, _ := newSvc()
	j, _ := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapReachability, judgment.SubjectFinding, "f1", reach())
	beforeSeals := len(sealer.kinds)

	// proposer == verifier
	if _, err := svc.Verify(context.Background(), "agent:s1", "e1", j.ID, 90, "x", j.Version); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("self-confirm: want ErrValidation, got %v", err)
	}
	// no verdict seal written, score unchanged
	if len(sealer.kinds) != beforeSeals || store.saved[0].EvidenceScore != 0 {
		t.Fatal("self-confirm leaked a seal or moved the score")
	}

	// ungated capability cannot take a verdict
	jn, _ := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapRiskNarrative, judgment.SubjectFinding, "f2", narr())
	if _, err := svc.Verify(context.Background(), "human:bob", "e1", jn.ID, 90, "x", jn.Version); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("ungated verify: want ErrValidation, got %v", err)
	}
}

func TestAcceptUngatedDoesNotSetVerdictProvenance(t *testing.T) {
	svc, store, _, _ := newSvc()
	jn, err := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapRiskNarrative, judgment.SubjectFinding, "f1", narr())
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.Accept(context.Background(), "human:bob", "e1", jn.ID, jn.Version)
	if err != nil {
		t.Fatal(err)
	}
	if got.VerifiedBy != "" || got.VerdictRationale != "" || store.saved[0].VerifiedBy != "" || store.saved[0].VerdictRationale != "" {
		t.Fatalf("accept fabricated verdict provenance: got=%#v stored=%#v", got, store.saved[0])
	}
}

func TestAcceptUngated(t *testing.T) {
	svc, _, _, audit := newSvc()
	jn, _ := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapRiskNarrative, judgment.SubjectFinding, "f1", narr())
	got, err := svc.Accept(context.Background(), "human:bob", "e1", jn.ID, jn.Version)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got.State != judgment.StateConfirmed || !got.Publishable() {
		t.Fatalf("want confirmed/publishable, got %s/%v", got.State, got.Publishable())
	}
	if audit.actions[len(audit.actions)-1] != "judgment.accepted" {
		t.Fatalf("want accepted audit, got %v", audit.actions)
	}
	// self-accept rejected
	jn2, _ := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapRiskNarrative, judgment.SubjectFinding, "f3", narr())
	if _, err := svc.Accept(context.Background(), "agent:s1", "e1", jn2.ID, jn2.Version); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("self-accept: want ErrValidation, got %v", err)
	}
}

func TestVerifyConflict(t *testing.T) {
	svc, _, _, _ := newSvc()
	j, _ := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapReachability, judgment.SubjectFinding, "f1", reach())
	// wrong expectedVersion → conflict (seal still happens; orphan acceptable by design)
	if _, err := svc.Verify(context.Background(), "human:bob", "e1", j.ID, 80, "holds", j.Version+1); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
}

func TestVerifyPromotionRecordsAfterSealedVerdict(t *testing.T) {
	svc, store, sealer, audit := newSvc()
	rec := &fakePromotionRecorder{check: func(j judgment.Judgment) error {
		if j.State != judgment.StateConfirmed || !j.Publishable() || j.VerifiedBy != "human:bob" || j.VerdictRationale != "holds" {
			return fmt.Errorf("recorder saw unsealed judgment: %#v", j)
		}
		if store.saved[0].State != judgment.StateConfirmed || store.saved[0].VerifiedBy != "human:bob" || store.saved[0].VerdictRationale != "holds" {
			return fmt.Errorf("recorder ran before verdict persistence: %#v", store.saved[0])
		}
		if len(sealer.kinds) != 2 || sealer.kinds[0] != ProposedEvidenceKind || sealer.kinds[1] != VerdictEvidenceKind {
			return fmt.Errorf("recorder ran before verdict seal: %v", sealer.kinds)
		}
		if audit.actions[len(audit.actions)-1] != "judgment.verdict" {
			return fmt.Errorf("recorder ran before verdict audit: %v", audit.actions)
		}
		return nil
	}}
	svc.SetPromotionRecorder(rec)
	j, err := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapPromotion, judgment.SubjectFinding, "f1", promo())
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.Verify(context.Background(), "human:bob", "e1", j.ID, 75, "holds", j.Version)
	if err != nil {
		t.Fatalf("Verify promotion: %v", err)
	}
	if got.Capability != judgment.CapPromotion || got.State != judgment.StateConfirmed {
		t.Fatalf("promotion verdict not confirmed: %#v", got)
	}
	if rec.attempts != 1 || len(rec.calls) != 1 {
		t.Fatalf("promotion recorder calls = attempts %d stored %d", rec.attempts, len(rec.calls))
	}
}

func TestVerifyPromotionReturnsRecorderErrorAndRetriesConfirmed(t *testing.T) {
	svc, store, _, _ := newSvc()
	rec := &fakePromotionRecorder{err: errors.New("apply promotion down")}
	svc.SetPromotionRecorder(rec)
	j, err := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapPromotion, judgment.SubjectFinding, "f1", promo())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(context.Background(), "human:bob", "e1", j.ID, 75, "holds", j.Version); err == nil {
		t.Fatal("promotion recorder failure must be returned")
	}
	if store.saved[0].State != judgment.StateConfirmed || store.saved[0].Version != 2 {
		t.Fatalf("judgment not persisted for retry: %#v", store.saved[0])
	}
	got, err := svc.Verify(context.Background(), "human:bob", "e1", j.ID, 75, "holds", store.saved[0].Version)
	if err != nil {
		t.Fatalf("retry confirmed promotion: %v", err)
	}
	if got.Version != store.saved[0].Version || rec.attempts != 2 || len(rec.calls) != 1 {
		t.Fatalf("retry state wrong: got version %d store version %d attempts %d calls %d", got.Version, store.saved[0].Version, rec.attempts, len(rec.calls))
	}
}

func TestVerifyPromotionRejectsMissingRecorder(t *testing.T) {
	svc, store, _, _ := newSvc()
	j, err := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapPromotion, judgment.SubjectFinding, "f1", promo())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(context.Background(), "human:bob", "e1", j.ID, 75, "holds", j.Version); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing promotion recorder: want ErrValidation, got %v", err)
	}
	if store.saved[0].State != judgment.StateConfirmed {
		t.Fatalf("verdict should remain retryable after projection config error: %#v", store.saved[0])
	}
}

func TestGovernanceReconcilerDeliversPendingAuditOnce(t *testing.T) {
	store, sealer, audit := &fakeStore{}, &fakeSealer{}, &fakeAudit{fail: true}
	svc, err := NewService(store, sealer, audit, fakeClock{}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapReachability, judgment.SubjectFinding, "f1", reach()); err == nil {
		t.Fatal("proposal must surface failed durable audit delivery")
	}
	if len(store.pending) != 1 {
		t.Fatalf("pending audits = %d, want 1", len(store.pending))
	}
	audit.fail = false
	reconciler, err := NewGovernanceReconciler(store, audit)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Reconcile(context.Background(), "e1"); err != nil {
		t.Fatal(err)
	}
	if len(store.pending) != 0 || audit.once != 2 {
		t.Fatalf("reconciliation pending=%d attempts=%d", len(store.pending), audit.once)
	}
}

func TestPromotionWaitsForDurableVerdictAudit(t *testing.T) {
	svc, store, _, audit := newSvc()
	audit.fail = true
	recorder := &fakePromotionRecorder{}
	svc.SetPromotionRecorder(recorder)
	j, err := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapPromotion, judgment.SubjectFinding, "f1", promo())
	if err == nil {
		t.Fatal("proposal audit must fail")
	}
	audit.fail = false
	if err := svc.deliverPendingForJudgment(context.Background(), "e1", j.ID); err != nil {
		t.Fatal(err)
	}
	j = store.saved[0]
	audit.fail = true
	if _, err := svc.Verify(context.Background(), "human:bob", "e1", j.ID, 75, "holds", j.Version); err == nil {
		t.Fatal("verdict audit must fail")
	}
	if recorder.attempts != 0 {
		t.Fatalf("promotion applied before durable verdict audit: %d", recorder.attempts)
	}
}
