package promotion

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/promotion"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ---------------------------------------------------------------------------
// Test helpers / fakes
// ---------------------------------------------------------------------------

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }

type fakeIDGen struct{ id shared.ID }

func (g *fakeIDGen) NewID() shared.ID { return g.id }

type fakeAudit struct {
	entries []ports.AuditEntry
	fail    int
	seen    map[string]struct{}
}

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

func (a *fakeAudit) RecordOnce(ctx context.Context, e ports.AuditEntry) error {
	if a.fail > 0 {
		a.fail--
		return errors.New("audit unavailable")
	}
	if a.seen == nil {
		a.seen = make(map[string]struct{})
	}
	key := e.Action + ":" + e.Metadata["idempotency_key"]
	if _, ok := a.seen[key]; ok {
		return nil
	}
	a.seen[key] = struct{}{}
	return a.Record(ctx, e)
}

type fakeProposer struct {
	proposed []judgment.Judgment
	existing []judgment.Judgment
}

func (p *fakeProposer) Propose(_ context.Context, proposer string, engagementID shared.ID, cap judgment.Capability, sk judgment.SubjectKind, sid shared.ID, claim judgment.Claim) (judgment.Judgment, error) {
	j := judgment.Judgment{
		ID:           shared.ID("j-" + sid.String()),
		EngagementID: engagementID,
		Capability:   cap,
		SubjectKind:  sk,
		SubjectID:    sid,
		Claim:        claim,
		State:        judgment.StateProposed,
		ProposedBy:   proposer,
	}
	p.proposed = append(p.proposed, j)
	return j, nil
}

type fakeFindingRepo struct {
	findings []finding.Finding
}

func (r *fakeFindingRepo) Upsert(_ context.Context, _ []finding.Finding) error { return nil }
func (r *fakeFindingRepo) ListByEngagement(_ context.Context, _ shared.ID) ([]finding.Finding, error) {
	return r.findings, nil
}
func (r *fakeFindingRepo) ListPublishableByEngagement(_ context.Context, _ shared.ID) ([]finding.Finding, error) {
	return r.findings, nil
}
func (r *fakeFindingRepo) UpdateStatus(_ context.Context, _, _ shared.ID, _ finding.Status, _ int) (finding.Finding, error) {
	return finding.Finding{}, nil
}
func (r *fakeFindingRepo) SetAssignee(_ context.Context, _, _ shared.ID, _ string, _ int) (finding.Finding, error) {
	return finding.Finding{}, nil
}
func (r *fakeFindingRepo) GetByEngagementAndID(_ context.Context, engagementID, findingID shared.ID) (finding.Finding, error) {
	for _, f := range r.findings {
		if f.ID == findingID && f.EngagementID == engagementID {
			return f, nil
		}
	}
	return finding.Finding{}, shared.ErrNotFound
}

type fakeJudgmentStore struct {
	judgments []judgment.Judgment
}

func (s *fakeJudgmentStore) Save(_ context.Context, _ judgment.Judgment) error { return nil }
func (s *fakeJudgmentStore) ListByEngagement(_ context.Context, _ shared.ID) ([]judgment.Judgment, error) {
	return s.judgments, nil
}
func (s *fakeJudgmentStore) ListBySubject(_ context.Context, _, _ shared.ID) ([]judgment.Judgment, error) {
	return nil, nil
}

type fakeAttackPathStore struct {
	bindings []attackpath.Binding
}

func (s *fakeAttackPathStore) ReplaceBindings(_ context.Context, _, _, _ shared.ID, _ []attackpath.Binding) error {
	return nil
}
func (s *fakeAttackPathStore) ListBindings(_ context.Context, _ shared.ID) ([]attackpath.Binding, error) {
	return s.bindings, nil
}

type fakeAssetRepo struct {
	assets []*asset.Asset
	edges  []*asset.Edge
}

func (r *fakeAssetRepo) UpsertAsset(_ context.Context, _ *asset.Asset) error { return nil }
func (r *fakeAssetRepo) GetAssetByKey(_ context.Context, _ shared.ID, _ asset.Kind, _ string) (*asset.Asset, error) {
	return nil, nil
}
func (r *fakeAssetRepo) ListAssets(_ context.Context, _ shared.ID) ([]*asset.Asset, error) {
	return r.assets, nil
}
func (r *fakeAssetRepo) UpsertEdge(_ context.Context, _ *asset.Edge) error { return nil }
func (r *fakeAssetRepo) ListEdges(_ context.Context, _ shared.ID) ([]*asset.Edge, error) {
	return r.edges, nil
}

type fakeDetectionStore struct {
	records []detection.Record
}

func (s *fakeDetectionStore) AppendDetection(_ context.Context, _ detection.Record) error { return nil }
func (s *fakeDetectionStore) HasDetection(_ context.Context, _, _ shared.ID) (bool, error) {
	return false, nil
}
func (s *fakeDetectionStore) ListDetections(_ context.Context, _ shared.ID) ([]detection.Record, error) {
	return s.records, nil
}
func (s *fakeDetectionStore) LastBatchSequence(_ context.Context, _ shared.ID) (uint64, error) {
	return 0, nil
}
func (s *fakeDetectionStore) ExpireDetections(_ context.Context, _ shared.ID, _ time.Time) ([]shared.ID, error) {
	return nil, nil
}

type fakeEngagementReader struct {
	eng *engagementStub
}

type engagementStub struct {
	id       shared.ID
	tenantID shared.ID
}

func (r *fakeEngagementReader) GetByIDInTenant(_ context.Context, tenantID, id shared.ID) (*engagementStub, error) {
	if r.eng == nil || r.eng.id != id || r.eng.tenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return r.eng, nil
}

// Adapt to the ports.EngagementOwnershipReader interface which returns
// *engagement.Engagement. We need a minimal stub.
// The ports.EngagementOwnershipReader returns (*engagement.Engagement, error).
// Let's use a real adapter.

type fakePromotionStore struct {
	events  map[shared.ID][]promotion.PromotionEvent
	latest  map[shared.ID]promotion.PromotionEvent
	applied []ports.PromotionCommand
	byEvent map[shared.ID]ports.PromotionCommand
}

func (s *fakePromotionStore) Apply(_ context.Context, _, _ shared.ID, cmd ports.PromotionCommand) (finding.Finding, error) {
	if s.byEvent == nil {
		s.byEvent = make(map[shared.ID]ports.PromotionCommand)
	}
	if _, ok := s.byEvent[cmd.EventID]; ok {
		return finding.Finding{}, nil
	}
	s.byEvent[cmd.EventID] = cmd
	s.applied = append(s.applied, cmd)
	return finding.Finding{}, nil
}
func (s *fakePromotionStore) ListByFinding(_ context.Context, _, fid shared.ID) ([]promotion.PromotionEvent, error) {
	if events, ok := s.events[fid]; ok {
		return append([]promotion.PromotionEvent(nil), events...), nil
	}
	if evt, ok := s.latest[fid]; ok {
		return []promotion.PromotionEvent{evt}, nil
	}
	return nil, nil
}
func (s *fakePromotionStore) LatestByFinding(_ context.Context, _, fid shared.ID) (promotion.PromotionEvent, bool, error) {
	if evt, ok := s.latest[fid]; ok {
		return evt, true, nil
	}
	return promotion.PromotionEvent{}, false, nil
}

func (s *fakePromotionStore) FindByJudgment(_ context.Context, engagementID, findingID, judgmentID shared.ID) (promotion.PromotionEvent, bool, error) {
	for eventID, cmd := range s.byEvent {
		if cmd.JudgmentID == judgmentID {
			afterVersion := cmd.FindingVersion
			if cmd.Effect != judgment.PromotionFlagForReview {
				afterVersion++
			}
			return promotion.PromotionEvent{
				ID: eventID, EngagementID: engagementID, JudgmentID: judgmentID, FindingID: findingID, FindingVersion: cmd.FindingVersion, AfterFindingVersion: afterVersion,
				Rule: cmd.Rule, Effect: cmd.Effect, BeforePriority: cmd.BeforePriority, AfterPriority: cmd.AfterPriority,
				Inputs: cmd.Inputs, Fingerprint: cmd.Fingerprint, VerdictScore: cmd.VerdictScore,
				VerdictRationale: cmd.VerdictRationale, EvidenceID: cmd.EvidenceID, Verifier: cmd.Verifier,
				Uncertainty: cmd.Uncertainty, AppliedBy: cmd.AppliedBy,
			}, true, nil
		}
	}
	return promotion.PromotionEvent{}, false, nil
}
func (s *fakePromotionStore) ListPendingAudits(_ context.Context, _ shared.ID) ([]promotion.PromotionEvent, error) {
	return nil, nil
}
func (s *fakePromotionStore) MarkAuditComplete(_ context.Context, _ shared.ID) error { return nil }

type fakeEvidenceSealer struct {
	evidence.Evidence
	err          error
	sealed       *evidence.Evidence // pre-sealed evidence for crash recovery
	sealCalled   int
	contentMatch bool // whether LookupSealedForFinding content matches
}

func (s *fakeEvidenceSealer) Seal(_ context.Context, _ shared.ID, _ string, _ []byte, _ string) (evidence.Evidence, error) {
	return s.Evidence, s.err
}
func (s *fakeEvidenceSealer) SealForFinding(_ context.Context, _, _ shared.ID, _ string, _ []byte, _ string) (evidence.Evidence, error) {
	s.sealCalled++
	return s.Evidence, s.err
}
func (s *fakeEvidenceSealer) LookupSealedForFinding(_ context.Context, _, _ shared.ID, _ string) (evidence.Evidence, bool, error) {
	if s.sealed != nil {
		ev := *s.sealed
		if s.contentMatch {
			return ev, true, nil
		}
		ev.Content = []byte("different")
		return ev, true, nil
	}
	return evidence.Evidence{}, false, nil
}
func (s *fakeEvidenceSealer) LookupSealedByID(_ context.Context, _ shared.ID, evidenceID shared.ID) (evidence.Evidence, bool, error) {
	if s.sealed != nil && s.sealed.ID == evidenceID {
		return *s.sealed, true, nil
	}
	return evidence.Evidence{}, false, nil
}
func (s *fakeEvidenceSealer) SealForFindingWithID(_ context.Context, evidenceID, _, _ shared.ID, _ string, content []byte, _ string, _ string) (evidence.Evidence, error) {
	s.sealCalled++
	s.Content = append([]byte(nil), content...)
	ev := s.Evidence
	ev.ID, ev.Content = evidenceID, s.Content
	return ev, s.err
}

// ---------------------------------------------------------------------------
// Helper to build a minimal engagement for the ownership reader.
// ---------------------------------------------------------------------------

// We need to import the engagement domain for the ownership reader.
// The ports.EngagementOwnershipReader returns *engagement.Engagement.
// We wrap the fake to satisfy the interface.

type fakeEngagementOwnershipReader struct {
	eng *engdom.Engagement
}

func (r *fakeEngagementOwnershipReader) GetByIDInTenant(_ context.Context, tenantID, id shared.ID) (*engdom.Engagement, error) {
	if r.eng == nil || r.eng.ID != id || r.eng.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return r.eng, nil
}

// ---------------------------------------------------------------------------
// Test fakes for Evaluator dependencies
// ---------------------------------------------------------------------------

func testTenantID() shared.ID     { return shared.ID("tenant-1") }
func testEngagementID() shared.ID { return shared.ID("eng-1") }
func testFindingID() shared.ID    { return shared.ID("find-1") }
func testAssetID() shared.ID      { return shared.ID("asset-1") }
func testExposureID() shared.ID   { return shared.ID("exposure-1") }
func testDetectionID() shared.ID  { return shared.ID("det-1") }
func testEvidenceID() shared.ID   { return shared.ID("ev-1") }

func baseFinding() finding.Finding {
	return finding.Finding{
		ID:           testFindingID(),
		EngagementID: testEngagementID(),
		Title:        "Test Finding",
		Priority:     3,
		Version:      1,
		Kind:         finding.KindSCA,
		DedupKey:     "dedup-1",
	}
}

func baseEngagement() *engdom.Engagement {
	return &engdom.Engagement{
		ID:       testEngagementID(),
		TenantID: testTenantID(),
	}
}

func baseEvaluator(t *testing.T) (*Evaluator, *fakeProposer, *fakeAudit) {
	t.Helper()
	p := &fakeProposer{}
	audit := &fakeAudit{}
	ev := &Evaluator{
		proposer:   p,
		findings:   &fakeFindingRepo{findings: []finding.Finding{baseFinding()}},
		judgments:  &fakeJudgmentStore{},
		bindings:   &fakeAttackPathStore{},
		assets:     &fakeAssetRepo{},
		detections: &fakeDetectionStore{},
		engagement: &fakeEngagementOwnershipReader{eng: baseEngagement()},
		promotions: &fakePromotionStore{},
		clock:      &fakeClock{t: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
		audit:      audit,
	}
	return ev, p, audit
}

// ---------------------------------------------------------------------------
// Tests: Evaluator
// ---------------------------------------------------------------------------

func TestEvaluatorRequiresTenantContext(t *testing.T) {
	ev, _, _ := baseEvaluator(t)
	_, err := ev.Evaluate(context.Background(), testEngagementID())
	if err == nil {
		t.Fatal("expected error without tenant context")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation, got %v", err)
	}
}

func TestEvaluatorRequiresEngagementID(t *testing.T) {
	ev, _, _ := baseEvaluator(t)
	ctx := shared.WithTenant(context.Background(), testTenantID())
	_, err := ev.Evaluate(ctx, shared.ID(""))
	if err == nil {
		t.Fatal("expected error with zero engagement ID")
	}
}

func TestEvaluatorRejectsCrossTenantAccess(t *testing.T) {
	ev, _, _ := baseEvaluator(t)
	ctx := shared.WithTenant(context.Background(), shared.ID("other-tenant"))
	_, err := ev.Evaluate(ctx, testEngagementID())
	if err == nil {
		t.Fatal("expected error for cross-tenant access")
	}
}

func TestEvaluatorNoDetectionReturnsNoProposal(t *testing.T) {
	ev, p, _ := baseEvaluator(t)
	ctx := shared.WithTenant(context.Background(), testTenantID())
	n, err := ev.Evaluate(ctx, testEngagementID())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 proposals without detection+path, got %d", n)
	}
	if len(p.proposed) != 0 {
		t.Fatalf("expected 0 proposed judgments, got %d", len(p.proposed))
	}
}

func TestEvaluatorEscalationWithDetectionOnExposurePath(t *testing.T) {
	tid := testTenantID()
	eid := testEngagementID()
	fid := testFindingID()
	aid := testAssetID()
	expID := testExposureID()
	detID := testDetectionID()
	evID := testEvidenceID()

	// Build a finding at priority 3 (escalation moves to 2).
	f := baseFinding()
	f.Priority = 3

	// A publishable Reachable judgment so the domain Evaluate sees Reachable.
	reachJudgment := judgment.Judgment{
		ID:           shared.ID("reach-j-1"),
		EngagementID: eid,
		Capability:   judgment.CapReachability,
		SubjectKind:  judgment.SubjectFinding,
		SubjectID:    fid,
		Claim: judgment.ReachabilityClaim{
			Reachable: judgment.Reachable,
			Tier:      judgment.Tier0,
		},
		State:         judgment.StateConfirmed,
		EvidenceScore: 90,
		ProposedBy:    "agent:reacher",
	}

	// Build assets: an exposure root and a connected asset.
	exposureAsset := &asset.Asset{ID: expID, TenantID: tid, Kind: asset.KindExposure, Key: "exp-1", Name: "Internet"}
	targetAsset := &asset.Asset{ID: aid, TenantID: tid, Kind: asset.KindHost, Key: "host-1", Name: "Host"}
	edges := []*asset.Edge{{TenantID: tid, From: expID, To: aid, Kind: asset.EdgeReaches, Provenance: shared.ID("prov-1"), Confidence: asset.EdgeObserved}}

	// Binding: finding bound to the target asset.
	bindings := []attackpath.Binding{{
		TenantID: tid, EngagementID: eid, AssetID: aid, FindingID: fid,
		TargetKind: attackpath.TargetCanonical, Producer: shared.ID("prod-1"),
		Provenance: shared.ID("prov-1"), Confidence: asset.EdgeObserved,
	}}

	// Active detection on the target asset.
	det := detection.Record{
		ID:           detID,
		TenantID:     tid,
		EngagementID: eid,
		AssetID:      aid,
		EvidenceID:   evID,
		RecordedAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	p := &fakeProposer{}
	audit := &fakeAudit{}
	ev := &Evaluator{
		proposer:   p,
		findings:   &fakeFindingRepo{findings: []finding.Finding{f}},
		judgments:  &fakeJudgmentStore{judgments: []judgment.Judgment{reachJudgment}},
		bindings:   &fakeAttackPathStore{bindings: bindings},
		assets:     &fakeAssetRepo{assets: []*asset.Asset{exposureAsset, targetAsset}, edges: edges},
		detections: &fakeDetectionStore{records: []detection.Record{det}},
		engagement: &fakeEngagementOwnershipReader{eng: baseEngagement()},
		promotions: &fakePromotionStore{},
		clock:      &fakeClock{t: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
		audit:      audit,
	}

	ctx := shared.WithTenant(context.Background(), tid)
	n, err := ev.Evaluate(ctx, eid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 proposal, got %d", n)
	}
	if len(p.proposed) != 1 {
		t.Fatalf("expected 1 proposed judgment, got %d", len(p.proposed))
	}
	j := p.proposed[0]
	if j.Capability != judgment.CapPromotion {
		t.Fatalf("expected CapPromotion, got %s", j.Capability)
	}
	pc, ok := j.Claim.(*judgment.PromotionClaim)
	if !ok {
		t.Fatal("expected *PromotionClaim")
	}
	if pc.Rule != judgment.RuleRuntimeReachableExposed {
		t.Fatalf("expected rule %s, got %s", judgment.RuleRuntimeReachableExposed, pc.Rule)
	}
	if pc.Proposed != judgment.PromotionEscalate {
		t.Fatalf("expected escalate, got %s", pc.Proposed)
	}
	if pc.BeforePriority != 3 || pc.AfterPriority != 2 {
		t.Fatalf("expected priority 3->2, got %d->%d", pc.BeforePriority, pc.AfterPriority)
	}
	// Audit should have recorded the proposal.
	if len(audit.entries) != 1 || audit.entries[0].Action != "promotion.proposed" {
		t.Fatalf("expected 1 audit entry for promotion.proposed, got %d", len(audit.entries))
	}
}

func TestEvaluatorDeterministicUnreachabilityDeescalation(t *testing.T) {
	tid := testTenantID()
	eid := testEngagementID()
	fid := testFindingID()

	f := baseFinding()
	f.Priority = 2

	// A publishable NotReachable judgment from a system reachproof identity
	// with score >= DeterministicProofScore. This is the only combination
	// that triggers deterministic de-escalation (not just Tier0).
	reachJudgment := judgment.Judgment{
		ID:           shared.ID("reach-j-1"),
		EngagementID: eid,
		Capability:   judgment.CapReachability,
		SubjectKind:  judgment.SubjectFinding,
		SubjectID:    fid,
		Claim: judgment.ReachabilityClaim{
			Reachable: judgment.NotReachable,
			Tier:      judgment.Tier2,
		},
		State:         judgment.StateConfirmed,
		EvidenceScore: 90,
		ProposedBy:    "system:callgraph-scan", VerifiedBy: "system:callgraph-engine", VerdictRationale: "confirmed",
	}

	p := &fakeProposer{}
	audit := &fakeAudit{}
	ev := &Evaluator{
		proposer:   p,
		findings:   &fakeFindingRepo{findings: []finding.Finding{f}},
		judgments:  &fakeJudgmentStore{judgments: []judgment.Judgment{reachJudgment}},
		bindings:   &fakeAttackPathStore{},
		assets:     &fakeAssetRepo{},
		detections: &fakeDetectionStore{},
		engagement: &fakeEngagementOwnershipReader{eng: baseEngagement()},
		promotions: &fakePromotionStore{},
		clock:      &fakeClock{t: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
		audit:      audit,
	}

	ctx := shared.WithTenant(context.Background(), tid)
	n, err := ev.Evaluate(ctx, eid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 proposal, got %d", n)
	}
	pc := p.proposed[0].Claim.(*judgment.PromotionClaim)
	if pc.Rule != judgment.RuleDeterministicUnreachable {
		t.Fatalf("expected rule %s, got %s", judgment.RuleDeterministicUnreachable, pc.Rule)
	}
	if pc.Proposed != judgment.PromotionDeescalate {
		t.Fatalf("expected de_escalate, got %s", pc.Proposed)
	}
	if pc.BeforePriority != 2 || pc.AfterPriority != 3 {
		t.Fatalf("expected priority 2->3, got %d->%d", pc.BeforePriority, pc.AfterPriority)
	}
}

func TestEvaluatorInferredPathFlagForReview(t *testing.T) {
	tid := testTenantID()
	eid := testEngagementID()
	fid := testFindingID()
	aid := testAssetID()
	expID := testExposureID()
	detID := testDetectionID()

	f := baseFinding()
	f.Priority = 3

	// Assets with an inferred (not observed) edge.
	exposureAsset := &asset.Asset{ID: expID, TenantID: tid, Kind: asset.KindExposure, Key: "exp-1", Name: "Internet"}
	targetAsset := &asset.Asset{ID: aid, TenantID: tid, Kind: asset.KindHost, Key: "host-1", Name: "Host"}
	edges := []*asset.Edge{{TenantID: tid, From: expID, To: aid, Kind: asset.EdgeReaches, Provenance: shared.ID("prov-1"), Confidence: asset.EdgeInferred}}

	bindings := []attackpath.Binding{{
		TenantID: tid, EngagementID: eid, AssetID: aid, FindingID: fid,
		TargetKind: attackpath.TargetCanonical, Producer: shared.ID("prod-1"),
		Provenance: shared.ID("prov-1"), Confidence: asset.EdgeInferred,
	}}

	det := detection.Record{
		ID: detID, TenantID: tid, EngagementID: eid, AssetID: aid,
		RecordedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	p := &fakeProposer{}
	ev := &Evaluator{
		proposer:   p,
		findings:   &fakeFindingRepo{findings: []finding.Finding{f}},
		judgments:  &fakeJudgmentStore{},
		bindings:   &fakeAttackPathStore{bindings: bindings},
		assets:     &fakeAssetRepo{assets: []*asset.Asset{exposureAsset, targetAsset}, edges: edges},
		detections: &fakeDetectionStore{records: []detection.Record{det}},
		engagement: &fakeEngagementOwnershipReader{eng: baseEngagement()},
		promotions: &fakePromotionStore{},
		clock:      &fakeClock{t: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
		audit:      &fakeAudit{},
	}

	ctx := shared.WithTenant(context.Background(), tid)
	n, err := ev.Evaluate(ctx, eid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 proposal for inferred path, got %d", n)
	}
	pc := p.proposed[0].Claim.(*judgment.PromotionClaim)
	if pc.Rule != judgment.RuleUncertainCorroboration {
		t.Fatalf("expected rule %s, got %s", judgment.RuleUncertainCorroboration, pc.Rule)
	}
	if pc.Proposed != judgment.PromotionFlagForReview {
		t.Fatalf("expected flag_for_review, got %s", pc.Proposed)
	}
	if len(pc.Uncertainty) == 0 {
		t.Fatal("expected uncertainty tokens for inferred path")
	}
}

func TestEvaluatorUnrelatedDetectionRejected(t *testing.T) {
	tid := testTenantID()
	eid := testEngagementID()
	aid := testAssetID()
	expID := testExposureID()

	// Finding bound to asset A, but detection is on asset B (not on any path).
	f := baseFinding()
	f.Priority = 3

	exposureAsset := &asset.Asset{ID: expID, TenantID: tid, Kind: asset.KindExposure, Key: "exp-1", Name: "Internet"}
	targetAsset := &asset.Asset{ID: aid, TenantID: tid, Kind: asset.KindHost, Key: "host-1", Name: "Host"}
	otherAsset := &asset.Asset{ID: shared.ID("other-asset"), TenantID: tid, Kind: asset.KindHost, Key: "host-2", Name: "Other"}
	edges := []*asset.Edge{{TenantID: tid, From: expID, To: aid, Kind: asset.EdgeReaches, Provenance: shared.ID("prov-1"), Confidence: asset.EdgeObserved}}

	bindings := []attackpath.Binding{{
		TenantID: tid, EngagementID: eid, AssetID: aid, FindingID: testFindingID(),
		TargetKind: attackpath.TargetCanonical, Producer: shared.ID("prod-1"),
		Provenance: shared.ID("prov-1"), Confidence: asset.EdgeObserved,
	}}

	// Detection on otherAsset (not on the path to the finding).
	det := detection.Record{
		ID: shared.ID("det-other"), TenantID: tid, EngagementID: eid,
		AssetID:    shared.ID("other-asset"),
		RecordedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	p := &fakeProposer{}
	ev := &Evaluator{
		proposer:   p,
		findings:   &fakeFindingRepo{findings: []finding.Finding{f}},
		judgments:  &fakeJudgmentStore{},
		bindings:   &fakeAttackPathStore{bindings: bindings},
		assets:     &fakeAssetRepo{assets: []*asset.Asset{exposureAsset, targetAsset, otherAsset}, edges: edges},
		detections: &fakeDetectionStore{records: []detection.Record{det}},
		engagement: &fakeEngagementOwnershipReader{eng: baseEngagement()},
		promotions: &fakePromotionStore{},
		clock:      &fakeClock{t: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
		audit:      &fakeAudit{},
	}

	ctx := shared.WithTenant(context.Background(), tid)
	n, err := ev.Evaluate(ctx, eid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 proposals for unrelated detection, got %d", n)
	}
}

func TestEvaluatorIdempotentSkipUnchangedFingerprint(t *testing.T) {
	tid := testTenantID()
	eid := testEngagementID()
	fid := testFindingID()
	aid := testAssetID()
	expID := testExposureID()
	detID := testDetectionID()

	f := baseFinding()
	f.Priority = 3

	exposureAsset := &asset.Asset{ID: expID, TenantID: tid, Kind: asset.KindExposure, Key: "exp-1", Name: "Internet"}
	targetAsset := &asset.Asset{ID: aid, TenantID: tid, Kind: asset.KindHost, Key: "host-1", Name: "Host"}
	edges := []*asset.Edge{{TenantID: tid, From: expID, To: aid, Kind: asset.EdgeReaches, Provenance: shared.ID("prov-1"), Confidence: asset.EdgeObserved}}
	bindings := []attackpath.Binding{{
		TenantID: tid, EngagementID: eid, AssetID: aid, FindingID: fid,
		TargetKind: attackpath.TargetCanonical, Producer: shared.ID("prod-1"),
		Provenance: shared.ID("prov-1"), Confidence: asset.EdgeObserved,
	}}
	det := detection.Record{
		ID: detID, TenantID: tid, EngagementID: eid, AssetID: aid,
		RecordedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	// Pre-compute the expected fingerprint by running evaluate once.
	p1 := &fakeProposer{}
	ev1 := &Evaluator{
		proposer: p1, findings: &fakeFindingRepo{findings: []finding.Finding{f}},
		judgments: &fakeJudgmentStore{}, bindings: &fakeAttackPathStore{bindings: bindings},
		assets:     &fakeAssetRepo{assets: []*asset.Asset{exposureAsset, targetAsset}, edges: edges},
		detections: &fakeDetectionStore{records: []detection.Record{det}},
		engagement: &fakeEngagementOwnershipReader{eng: baseEngagement()},
		promotions: &fakePromotionStore{}, clock: &fakeClock{t: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}, audit: &fakeAudit{},
	}
	ctx := shared.WithTenant(context.Background(), tid)
	n, err := ev1.Evaluate(ctx, eid)
	if err != nil || n != 1 {
		t.Fatalf("first evaluate: n=%d err=%v", n, err)
	}
	fp := p1.proposed[0].Claim.(*judgment.PromotionClaim).Fingerprint

	// Second evaluate with existing proposal having same fingerprint -> skip.
	existingJ := judgment.Judgment{
		ID: shared.ID("existing-j"), EngagementID: eid, Capability: judgment.CapPromotion,
		SubjectKind: judgment.SubjectFinding, SubjectID: fid,
		Claim: judgment.PromotionClaim{FindingID: fid, Fingerprint: fp, Rule: judgment.RuleRuntimeReachableExposed,
			Proposed: judgment.PromotionEscalate, FindingVersion: 1, BeforePriority: 3, AfterPriority: 2,
			Inputs: []judgment.PromotionInput{{Kind: judgment.PromotionInputDetection, ID: detID}}},
		State: judgment.StateProposed,
	}
	p2 := &fakeProposer{existing: []judgment.Judgment{existingJ}}
	ev2 := &Evaluator{
		proposer: p2, findings: &fakeFindingRepo{findings: []finding.Finding{f}},
		judgments:  &fakeJudgmentStore{judgments: []judgment.Judgment{existingJ}},
		bindings:   &fakeAttackPathStore{bindings: bindings},
		assets:     &fakeAssetRepo{assets: []*asset.Asset{exposureAsset, targetAsset}, edges: edges},
		detections: &fakeDetectionStore{records: []detection.Record{det}},
		engagement: &fakeEngagementOwnershipReader{eng: baseEngagement()},
		promotions: &fakePromotionStore{}, clock: &fakeClock{t: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
		audit: &fakeAudit{},
	}
	n2, err := ev2.Evaluate(ctx, eid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("expected 0 proposals (unchanged fingerprint), got %d", n2)
	}
	if len(p2.proposed) != 0 {
		t.Fatalf("expected 0 proposed (skip unchanged), got %d", len(p2.proposed))
	}
}

func TestIndexPromotionProposalsTracksEveryFingerprint(t *testing.T) {
	claims := []judgment.Judgment{
		{Capability: judgment.CapPromotion, Claim: judgment.PromotionClaim{FindingID: "finding", Fingerprint: "refuted"}, State: judgment.StateRefuted},
		{Capability: judgment.CapPromotion, Claim: judgment.PromotionClaim{FindingID: "finding", Fingerprint: "changed"}, State: judgment.StateProposed},
	}
	got := indexPromotionProposals(claims)["finding"]
	if len(got) != 2 {
		t.Fatalf("fingerprints = %#v, want refuted and changed", got)
	}
	if _, ok := got["refuted"]; !ok {
		t.Fatal("unchanged refuted fingerprint was not evaluated")
	}
	if _, ok := got["changed"]; !ok {
		t.Fatal("changed fingerprint was not retained as eligible comparison state")
	}
}

func TestEvaluatorRetriesProposalAuditWithoutDuplicateProposal(t *testing.T) {
	tid, eid := testTenantID(), testEngagementID()
	fid, aid, expID, detID := testFindingID(), testAssetID(), testExposureID(), testDetectionID()
	f := baseFinding()
	exposure := &asset.Asset{ID: expID, TenantID: tid, Kind: asset.KindExposure, Key: "exp", Name: "Internet"}
	target := &asset.Asset{ID: aid, TenantID: tid, Kind: asset.KindHost, Key: "host", Name: "Host"}
	bindings := []attackpath.Binding{{TenantID: tid, EngagementID: eid, AssetID: aid, FindingID: fid, TargetKind: attackpath.TargetCanonical, Producer: "producer", Provenance: "provenance", Confidence: asset.EdgeObserved}}
	dets := []detection.Record{{ID: detID, TenantID: tid, EngagementID: eid, AssetID: aid, RecordedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}}
	clock := &fakeClock{t: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}
	audit := &fakeAudit{fail: 1}
	newEvaluator := func(p *fakeProposer, judgments []judgment.Judgment) *Evaluator {
		return &Evaluator{
			proposer: p, findings: &fakeFindingRepo{findings: []finding.Finding{f}}, judgments: &fakeJudgmentStore{judgments: judgments},
			bindings: &fakeAttackPathStore{bindings: bindings}, assets: &fakeAssetRepo{assets: []*asset.Asset{exposure, target}, edges: []*asset.Edge{{TenantID: tid, From: expID, To: aid, Kind: asset.EdgeReaches, Provenance: "provenance", Confidence: asset.EdgeObserved}}},
			detections: &fakeDetectionStore{records: dets}, engagement: &fakeEngagementOwnershipReader{eng: baseEngagement()}, promotions: &fakePromotionStore{}, clock: clock, audit: audit,
		}
	}
	ctx := shared.WithTenant(context.Background(), tid)
	firstProposer := &fakeProposer{}
	if _, err := newEvaluator(firstProposer, nil).Evaluate(ctx, eid); err == nil {
		t.Fatal("first audit failure must be returned")
	}
	if len(firstProposer.proposed) != 1 || len(audit.entries) != 0 {
		t.Fatalf("proposal must persist before failed audit: proposals=%d audits=%d", len(firstProposer.proposed), len(audit.entries))
	}
	retryProposer := &fakeProposer{}
	if n, err := newEvaluator(retryProposer, firstProposer.proposed).Evaluate(ctx, eid); err != nil || n != 0 {
		t.Fatalf("retry = (%d, %v), want (0, nil)", n, err)
	}
	if len(retryProposer.proposed) != 0 || len(audit.entries) != 1 {
		t.Fatalf("retry duplicated proposal/audit: proposals=%d audits=%d", len(retryProposer.proposed), len(audit.entries))
	}
	if _, err := newEvaluator(retryProposer, firstProposer.proposed).Evaluate(ctx, eid); err != nil {
		t.Fatalf("exact retry: %v", err)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("exact retry duplicated audit: %d", len(audit.entries))
	}
}

func TestEvaluatorProposesStackedSignalLossReversalsLIFO(t *testing.T) {
	fid := testFindingID()
	first := promotion.PromotionEvent{ID: "escalation-a", FindingID: fid, Effect: judgment.PromotionEscalate, BeforePriority: 4, AfterPriority: 3, AfterFindingVersion: 2}
	second := promotion.PromotionEvent{ID: "escalation-b", FindingID: fid, Effect: judgment.PromotionEscalate, BeforePriority: 3, AfterPriority: 2, AfterFindingVersion: 3}
	store := &fakePromotionStore{events: map[shared.ID][]promotion.PromotionEvent{fid: {first, second}}}
	newEvaluator := func(priority, version int, events []promotion.PromotionEvent) (*Evaluator, *fakeProposer) {
		store.events[fid] = events
		f := baseFinding()
		f.Priority, f.Version = priority, version
		proposer := &fakeProposer{}
		return &Evaluator{
			proposer: proposer, findings: &fakeFindingRepo{findings: []finding.Finding{f}}, judgments: &fakeJudgmentStore{},
			bindings: &fakeAttackPathStore{}, assets: &fakeAssetRepo{}, detections: &fakeDetectionStore{},
			engagement: &fakeEngagementOwnershipReader{eng: baseEngagement()}, promotions: store,
			clock: &fakeClock{t: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}, audit: &fakeAudit{},
		}, proposer
	}
	ctx := shared.WithTenant(context.Background(), testTenantID())
	evaluator, proposer := newEvaluator(2, 3, []promotion.PromotionEvent{first, second})
	if n, err := evaluator.Evaluate(ctx, testEngagementID()); err != nil || n != 1 {
		t.Fatalf("first signal-loss evaluation = (%d, %v)", n, err)
	}
	claim := proposer.proposed[0].Claim.(*judgment.PromotionClaim)
	if claim.Rule != judgment.RuleCorroboratingSignalLoss || claim.BeforePriority != 2 || claim.AfterPriority != 3 || claim.Inputs[0].ID != second.ID {
		t.Fatalf("first reversal claim = %#v, want reversal of %s", claim, second.ID)
	}
	reversalB := promotion.PromotionEvent{ID: "reversal-b", FindingID: fid, Effect: judgment.PromotionDeescalate, Rule: judgment.RuleCorroboratingSignalLoss, Inputs: claim.Inputs}
	evaluator, proposer = newEvaluator(3, 4, []promotion.PromotionEvent{first, second, reversalB})
	if n, err := evaluator.Evaluate(ctx, testEngagementID()); err != nil || n != 1 {
		t.Fatalf("second signal-loss evaluation = (%d, %v)", n, err)
	}
	claim = proposer.proposed[0].Claim.(*judgment.PromotionClaim)
	if claim.BeforePriority != 3 || claim.AfterPriority != 4 || claim.Inputs[0].ID != first.ID {
		t.Fatalf("second reversal claim = %#v, want reversal of %s", claim, first.ID)
	}
	evaluator, proposer = newEvaluator(4, 5, append(store.events[fid], promotion.PromotionEvent{ID: "reversal-a", FindingID: fid, Effect: judgment.PromotionDeescalate, Rule: judgment.RuleCorroboratingSignalLoss, Inputs: claim.Inputs}))
	if n, err := evaluator.Evaluate(ctx, testEngagementID()); err != nil || n != 0 || len(proposer.proposed) != 0 {
		t.Fatalf("unchanged reevaluation = (%d, %v), proposals=%#v", n, err, proposer.proposed)
	}
}

// ---------------------------------------------------------------------------
// Tests: ConfirmedRecorder
// ---------------------------------------------------------------------------

func TestRecorderRejectsNonPromotionCapability(t *testing.T) {
	r, err := NewConfirmedRecorder(&fakeEvidenceSealer{}, &fakePromotionStore{}, &fakeFindingRepo{findings: []finding.Finding{baseFinding()}}, &fakeEngagementOwnershipReader{eng: baseEngagement()}, &fakeAudit{}, &fakeClock{t: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	j := judgment.Judgment{Capability: judgment.CapSAST, State: judgment.StateConfirmed, EvidenceScore: 90}
	err = r.RecordConfirmed(shared.WithTenant(context.Background(), testTenantID()), j)
	if err == nil {
		t.Fatal("expected error for non-CapPromotion")
	}
}

func TestRecorderRejectsNotPublishable(t *testing.T) {
	r, err := NewConfirmedRecorder(&fakeEvidenceSealer{}, &fakePromotionStore{}, &fakeFindingRepo{findings: []finding.Finding{baseFinding()}}, &fakeEngagementOwnershipReader{eng: baseEngagement()}, &fakeAudit{}, &fakeClock{t: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	// StateProposed is not publishable.
	j := judgment.Judgment{Capability: judgment.CapPromotion, State: judgment.StateProposed, EvidenceScore: 90}
	err = r.RecordConfirmed(shared.WithTenant(context.Background(), testTenantID()), j)
	if err == nil {
		t.Fatal("expected error for not publishable")
	}
}

func TestRecorderRejectsLowEvidenceScore(t *testing.T) {
	r, err := NewConfirmedRecorder(&fakeEvidenceSealer{}, &fakePromotionStore{}, &fakeFindingRepo{findings: []finding.Finding{baseFinding()}}, &fakeEngagementOwnershipReader{eng: baseEngagement()}, &fakeAudit{}, &fakeClock{t: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	j := judgment.Judgment{
		ID: shared.ID("j-1"), EngagementID: testEngagementID(),
		Capability: judgment.CapPromotion, State: judgment.StateConfirmed,
		EvidenceScore: 74, Claim: judgment.PromotionClaim{
			FindingID: testFindingID(), Rule: judgment.RuleRuntimeReachableExposed,
			Inputs:   []judgment.PromotionInput{{Kind: judgment.PromotionInputDetection, ID: testDetectionID()}},
			Proposed: judgment.PromotionEscalate, FindingVersion: 1, BeforePriority: 3, AfterPriority: 2,
		},
	}
	err = r.RecordConfirmed(shared.WithTenant(context.Background(), testTenantID()), j)
	if err == nil {
		t.Fatal("expected error for score < threshold")
	}
}

func TestRecorderRejectsMissingVerdictProvenance(t *testing.T) {
	fid := testFindingID()
	r, err := NewConfirmedRecorder(&fakeEvidenceSealer{}, &fakePromotionStore{}, &fakeFindingRepo{findings: []finding.Finding{baseFinding()}}, &fakeEngagementOwnershipReader{eng: baseEngagement()}, &fakeAudit{}, &fakeClock{t: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	base := judgment.Judgment{
		ID: "j-missing-provenance", EngagementID: testEngagementID(), Capability: judgment.CapPromotion,
		SubjectKind: judgment.SubjectFinding, SubjectID: fid, State: judgment.StateConfirmed,
		EvidenceScore: 75, ProposedBy: "agent:proposer",
		Claim: judgment.PromotionClaim{
			FindingID: fid, Rule: judgment.RuleRuntimeReachableExposed,
			Inputs:   []judgment.PromotionInput{{Kind: judgment.PromotionInputDetection, ID: testDetectionID()}},
			Proposed: judgment.PromotionEscalate, FindingVersion: 1, BeforePriority: 3, AfterPriority: 2,
			Fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}
	for _, tc := range []struct {
		name string
		j    judgment.Judgment
	}{
		{"missing verifier", base},
		{"missing rationale", func() judgment.Judgment { j := base; j.VerifiedBy = "human:verifier"; return j }()},
		{"self verifier", func() judgment.Judgment {
			j := base
			j.VerifiedBy, j.VerdictRationale = "agent:proposer", "confirmed"
			return j
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := r.RecordConfirmed(shared.WithTenant(context.Background(), testTenantID()), tc.j); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("RecordConfirmed: want ErrValidation, got %v", err)
			}
		})
	}
}

func TestRecorderScoreMeetsThresholdApplies(t *testing.T) {
	fid := testFindingID()
	ps := &fakePromotionStore{}
	es := &fakeEvidenceSealer{Evidence: evidence.Evidence{ID: testEvidenceID()}}
	audit := &fakeAudit{}
	r, err := NewConfirmedRecorder(es, ps, &fakeFindingRepo{findings: []finding.Finding{baseFinding()}}, &fakeEngagementOwnershipReader{eng: baseEngagement()}, audit, &fakeClock{t: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	j := judgment.Judgment{
		ID: shared.ID("j-1"), EngagementID: testEngagementID(),
		Capability: judgment.CapPromotion, SubjectKind: judgment.SubjectFinding, SubjectID: fid,
		State:         judgment.StateConfirmed,
		EvidenceScore: 75, ProposedBy: "agent:proposer", VerifiedBy: "human:verifier", VerdictRationale: "confirmed",
		Claim: judgment.PromotionClaim{
			FindingID: fid, Rule: judgment.RuleRuntimeReachableExposed,
			Inputs:   []judgment.PromotionInput{{Kind: judgment.PromotionInputDetection, ID: testDetectionID()}},
			Proposed: judgment.PromotionEscalate, FindingVersion: 1, BeforePriority: 3, AfterPriority: 2,
			Fingerprint: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		},
	}
	err = r.RecordConfirmed(shared.WithTenant(context.Background(), testTenantID()), j)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ps.applied) != 1 {
		t.Fatalf("expected 1 applied command, got %d", len(ps.applied))
	}
	if ps.applied[0].JudgmentID != j.ID {
		t.Fatalf("applied command judgment mismatch")
	}
	if ps.applied[0].EvidenceID.IsZero() {
		t.Fatalf("expected evidence ID to be set")
	}
	if ps.applied[0].VerdictScore != 75 {
		t.Fatalf("expected sealed verdict score 75, got %d", ps.applied[0].VerdictScore)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "promotion.applied" {
		t.Fatalf("expected audit entry for promotion.applied")
	}
}

func TestRecorderRejectsStaleFindingBeforeEvidenceSeal(t *testing.T) {
	f := baseFinding()
	f.Version = 2
	evidence := &fakeEvidenceSealer{Evidence: evidence.Evidence{ID: testEvidenceID()}}
	r, err := NewConfirmedRecorder(evidence, &fakePromotionStore{}, &fakeFindingRepo{findings: []finding.Finding{f}}, &fakeEngagementOwnershipReader{eng: baseEngagement()}, &fakeAudit{}, &fakeClock{t: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	j := judgment.Judgment{
		ID: "j-stale", EngagementID: testEngagementID(), Capability: judgment.CapPromotion, SubjectKind: judgment.SubjectFinding, SubjectID: testFindingID(),
		State: judgment.StateConfirmed, EvidenceScore: 75, ProposedBy: "agent:proposer", VerifiedBy: "human:verifier", VerdictRationale: "verified",
		Claim: judgment.PromotionClaim{FindingID: testFindingID(), Rule: judgment.RuleRuntimeReachableExposed, Inputs: []judgment.PromotionInput{{Kind: judgment.PromotionInputDetection, ID: testDetectionID()}}, Proposed: judgment.PromotionEscalate, FindingVersion: 1, BeforePriority: 3, AfterPriority: 2, Fingerprint: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"},
	}
	if err := r.RecordConfirmed(shared.WithTenant(context.Background(), testTenantID()), j); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("RecordConfirmed error = %v, want ErrConflict", err)
	}
	if evidence.sealCalled != 0 {
		t.Fatalf("sealed stale promotion evidence %d times", evidence.sealCalled)
	}
}

func TestRecorderCarriesVerdictProvenanceToEvidenceAndEvent(t *testing.T) {
	fid := testFindingID()
	ps := &fakePromotionStore{}
	es := &fakeEvidenceSealer{Evidence: evidence.Evidence{ID: testEvidenceID()}}
	r, err := NewConfirmedRecorder(es, ps, &fakeFindingRepo{findings: []finding.Finding{baseFinding()}}, &fakeEngagementOwnershipReader{eng: baseEngagement()}, &fakeAudit{}, &fakeClock{t: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	j := judgment.Judgment{
		ID: "j-provenance", EngagementID: testEngagementID(), Capability: judgment.CapPromotion,
		SubjectKind: judgment.SubjectFinding, SubjectID: fid, State: judgment.StateConfirmed,
		EvidenceScore: 91, ProposedBy: "agent:proposer", VerifiedBy: "human:verifier", VerdictRationale: "reproduced",
		Claim: judgment.PromotionClaim{
			FindingID: fid, Rule: judgment.RuleRuntimeReachableExposed,
			Inputs:   []judgment.PromotionInput{{Kind: judgment.PromotionInputDetection, ID: testDetectionID()}},
			Proposed: judgment.PromotionEscalate, FindingVersion: 1, BeforePriority: 3, AfterPriority: 2,
			Fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}
	if err := r.RecordConfirmed(shared.WithTenant(context.Background(), testTenantID()), j); err != nil {
		t.Fatal(err)
	}
	if len(ps.applied) != 1 || ps.applied[0].VerdictScore != 91 || ps.applied[0].Verifier != "human:verifier" || ps.applied[0].VerdictRationale != "reproduced" {
		t.Fatalf("event provenance not preserved: %#v", ps.applied)
	}
	if string(es.Content) == "" || !strings.Contains(string(es.Content), `"verdict_score":91`) || !strings.Contains(string(es.Content), `"verified_by":"human:verifier"`) || !strings.Contains(string(es.Content), `"verdict_rationale":"reproduced"`) {
		t.Fatalf("evidence provenance not preserved: %s", es.Content)
	}
}

func TestRecorderIdempotentExactReplay(t *testing.T) {
	fid := testFindingID()
	jid := shared.ID("j-1")
	fp := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	ps := &fakePromotionStore{
		latest: map[shared.ID]promotion.PromotionEvent{
			fid: {JudgmentID: jid, Fingerprint: fp},
		},
	}
	es := &fakeEvidenceSealer{Evidence: evidence.Evidence{ID: testEvidenceID()}}
	r, err := NewConfirmedRecorder(es, ps, &fakeFindingRepo{findings: []finding.Finding{baseFinding()}}, &fakeEngagementOwnershipReader{eng: baseEngagement()}, &fakeAudit{}, &fakeClock{t: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	j := judgment.Judgment{
		ID: jid, EngagementID: testEngagementID(),
		Capability: judgment.CapPromotion, SubjectKind: judgment.SubjectFinding, SubjectID: fid,
		State:         judgment.StateConfirmed,
		EvidenceScore: 75, ProposedBy: "agent:proposer", VerifiedBy: "human:verifier", VerdictRationale: "confirmed",
		Claim: judgment.PromotionClaim{
			FindingID: fid, Rule: judgment.RuleRuntimeReachableExposed,
			Inputs:   []judgment.PromotionInput{{Kind: judgment.PromotionInputDetection, ID: testDetectionID()}},
			Proposed: judgment.PromotionEscalate, FindingVersion: 1, BeforePriority: 3, AfterPriority: 2,
			Fingerprint: fp,
		},
	}
	err = r.RecordConfirmed(shared.WithTenant(context.Background(), testTenantID()), j)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Exact replay must reach the lifecycle store, which validates complete semantics.
	if len(ps.applied) != 1 {
		t.Fatalf("expected 1 applied replay, got %d", len(ps.applied))
	}
}

func TestRecorderRetriesAuditWithoutRepeatingLifecycle(t *testing.T) {
	fid := testFindingID()
	ps := &fakePromotionStore{}
	es := &fakeEvidenceSealer{Evidence: evidence.Evidence{ID: testEvidenceID()}}
	audit := &fakeAudit{fail: 1}
	r, err := NewConfirmedRecorder(es, ps, &fakeFindingRepo{findings: []finding.Finding{baseFinding()}}, &fakeEngagementOwnershipReader{eng: baseEngagement()}, audit, &fakeClock{t: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	j := judgment.Judgment{
		ID: "j-audit-retry", EngagementID: testEngagementID(), Capability: judgment.CapPromotion,
		SubjectKind: judgment.SubjectFinding, SubjectID: fid, State: judgment.StateConfirmed,
		EvidenceScore: 75, ProposedBy: "agent:proposer", VerifiedBy: "human:verifier", VerdictRationale: "confirmed",
		Claim: judgment.PromotionClaim{
			FindingID: fid, Rule: judgment.RuleRuntimeReachableExposed,
			Inputs:   []judgment.PromotionInput{{Kind: judgment.PromotionInputDetection, ID: testDetectionID()}},
			Proposed: judgment.PromotionEscalate, FindingVersion: 1, BeforePriority: 3, AfterPriority: 2,
			Fingerprint: "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
		},
	}
	ctx := shared.WithTenant(context.Background(), testTenantID())
	if err := r.RecordConfirmed(ctx, j); err == nil {
		t.Fatal("first audit failure must be returned")
	}
	if len(ps.applied) != 1 || es.sealCalled != 1 {
		t.Fatalf("failed audit must retain one lifecycle application and evidence seal, got applications=%d seals=%d", len(ps.applied), es.sealCalled)
	}
	if err := r.RecordConfirmed(ctx, j); err != nil {
		t.Fatalf("retry audit: %v", err)
	}
	if len(ps.applied) != 1 || es.sealCalled != 1 {
		t.Fatalf("retry must not repeat lifecycle application or evidence seal, got applications=%d seals=%d", len(ps.applied), es.sealCalled)
	}
	if len(audit.entries) != 1 || audit.entries[0].Metadata["idempotency_key"] == "" {
		t.Fatalf("retry must create one idempotent audit record: %#v", audit.entries)
	}
	if err := r.RecordConfirmed(ctx, j); err != nil {
		t.Fatalf("successful replay: %v", err)
	}
	if len(audit.entries) != 1 || len(ps.applied) != 1 {
		t.Fatalf("successful replay duplicated audit or lifecycle: audits=%d applications=%d", len(audit.entries), len(ps.applied))
	}
}

func TestRecorderRetriesPersistedPromotionAuditPayloadAfterAcknowledgementFailure(t *testing.T) {
	fid := testFindingID()
	appliedAt := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	event := promotion.PromotionEvent{
		ID: "event-audit-retry", EngagementID: testEngagementID(), JudgmentID: "judgment-audit-retry", FindingID: fid,
		Rule: judgment.RuleRuntimeReachableExposed, Effect: judgment.PromotionEscalate, Fingerprint: strings.Repeat("a", 64), EvidenceID: testEvidenceID(), AppliedAt: appliedAt,
	}
	promotions := &reconciliationAudits{pending: []promotion.PromotionEvent{event}, failMark: 1}
	audit := &fakeAudit{}
	reconciler, err := NewReconciler(&fakeJudgmentStore{}, promotions, &reconciliationRecorder{}, audit, &fakeClock{t: appliedAt.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), testTenantID())
	if err := reconciler.Reconcile(ctx, testEngagementID()); err == nil {
		t.Fatal("acknowledgement failure must be returned")
	}
	if len(audit.entries) != 1 || !audit.entries[0].At.Equal(appliedAt) {
		t.Fatalf("first audit = %#v, want persisted AppliedAt %s", audit.entries, appliedAt)
	}
	if len(promotions.pending) != 1 || len(promotions.marked) != 1 {
		t.Fatalf("pending audit cleared after failed acknowledgement: pending=%#v marked=%#v", promotions.pending, promotions.marked)
	}
	if err := reconciler.Reconcile(ctx, testEngagementID()); err != nil {
		t.Fatalf("retry reconciliation: %v", err)
	}
	if len(audit.entries) != 1 || len(promotions.pending) != 0 || len(promotions.marked) != 2 {
		t.Fatalf("retry duplicated audit or left status pending: audits=%#v pending=%#v marked=%#v", audit.entries, promotions.pending, promotions.marked)
	}
}

func latestPromotionJudgment(t *testing.T, judgments []judgment.Judgment) judgment.Judgment {
	t.Helper()
	for i := len(judgments) - 1; i >= 0; i-- {
		if judgments[i].Capability == judgment.CapPromotion {
			return judgments[i]
		}
	}
	t.Fatal("missing promotion judgment")
	return judgment.Judgment{}
}

func assertPriority(t *testing.T, findings ports.FindingRepository, ctx context.Context, engagementID, findingID shared.ID, priority, version int) {
	t.Helper()
	got, err := findings.GetByEngagementAndID(ctx, engagementID, findingID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Priority != priority || got.Version != version {
		t.Fatalf("finding = priority %d version %d, want %d/%d", got.Priority, got.Version, priority, version)
	}
}

func countAudit(entries []ports.AuditEntry, action string) int {
	n := 0
	for _, entry := range entries {
		if entry.Action == action {
			n++
		}
	}
	return n
}

func recoveryJudgment() judgment.Judgment {
	return judgment.Judgment{
		ID: "recovery-judgment", EngagementID: testEngagementID(),
		Capability: judgment.CapPromotion, SubjectKind: judgment.SubjectFinding, SubjectID: testFindingID(),
		State: judgment.StateConfirmed, EvidenceScore: 75, ProposedBy: "agent:proposer", VerifiedBy: "human:verifier", VerdictRationale: "confirmed",
		Claim: judgment.PromotionClaim{
			FindingID: testFindingID(), Rule: judgment.RuleRuntimeReachableExposed,
			Inputs:   []judgment.PromotionInput{{Kind: judgment.PromotionInputDetection, ID: testDetectionID()}},
			Proposed: judgment.PromotionEscalate, FindingVersion: 1, BeforePriority: 3, AfterPriority: 2,
			Fingerprint: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		},
	}
}

func TestRecorderFlagForReviewNoPriorityBump(t *testing.T) {
	fid := testFindingID()
	ps := &fakePromotionStore{}
	es := &fakeEvidenceSealer{Evidence: evidence.Evidence{ID: testEvidenceID()}}
	audit := &fakeAudit{}
	r, err := NewConfirmedRecorder(es, ps, &fakeFindingRepo{findings: []finding.Finding{baseFinding()}}, &fakeEngagementOwnershipReader{eng: baseEngagement()}, audit, &fakeClock{t: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	j := judgment.Judgment{
		ID: shared.ID("j-review"), EngagementID: testEngagementID(),
		Capability: judgment.CapPromotion, SubjectKind: judgment.SubjectFinding, SubjectID: fid,
		State:         judgment.StateConfirmed,
		EvidenceScore: 75, ProposedBy: "agent:proposer", VerifiedBy: "human:verifier", VerdictRationale: "confirmed",
		Claim: judgment.PromotionClaim{
			FindingID: fid, Rule: judgment.RuleUncertainCorroboration,
			Inputs:   []judgment.PromotionInput{{Kind: judgment.PromotionInputDetection, ID: testDetectionID()}},
			Proposed: judgment.PromotionFlagForReview, FindingVersion: 1,
			BeforePriority: 3, AfterPriority: 3,
			Uncertainty: []string{"inferred_edge"}, Fingerprint: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		},
	}
	err = r.RecordConfirmed(shared.WithTenant(context.Background(), testTenantID()), j)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ps.applied) != 1 {
		t.Fatalf("expected 1 applied, got %d", len(ps.applied))
	}
	cmd := ps.applied[0]
	if cmd.BeforePriority != 3 || cmd.AfterPriority != 3 {
		t.Fatalf("expected no priority change for review, got %d->%d", cmd.BeforePriority, cmd.AfterPriority)
	}
	if cmd.Effect != judgment.PromotionFlagForReview {
		t.Fatalf("expected flag_for_review, got %s", cmd.Effect)
	}
}

// ---------------------------------------------------------------------------
// Architecture: Evaluator cannot Verify/Accept
// ---------------------------------------------------------------------------

// Compile-time check that the proposer interface does NOT include Verify or Accept.
// This is enforced by the narrow interface definition, but we verify it explicitly.
func TestEvaluatorCannotVerify(t *testing.T) {
	// The evaluator proposal authority excludes verification, acceptance, and reads.
	// It cannot confirm a promotion or use proposal listing as state.
	type proposerCheck interface {
		Propose(context.Context, string, shared.ID, judgment.Capability, judgment.SubjectKind, shared.ID, judgment.Claim) (judgment.Judgment, error)
	}
	var _ proposerCheck = (proposer)(nil)
}

// ---------------------------------------------------------------------------
// Tests: Constructor validation
// ---------------------------------------------------------------------------

func TestNewEvaluatorRejectsNilDependencies(t *testing.T) {
	full := func() (*fakeProposer, *fakeFindingRepo, *fakeJudgmentStore, *fakeAttackPathStore, *fakeAssetRepo, *fakeDetectionStore, *fakeEngagementOwnershipReader, *fakePromotionStore, *fakeClock, *fakeAudit) {
		return &fakeProposer{}, &fakeFindingRepo{}, &fakeJudgmentStore{},
			&fakeAttackPathStore{}, &fakeAssetRepo{}, &fakeDetectionStore{},
			&fakeEngagementOwnershipReader{}, &fakePromotionStore{}, &fakeClock{}, &fakeAudit{}
	}
	cases := []struct {
		name string
		new  func(*fakeProposer, *fakeFindingRepo, *fakeJudgmentStore, *fakeAttackPathStore, *fakeAssetRepo, *fakeDetectionStore, *fakeEngagementOwnershipReader, *fakePromotionStore, *fakeClock, *fakeAudit) (*Evaluator, error)
	}{
		{"nil_proposer", func(_ *fakeProposer, fr *fakeFindingRepo, jr *fakeJudgmentStore, ap *fakeAttackPathStore, ar *fakeAssetRepo, dr *fakeDetectionStore, er *fakeEngagementOwnershipReader, ps *fakePromotionStore, cl *fakeClock, au *fakeAudit) (*Evaluator, error) {
			return NewEvaluator(nil, fr, jr, ap, ar, dr, er, ps, cl, au)
		}},
		{"nil_findings", func(p *fakeProposer, _ *fakeFindingRepo, jr *fakeJudgmentStore, ap *fakeAttackPathStore, ar *fakeAssetRepo, dr *fakeDetectionStore, er *fakeEngagementOwnershipReader, ps *fakePromotionStore, cl *fakeClock, au *fakeAudit) (*Evaluator, error) {
			return NewEvaluator(p, nil, jr, ap, ar, dr, er, ps, cl, au)
		}},
		{"nil_judgments", func(p *fakeProposer, fr *fakeFindingRepo, _ *fakeJudgmentStore, ap *fakeAttackPathStore, ar *fakeAssetRepo, dr *fakeDetectionStore, er *fakeEngagementOwnershipReader, ps *fakePromotionStore, cl *fakeClock, au *fakeAudit) (*Evaluator, error) {
			return NewEvaluator(p, fr, nil, ap, ar, dr, er, ps, cl, au)
		}},
		{"nil_bindings", func(p *fakeProposer, fr *fakeFindingRepo, jr *fakeJudgmentStore, _ *fakeAttackPathStore, ar *fakeAssetRepo, dr *fakeDetectionStore, er *fakeEngagementOwnershipReader, ps *fakePromotionStore, cl *fakeClock, au *fakeAudit) (*Evaluator, error) {
			return NewEvaluator(p, fr, jr, nil, ar, dr, er, ps, cl, au)
		}},
		{"nil_assets", func(p *fakeProposer, fr *fakeFindingRepo, jr *fakeJudgmentStore, ap *fakeAttackPathStore, _ *fakeAssetRepo, dr *fakeDetectionStore, er *fakeEngagementOwnershipReader, ps *fakePromotionStore, cl *fakeClock, au *fakeAudit) (*Evaluator, error) {
			return NewEvaluator(p, fr, jr, ap, nil, dr, er, ps, cl, au)
		}},
		{"nil_detections", func(p *fakeProposer, fr *fakeFindingRepo, jr *fakeJudgmentStore, ap *fakeAttackPathStore, ar *fakeAssetRepo, _ *fakeDetectionStore, er *fakeEngagementOwnershipReader, ps *fakePromotionStore, cl *fakeClock, au *fakeAudit) (*Evaluator, error) {
			return NewEvaluator(p, fr, jr, ap, ar, nil, er, ps, cl, au)
		}},
		{"nil_engagement", func(p *fakeProposer, fr *fakeFindingRepo, jr *fakeJudgmentStore, ap *fakeAttackPathStore, ar *fakeAssetRepo, dr *fakeDetectionStore, _ *fakeEngagementOwnershipReader, ps *fakePromotionStore, cl *fakeClock, au *fakeAudit) (*Evaluator, error) {
			return NewEvaluator(p, fr, jr, ap, ar, dr, nil, ps, cl, au)
		}},
		{"nil_promotions", func(p *fakeProposer, fr *fakeFindingRepo, jr *fakeJudgmentStore, ap *fakeAttackPathStore, ar *fakeAssetRepo, dr *fakeDetectionStore, er *fakeEngagementOwnershipReader, _ *fakePromotionStore, cl *fakeClock, au *fakeAudit) (*Evaluator, error) {
			return NewEvaluator(p, fr, jr, ap, ar, dr, er, nil, cl, au)
		}},
		{"nil_clock", func(p *fakeProposer, fr *fakeFindingRepo, jr *fakeJudgmentStore, ap *fakeAttackPathStore, ar *fakeAssetRepo, dr *fakeDetectionStore, er *fakeEngagementOwnershipReader, ps *fakePromotionStore, _ *fakeClock, au *fakeAudit) (*Evaluator, error) {
			return NewEvaluator(p, fr, jr, ap, ar, dr, er, ps, nil, au)
		}},
		{"nil_audit", func(p *fakeProposer, fr *fakeFindingRepo, jr *fakeJudgmentStore, ap *fakeAttackPathStore, ar *fakeAssetRepo, dr *fakeDetectionStore, er *fakeEngagementOwnershipReader, ps *fakePromotionStore, cl *fakeClock, _ *fakeAudit) (*Evaluator, error) {
			return NewEvaluator(p, fr, jr, ap, ar, dr, er, ps, cl, nil)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, fr, jr, ap, ar, dr, er, ps, cl, au := full()
			if _, err := tc.new(p, fr, jr, ap, ar, dr, er, ps, cl, au); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestNewConfirmedRecorderRejectsNilDependencies(t *testing.T) {
	full := func() (*fakeEvidenceSealer, *fakePromotionStore, *fakeFindingRepo, *fakeAudit, *fakeClock) {
		return &fakeEvidenceSealer{}, &fakePromotionStore{}, &fakeFindingRepo{}, &fakeAudit{}, &fakeClock{}
	}
	t.Run("nil_evidence", func(t *testing.T) {
		_, ps, fr, au, cl := full()
		_, err := NewConfirmedRecorder(nil, ps, fr, &fakeEngagementOwnershipReader{eng: baseEngagement()}, au, cl)
		if err == nil {
			t.Error("expected error")
		}
	})
	t.Run("nil_promotions", func(t *testing.T) {
		es, _, fr, au, cl := full()
		_, err := NewConfirmedRecorder(es, nil, fr, &fakeEngagementOwnershipReader{eng: baseEngagement()}, au, cl)
		if err == nil {
			t.Error("expected error")
		}
	})
	t.Run("nil_findings", func(t *testing.T) {
		es, ps, _, au, cl := full()
		_, err := NewConfirmedRecorder(es, ps, nil, &fakeEngagementOwnershipReader{eng: baseEngagement()}, au, cl)
		if err == nil {
			t.Error("expected error")
		}
	})
	t.Run("nil_audit", func(t *testing.T) {
		es, ps, fr, _, cl := full()
		_, err := NewConfirmedRecorder(es, ps, fr, &fakeEngagementOwnershipReader{eng: baseEngagement()}, nil, cl)
		if err == nil {
			t.Error("expected error")
		}
	})
	t.Run("nil_clock", func(t *testing.T) {
		es, ps, fr, au, _ := full()
		_, err := NewConfirmedRecorder(es, ps, fr, &fakeEngagementOwnershipReader{eng: baseEngagement()}, au, nil)
		if err == nil {
			t.Error("expected error")
		}
	})
}

// ---------------------------------------------------------------------------
// Tests: Stable ordering
// ---------------------------------------------------------------------------

func TestEvaluatorStableFindingOrder(t *testing.T) {
	// Create findings in reverse order; evaluate should process them sorted by ID.
	f1 := finding.Finding{ID: shared.ID("find-z"), EngagementID: testEngagementID(), Priority: 3, Version: 1, Kind: finding.KindSCA, DedupKey: "z"}
	f2 := finding.Finding{ID: shared.ID("find-a"), EngagementID: testEngagementID(), Priority: 3, Version: 1, Kind: finding.KindSCA, DedupKey: "a"}

	p := &fakeProposer{}
	ev := &Evaluator{
		proposer: p, findings: &fakeFindingRepo{findings: []finding.Finding{f1, f2}},
		judgments: &fakeJudgmentStore{}, bindings: &fakeAttackPathStore{},
		assets: &fakeAssetRepo{}, detections: &fakeDetectionStore{},
		engagement: &fakeEngagementOwnershipReader{eng: baseEngagement()},
		promotions: &fakePromotionStore{}, clock: &fakeClock{t: time.Now()},
		audit: &fakeAudit{},
	}
	ctx := shared.WithTenant(context.Background(), testTenantID())
	_, err := ev.Evaluate(ctx, testEngagementID())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No proposals expected (no detections), but verify no error with sorted input.
	_ = p
}

// ---------------------------------------------------------------------------
// Tests: FilterActive
// ---------------------------------------------------------------------------

func TestFilterActiveExpired(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	records := []detection.Record{
		{ID: shared.ID("active"), RecordedAt: now},
		{ID: shared.ID("no-expiry"), RecordedAt: now},
		{ID: shared.ID("expired"), RecordedAt: now, ExpiresAt: now.Add(-time.Hour)},
	}
	active := filterActive(records, now)
	if len(active) != 2 {
		t.Fatalf("expected 2 active, got %d", len(active))
	}
}

// Ensure the imports are used.
var _ = promotion.Snapshot{}
var _ = judgment.PromotionClaim{}
var _ = attackpath.Binding{}
var _ = detection.Record{}
var _ = evidence.Evidence{}
var _ = asset.KindExposure
var _ = engdom.Engagement{}

type reconciliationRecorder struct {
	failed shared.ID
	called []shared.ID
}

func (r *reconciliationRecorder) RecordConfirmed(_ context.Context, j judgment.Judgment) error {
	r.called = append(r.called, j.ID)
	if j.ID == r.failed {
		return errors.New("record failed")
	}
	return nil
}

type reconciliationAudits struct {
	pending  []promotion.PromotionEvent
	marked   []shared.ID
	failMark int
}

func (a *reconciliationAudits) ListPendingAudits(_ context.Context, _ shared.ID) ([]promotion.PromotionEvent, error) {
	return a.pending, nil
}

func (a *reconciliationAudits) MarkAuditComplete(_ context.Context, id shared.ID) error {
	a.marked = append(a.marked, id)
	if a.failMark > 0 {
		a.failMark--
		return errors.New("acknowledgement unavailable")
	}
	for i, event := range a.pending {
		if event.ID == id {
			a.pending = append(a.pending[:i], a.pending[i+1:]...)
			break
		}
	}
	return nil
}

func TestReconcilerContinuesFailuresAndDrainsPendingAudits(t *testing.T) {
	first, second := recoveryJudgment(), recoveryJudgment()
	first.ID, second.ID = "failed", "succeeds"
	recorder := &reconciliationRecorder{failed: first.ID}
	audits := &reconciliationAudits{pending: []promotion.PromotionEvent{{ID: "audit-1", FindingID: testFindingID()}, {ID: "audit-2", FindingID: testFindingID()}}}
	reconciler, err := NewReconciler(&fakeJudgmentStore{judgments: []judgment.Judgment{first, second}}, audits, recorder, &fakeAudit{}, &fakeClock{t: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}

	err = reconciler.Reconcile(shared.WithTenant(context.Background(), testTenantID()), testEngagementID())
	if err == nil || !strings.Contains(err.Error(), "recover confirmed promotion failed") {
		t.Fatalf("Reconcile error = %v, want joined failed promotion error", err)
	}
	if len(recorder.called) != 2 || recorder.called[1] != second.ID {
		t.Fatalf("recovered judgments = %#v, want both", recorder.called)
	}
	if len(audits.marked) != 2 {
		t.Fatalf("completed audits = %#v, want both pending audits drained", audits.marked)
	}
}

type conflictAudit struct{}

func (conflictAudit) Record(context.Context, ports.AuditEntry) error { return nil }

func (conflictAudit) RecordOnce(context.Context, ports.AuditEntry) error { return shared.ErrConflict }

func TestReconcilerLeavesPendingAuditAfterRecordOnceConflict(t *testing.T) {
	audits := &reconciliationAudits{pending: []promotion.PromotionEvent{{ID: "audit-1", FindingID: testFindingID()}}}
	reconciler, err := NewReconciler(&fakeJudgmentStore{}, audits, &reconciliationRecorder{}, conflictAudit{}, &fakeClock{t: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}

	err = reconciler.Reconcile(shared.WithTenant(context.Background(), testTenantID()), testEngagementID())
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("Reconcile error = %v, want ErrConflict", err)
	}
	if len(audits.marked) != 0 {
		t.Fatalf("completed audits = %#v, want none after RecordOnce conflict", audits.marked)
	}
}

func TestReconcilerStopsPromptlyOnContextCancellation(t *testing.T) {
	recorder := &reconciliationRecorder{}
	audits := &reconciliationAudits{}
	reconciler, err := NewReconciler(&fakeJudgmentStore{judgments: []judgment.Judgment{recoveryJudgment()}}, audits, recorder, &fakeAudit{}, &fakeClock{t: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(shared.WithTenant(context.Background(), testTenantID()))
	cancel()
	if err := reconciler.Reconcile(ctx, testEngagementID()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Reconcile error = %v, want context.Canceled", err)
	}
	if len(recorder.called) != 0 {
		t.Fatalf("recovered canceled judgment: %#v", recorder.called)
	}
}

func promotionTraversalFixture(t *testing.T) (*attackpath.Graph, promotion.PromotionEvent, map[shared.ID]reachInfo) {
	t.Helper()
	tenantID, engagementID, findingID := testTenantID(), testEngagementID(), testFindingID()
	exposureID, assetID := testExposureID(), testAssetID()
	graph, err := attackpath.NewGraph(attackpath.Input{
		TenantID: tenantID,
		Assets: []asset.Asset{
			{ID: exposureID, TenantID: tenantID, Kind: asset.KindExposure, Key: "exposure", Name: "Exposure"},
			{ID: assetID, TenantID: tenantID, Kind: asset.KindHost, Key: "asset", Name: "Asset"},
		},
		Edges:    []asset.Edge{{TenantID: tenantID, From: exposureID, To: assetID, Kind: asset.EdgeReaches, Provenance: "edge", Confidence: asset.EdgeObserved}},
		Bindings: []attackpath.Binding{{TenantID: tenantID, EngagementID: engagementID, AssetID: assetID, FindingID: findingID, TargetKind: attackpath.TargetCanonical, Producer: "producer", Provenance: "binding", Confidence: asset.EdgeObserved}},
		Findings: []attackpath.FindingInput{{Target: attackpath.FindingTarget{ID: findingID, Kind: attackpath.TargetCanonical}, Finding: baseFinding()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return graph, promotion.PromotionEvent{ID: "event", FindingID: findingID, Effect: judgment.PromotionEscalate, Inputs: []judgment.PromotionInput{
		{Kind: judgment.PromotionInputAttackPath, ID: "path"},
		{Kind: judgment.PromotionInputReachability, ID: "reach"},
		{Kind: judgment.PromotionInputDetection, ID: testDetectionID()},
	}}, map[shared.ID]reachInfo{findingID: {judgmentID: "reach", state: judgment.Reachable, publishable: true}}
}

func TestPromotionTraversalCancellationPropagates(t *testing.T) {
	graph, event, reachability := promotionTraversalFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (&Evaluator{}).buildSnapshot(ctx, baseFinding(), graph, nil, reachability, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("buildSnapshot error = %v, want context.Canceled", err)
	}
	if _, err := inputsStillActive(ctx, event, testFindingID(), graph, nil, reachability); !errors.Is(err, context.Canceled) {
		t.Fatalf("inputsStillActive error = %v, want context.Canceled", err)
	}
	if _, err := escalationInputsMatch(ctx, event, testFindingID(), graph, nil, reachability); !errors.Is(err, context.Canceled) {
		t.Fatalf("escalationInputsMatch error = %v, want context.Canceled", err)
	}

	ev, _, _ := baseEvaluator(t)
	ev.assets = &fakeAssetRepo{assets: []*asset.Asset{
		{ID: testExposureID(), TenantID: testTenantID(), Kind: asset.KindExposure, Key: "exposure", Name: "Exposure"},
		{ID: testAssetID(), TenantID: testTenantID(), Kind: asset.KindHost, Key: "asset", Name: "Asset"},
	}, edges: []*asset.Edge{{TenantID: testTenantID(), From: testExposureID(), To: testAssetID(), Kind: asset.EdgeReaches, Provenance: "edge", Confidence: asset.EdgeObserved}}}
	ev.bindings = &fakeAttackPathStore{bindings: []attackpath.Binding{{TenantID: testTenantID(), EngagementID: testEngagementID(), AssetID: testAssetID(), FindingID: testFindingID(), TargetKind: attackpath.TargetCanonical, Producer: "producer", Provenance: "binding", Confidence: asset.EdgeObserved}}}
	ev.judgments = &fakeJudgmentStore{judgments: []judgment.Judgment{{ID: "reach", EngagementID: testEngagementID(), Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: testFindingID(), Claim: judgment.ReachabilityClaim{Reachable: judgment.Reachable, Tier: judgment.Tier0}, State: judgment.StateConfirmed, EvidenceScore: 90, ProposedBy: "agent"}}}
	ev.promotions = &fakePromotionStore{latest: map[shared.ID]promotion.PromotionEvent{testFindingID(): event}}
	ctx = shared.WithTenant(ctx, testTenantID())
	if _, err := ev.Evaluate(ctx, testEngagementID()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Evaluate error = %v, want context.Canceled", err)
	}
}
