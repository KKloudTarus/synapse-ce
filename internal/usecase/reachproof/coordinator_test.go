package reachproof

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/verdict"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
)

// --- fakes ---

type fakeAnalyzer struct {
	res []reachability.Result
	err error
}

func (f fakeAnalyzer) Analyze(context.Context, string, []string) (*reachability.Analysis, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &reachability.Analysis{Results: f.res, Entrypoints: []string{"app.main"}}, nil
}

type proposeCall struct {
	proposer  string
	subjectID shared.ID
	claim     judgment.ReachabilityClaim
}
type verifyCall struct {
	verifier  string
	score     int
	rationale string
}

type fakeRecorder struct {
	prior    []judgment.Judgment
	proposes []proposeCall
	verifies []verifyCall
	nextID   int
}

func (r *fakeRecorder) Propose(_ context.Context, proposer string, _ shared.ID, _ judgment.Capability, _ judgment.SubjectKind, subjectID shared.ID, claim judgment.Claim) (judgment.Judgment, error) {
	rc, _ := claim.(judgment.ReachabilityClaim)
	r.proposes = append(r.proposes, proposeCall{proposer: proposer, subjectID: subjectID, claim: rc})
	r.nextID++
	return judgment.Judgment{ID: shared.ID(string(rune('a' + r.nextID))), Version: 1, ProposedBy: proposer, SubjectID: subjectID, Claim: rc}, nil
}

func (r *fakeRecorder) Verify(_ context.Context, verifier string, _, _ shared.ID, score int, rationale string, _ int) (judgment.Judgment, error) {
	r.verifies = append(r.verifies, verifyCall{verifier: verifier, score: score, rationale: rationale})
	return judgment.Judgment{}, nil
}

func (r *fakeRecorder) List(context.Context, shared.ID) ([]judgment.Judgment, error) {
	return r.prior, nil
}

type fakeAudit struct{ actions []string }

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.actions = append(a.actions, e.Action)
	return nil
}

func newCoord(t *testing.T, a analyzer, r recorder) *Coordinator {
	t.Helper()
	c, err := NewCoordinator(a, r, &fakeAudit{}, fakeClock{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type fakeClock struct{}

func (fakeClock) Now() time.Time { return time.Unix(1_000_000, 0).UTC() }

// --- tests ---

// TestRecordReachableMintsConfirmedTier2 (C1/C2): a reachable result mints a Tier-2 judgment via
// propose(scan) -> verify(engine) – two DISTINCT reserved non-agent identities, score = deterministic
// proof score, rationale = the proof path.
func TestRecordReachableMintsConfirmedTier2(t *testing.T) {
	rec := &fakeRecorder{}
	c := newCoord(t, fakeAnalyzer{res: []reachability.Result{
		{Symbol: "dep.vuln", Reachable: true, Path: []string{"app.main", "app.a", "dep.vuln"}},
	}}, rec)
	n, err := c.Record(context.Background(), "eng-1", "/work", []ports.ReachabilitySubject{{FindingID: "f1", Symbols: []string{"dep.vuln"}}})
	if err != nil || n != 1 {
		t.Fatalf("want 1 minted, got n=%d err=%v", n, err)
	}
	if len(rec.proposes) != 1 || rec.proposes[0].proposer != proposerActor || rec.proposes[0].claim.Tier != judgment.Tier2 ||
		rec.proposes[0].claim.Reachable != judgment.Reachable {
		t.Fatalf("propose wrong: %+v", rec.proposes)
	}
	if len(rec.verifies) != 1 || rec.verifies[0].verifier != verifierActor || rec.verifies[0].score != verdict.DeterministicProofScore {
		t.Fatalf("verify wrong: %+v", rec.verifies)
	}
	// C1: the two identities are distinct, so the self-confirm guard never fires
	if verdict.SelfConfirm(verifierActor, proposerActor) {
		t.Error("proposer and verifier must be distinct (self-confirm guard)")
	}
	// proof path is in the rationale (C6), no file contents
	if rec.verifies[0].rationale == "" || rec.verifies[0].rationale[:6] != "tier-2" {
		t.Errorf("rationale should carry the proof, got %q", rec.verifies[0].rationale)
	}
}

// TestRecordNotReachable: a successful build that doesn't reach the symbol mints a definitive Tier-2
// not-reachable judgment (distinct from no-coverage).
func TestRecordNotReachable(t *testing.T) {
	rec := &fakeRecorder{}
	c := newCoord(t, fakeAnalyzer{res: []reachability.Result{{Symbol: "dep.vuln", Reachable: false}}}, rec)
	n, err := c.Record(context.Background(), "eng-1", "/work", []ports.ReachabilitySubject{{FindingID: "f1", Symbols: []string{"dep.vuln"}}})
	if err != nil || n != 1 {
		t.Fatalf("want 1 minted, got n=%d err=%v", n, err)
	}
	if rec.proposes[0].claim.Reachable != judgment.NotReachable || rec.proposes[0].claim.Tier != judgment.Tier2 {
		t.Errorf("want a Tier-2 not-reachable claim, got %+v", rec.proposes[0].claim)
	}
}

// TestSupersedesPriorTier15: a Tier-2 result supersedes a prior LLM Tier-1.5 judgment -> mints + audits
// the supersession naming both sides (C4). The prior judgment is never mutated (the fake exposes no
// mutate path; the coordinator only Propose/Verify/List).
func TestSupersedesPriorTier15(t *testing.T) {
	audit := &fakeAudit{}
	prior := judgment.Judgment{
		ID: "old1", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "f1",
		Claim: judgment.ReachabilityClaim{Reachable: judgment.NotReachable, Tier: judgment.Tier1_5, Confidence: 60},
	}
	rec := &fakeRecorder{prior: []judgment.Judgment{prior}}
	c, _ := NewCoordinator(fakeAnalyzer{res: []reachability.Result{{Symbol: "dep.vuln", Reachable: true, Path: []string{"app.main", "dep.vuln"}}}}, rec, audit, fakeClock{})
	n, err := c.Record(context.Background(), "eng-1", "/work", []ports.ReachabilitySubject{{FindingID: "f1", Symbols: []string{"dep.vuln"}}})
	if err != nil || n != 1 {
		t.Fatalf("want 1 minted (supersedes Tier-1.5), got n=%d err=%v", n, err)
	}
	var superseded bool
	for _, a := range audit.actions {
		if a == "judgment.superseded" {
			superseded = true
		}
	}
	if !superseded {
		t.Errorf("a supersession must be audited (both sides), got actions %v", audit.actions)
	}
}

// TestDoesNotChurnSameTier (C4): a prior Tier-2 judgment is NOT superseded by another Tier-2 run (same
// rank) – no propose/verify, no churn.
func TestDoesNotChurnSameTier(t *testing.T) {
	prior := judgment.Judgment{
		ID: "old1", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "f1",
		Claim: judgment.ReachabilityClaim{Reachable: judgment.Reachable, Tier: judgment.Tier2, Confidence: 90},
	}
	rec := &fakeRecorder{prior: []judgment.Judgment{prior}}
	c := newCoord(t, fakeAnalyzer{res: []reachability.Result{{Symbol: "dep.vuln", Reachable: true, Path: []string{"app.main", "dep.vuln"}}}}, rec)
	n, err := c.Record(context.Background(), "eng-1", "/work", []ports.ReachabilitySubject{{FindingID: "f1", Symbols: []string{"dep.vuln"}}})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || len(rec.proposes) != 0 {
		t.Errorf("a same-tier prior must not churn; minted=%d proposes=%d", n, len(rec.proposes))
	}
}

// TestNoCoverageMintsNothing (C5): a builder error (no coverage) aborts the pass – nothing minted, the
// weaker prior stands, never a false "not reachable".
func TestNoCoverageMintsNothing(t *testing.T) {
	rec := &fakeRecorder{}
	buildErr := errors.New("go: cannot find main module")
	c := newCoord(t, fakeAnalyzer{err: buildErr}, rec)
	n, err := c.Record(context.Background(), "eng-1", "/work", []ports.ReachabilitySubject{{FindingID: "f1", Symbols: []string{"dep.vuln"}}})
	if err == nil || !errors.Is(err, buildErr) {
		t.Fatalf("no coverage must surface the build error, got %v", err)
	}
	if n != 0 || len(rec.proposes) != 0 {
		t.Errorf("no coverage must mint nothing, minted=%d proposes=%d", n, len(rec.proposes))
	}
}

func TestNewCoordinatorValidates(t *testing.T) {
	if _, err := NewCoordinator(nil, &fakeRecorder{}, &fakeAudit{}, fakeClock{}); !errors.Is(err, shared.ErrValidation) {
		t.Error("nil analyzer must fail validation")
	}
}
