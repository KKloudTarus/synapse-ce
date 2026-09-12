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

func TestPythonTier2UsesDistinctSemanticProofActors(t *testing.T) {
	proposer, verifier, label := actorsFor(judgment.Tier2, LanguagePython)
	if proposer != judgment.ProofActorPySemanticScan || verifier != judgment.ProofActorPySemanticEngine {
		t.Fatalf("python tier-2 actors = (%q,%q)", proposer, verifier)
	}
	if label != "tier-2 python semantic call-graph proof" {
		t.Fatalf("python tier-2 label = %q", label)
	}
	goProposer, goVerifier, _ := actorsForTier(judgment.Tier2)
	if goProposer != judgment.ProofActorCallgraphScan || goVerifier != judgment.ProofActorCallgraphEngine {
		t.Fatalf("default Go callgraph actors changed = (%q,%q)", goProposer, goVerifier)
	}
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
	if len(rec.proposes) != 1 || rec.proposes[0].proposer != "system:callgraph-scan" || rec.proposes[0].claim.Tier != judgment.Tier2 ||
		rec.proposes[0].claim.Reachable != judgment.Reachable {
		t.Fatalf("propose wrong: %+v", rec.proposes)
	}
	if len(rec.verifies) != 1 || rec.verifies[0].verifier != "system:callgraph-engine" || rec.verifies[0].score != verdict.DeterministicProofScore {
		t.Fatalf("verify wrong: %+v", rec.verifies)
	}
	// C1: the two identities are distinct, so the self-confirm guard never fires
	if verdict.SelfConfirm("system:callgraph-engine", "system:callgraph-scan") {
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

// TestJVMVerdictMintsTier15 (D4.4): RecordVerdicts mints Tier-1.5 JVM class-reachability judgments from
// pre-computed verdicts, with the reserved JVM actors, via propose(scan)->verify(engine).
func TestJVMVerdictMintsTier15(t *testing.T) {
	rec := &fakeRecorder{}
	c, err := NewJVMVerdictCoordinator(rec, &fakeAudit{}, fakeClock{})
	if err != nil {
		t.Fatal(err)
	}
	n, err := c.RecordVerdicts(context.Background(), "eng-1", []ports.JVMReachabilityVerdict{
		{FindingID: "f1", Reachable: true},
		{FindingID: "f2", Reachable: false},
	})
	if err != nil || n != 2 {
		t.Fatalf("want 2 minted, got n=%d err=%v", n, err)
	}
	for _, p := range rec.proposes {
		if p.proposer != judgment.ProofActorJVMClassScan || p.claim.Tier != judgment.Tier1_5 {
			t.Fatalf("propose wrong (want jvmclass-scan + tier-1.5): %+v", p)
		}
	}
	if rec.proposes[0].claim.Reachable != judgment.Reachable || rec.proposes[1].claim.Reachable != judgment.NotReachable {
		t.Fatalf("verdicts wrong: %+v", rec.proposes)
	}
	for _, v := range rec.verifies {
		if v.verifier != judgment.ProofActorJVMClassEngine {
			t.Fatalf("verify actor wrong: %+v", v)
		}
	}
	// Distinct identities: the self-confirm guard never fires.
	if verdict.SelfConfirm(judgment.ProofActorJVMClassEngine, judgment.ProofActorJVMClassScan) {
		t.Error("jvm proposer and verifier must be distinct")
	}
}

// TestJVMNotReachableNeverPromotes is the D4.4 SOUNDNESS invariant: a JVM (Tier-1.5) not-reachable verdict is
// NEVER a deterministic promotable proof, so it can never become a VEX not_affected. JVM class-reachability
// is coarse and reflection-blind; it must only deprioritize, never suppress.
func TestJVMNotReachableNeverPromotes(t *testing.T) {
	if judgment.IsDeterministicReachabilityProof(judgment.Tier1_5, judgment.ProofActorJVMClassScan, judgment.ProofActorJVMClassEngine) {
		t.Fatal("a Tier-1.5 JVM verdict must NEVER be a deterministic proof (would wrongly promote to not_affected)")
	}
}

// TestJVMVerdictDoesNotSupersedeStrongerPrior: a prior Tier-2 call-graph proof stands; a JVM Tier-1.5 verdict
// for the same finding mints nothing (no churn, no downgrade of a stronger proof).
func TestJVMVerdictDoesNotSupersedeStrongerPrior(t *testing.T) {
	rec := &fakeRecorder{prior: []judgment.Judgment{{
		ID: "prior", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "f1",
		Claim: judgment.ReachabilityClaim{Reachable: judgment.NotReachable, Tier: judgment.Tier2, Confidence: 100},
	}}}
	c, err := NewJVMVerdictCoordinator(rec, &fakeAudit{}, fakeClock{})
	if err != nil {
		t.Fatal(err)
	}
	n, err := c.RecordVerdicts(context.Background(), "eng-1", []ports.JVMReachabilityVerdict{{FindingID: "f1", Reachable: true}})
	if err != nil || n != 0 {
		t.Fatalf("a stronger Tier-2 prior must stand: got n=%d err=%v", n, err)
	}
	if len(rec.proposes) != 0 {
		t.Errorf("must not mint over a stronger prior: %+v", rec.proposes)
	}
}

// TestSkipUnresolvedSubjectsMintsNothingForUnknown: a build-aware coordinator with
// WithSkipUnresolvedSubjects leaves the prior tier standing (mints nothing) when the analyzer returns NO
// result for a subject, so an UNKNOWN subject can never become a false not_affected.
func TestSkipUnresolvedSubjectsMintsNothingForUnknown(t *testing.T) {
	rec := &fakeRecorder{}
	c := newCoord(t, fakeAnalyzer{res: []reachability.Result{{Symbol: "decided.dep", Reachable: false}}}, rec).
		WithSkipUnresolvedSubjects()
	n, err := c.Record(context.Background(), "eng-1", "/work", []ports.ReachabilitySubject{
		{FindingID: "f-decided", Symbols: []string{"decided.dep"}}, // analyzer decided: not reachable
		{FindingID: "f-unknown", Symbols: []string{"unknown.dep"}}, // analyzer returned no result: UNKNOWN
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("only the decided subject must mint; got %d", n)
	}
	if len(rec.proposes) != 1 || rec.proposes[0].subjectID != "f-decided" {
		t.Fatalf("the unknown subject must mint nothing; proposes=%+v", rec.proposes)
	}
	if rec.proposes[0].claim.Reachable != judgment.NotReachable {
		t.Errorf("the decided subject is proven unreachable; got %+v", rec.proposes[0].claim)
	}
}

// TestUnresolvedSubjectDefaultsNotReachableWithoutFlag: without the flag the legacy behaviour holds (a
// subject with no result is treated not-reachable), so the change does not alter the other languages.
func TestUnresolvedSubjectDefaultsNotReachableWithoutFlag(t *testing.T) {
	rec := &fakeRecorder{}
	c := newCoord(t, fakeAnalyzer{res: nil}, rec) // analyzer returned no results at all
	n, err := c.Record(context.Background(), "eng-1", "/work", []ports.ReachabilitySubject{
		{FindingID: "f1", Symbols: []string{"dep.vuln"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(rec.proposes) != 1 || rec.proposes[0].claim.Reachable != judgment.NotReachable {
		t.Fatalf("without the flag an unresolved subject must default not-reachable; n=%d proposes=%+v", n, rec.proposes)
	}
}

func TestDotNetTier1UsesDistinctProofActors(t *testing.T) {
	proposer, verifier, label := actorsFor(judgment.Tier1, LanguageDotNet)
	if proposer != judgment.ProofActorDotNetReachScan || verifier != judgment.ProofActorDotNetReachEngine {
		t.Fatalf("dotnet tier-1 actors = (%q,%q), must not fall through to python", proposer, verifier)
	}
	if !judgment.IsDeterministicReachabilityProof(judgment.Tier1, proposer, verifier) {
		t.Error("the build-aware dotnet proof must be a deterministic (suppressing) proof")
	}
	_ = label
}

// TestSkipModePartialSubjectMintsNothing: in skip mode a subject with one symbol proven not-reachable and
// another symbol UNKNOWN (no result) must mint nothing, because the unknown symbol could be reached.
func TestSkipModePartialSubjectMintsNothing(t *testing.T) {
	rec := &fakeRecorder{}
	c := newCoord(t, fakeAnalyzer{res: []reachability.Result{{Symbol: "a", Reachable: false}}}, rec).
		WithSkipUnresolvedSubjects()
	n, err := c.Record(context.Background(), "eng-1", "/work", []ports.ReachabilitySubject{
		{FindingID: "f1", Symbols: []string{"a", "b"}}, // b has no result -> partially unknown
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || len(rec.proposes) != 0 {
		t.Errorf("a partially-unknown subject must mint nothing in skip mode; n=%d proposes=%+v", n, rec.proposes)
	}
}

// WithRaiseOnly mints a reachable claim exactly like the default: raise-only only affects the negative.
func TestRaiseOnlyMintsReachable(t *testing.T) {
	rec := &fakeRecorder{}
	c := newCoord(t, fakeAnalyzer{res: []reachability.Result{
		{Symbol: "dep.vuln", Reachable: true, Path: []string{"app.main", "dep.vuln"}},
	}}, rec).WithRaiseOnly()
	n, err := c.Record(context.Background(), "eng-1", "/work", []ports.ReachabilitySubject{{FindingID: "f1", Symbols: []string{"dep.vuln"}}})
	if err != nil || n != 1 {
		t.Fatalf("want 1 minted, got n=%d err=%v", n, err)
	}
	if rec.proposes[0].claim.Reachable != judgment.Reachable {
		t.Errorf("want a reachable claim, got %+v", rec.proposes[0].claim)
	}
}

// WithRaiseOnly must NEVER mint a not-reachable (suppressing) claim, even for a definitively un-reached
// subject (contrast TestRecordNotReachable, which mints one without the flag). The prior tier stands.
func TestRaiseOnlyNeverMintsNotReachable(t *testing.T) {
	rec := &fakeRecorder{}
	c := newCoord(t, fakeAnalyzer{res: []reachability.Result{{Symbol: "dep.vuln", Reachable: false}}}, rec).WithRaiseOnly()
	n, err := c.Record(context.Background(), "eng-1", "/work", []ports.ReachabilitySubject{{FindingID: "f1", Symbols: []string{"dep.vuln"}}})
	if err != nil || n != 0 {
		t.Fatalf("raise-only must mint nothing for an un-reached subject, got n=%d err=%v", n, err)
	}
	if len(rec.proposes) != 0 {
		t.Fatalf("raise-only must not propose a not-reachable claim, got %+v", rec.proposes)
	}
}

// With a mix, raise-only mints only the reached subject and leaves the un-reached one to the prior tier.
func TestRaiseOnlyMintsOnlyTheReached(t *testing.T) {
	rec := &fakeRecorder{}
	c := newCoord(t, fakeAnalyzer{res: []reachability.Result{
		{Symbol: "hit", Reachable: true, Path: []string{"app.main", "hit"}},
		{Symbol: "miss", Reachable: false},
	}}, rec).WithRaiseOnly()
	n, err := c.Record(context.Background(), "eng-1", "/work", []ports.ReachabilitySubject{
		{FindingID: "f1", Symbols: []string{"hit"}},
		{FindingID: "f2", Symbols: []string{"miss"}},
	})
	if err != nil || n != 1 {
		t.Fatalf("want only the reached subject minted, got n=%d err=%v", n, err)
	}
	if len(rec.proposes) != 1 || rec.proposes[0].claim.Reachable != judgment.Reachable {
		t.Fatalf("only the reached subject should mint (reachable), got %+v", rec.proposes)
	}
}
