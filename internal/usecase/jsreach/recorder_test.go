package jsreach

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type recordedJudgment struct {
	proposer string
	verifier string
	claim    judgment.ReachabilityClaim
}

type fakeJudgments struct {
	minted []recordedJudgment
}

func (f *fakeJudgments) Propose(_ context.Context, proposer string, _ shared.ID, _ judgment.Capability, _ judgment.SubjectKind, subjectID shared.ID, claim judgment.Claim) (judgment.Judgment, error) {
	rc, _ := claim.(judgment.ReachabilityClaim)
	f.minted = append(f.minted, recordedJudgment{proposer: proposer, claim: rc})
	return judgment.Judgment{ID: subjectID, Version: 1}, nil
}

func (f *fakeJudgments) Verify(_ context.Context, verifier string, _, _ shared.ID, _ int, _ string, _ int) (judgment.Judgment, error) {
	if len(f.minted) > 0 {
		f.minted[len(f.minted)-1].verifier = verifier
	}
	return judgment.Judgment{}, nil
}

func (f *fakeJudgments) List(context.Context, shared.ID) ([]judgment.Judgment, error) {
	return nil, nil
}

type fakeAudit struct{}

func (fakeAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(1700000000, 0).UTC() }

func recorderFor(t *testing.T, graph modulegraph.Graph, result jsresolution.Result, doc *sbom.SBOM) (*Recorder, *fakeJudgments) {
	t.Helper()
	judgments := &fakeJudgments{}
	r, err := NewRecorder(fakeScanner{graph: graph}, fakeResolver{result: result}, judgments, fakeAudit{}, fixedClock{})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	_ = doc
	return r, judgments
}

func TestRecorderValidatesDependencies(t *testing.T) {
	t.Parallel()

	if _, err := NewRecorder(nil, fakeResolver{}, &fakeJudgments{}, fakeAudit{}, fixedClock{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a nil scanner must be rejected, got %v", err)
	}
	r, err := NewRecorder(fakeScanner{}, fakeResolver{}, &fakeJudgments{}, fakeAudit{}, fixedClock{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// The SBOM the subjects were minted from is mandatory: reasoning over a different document would
	// silently miss every subject.
	if _, err := r.RecordWithSBOM(context.Background(), "eng1", "/ws", nil, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a nil sbom must be rejected, got %v", err)
	}
}

// TestRecorderDropsUnanswerableSubjects is the load-bearing R4 behaviour. The coordinator mints a claim
// for EVERY subject it is given and reads "no result" as not-reachable, so a subject the analyzer cannot
// answer must never reach it — otherwise a transitive package would be sealed as unused.
func TestRecorderDropsUnanswerableSubjects(t *testing.T) {
	t.Parallel()

	const direct = "pkg:npm/direct-dep@1.0.0"
	const transitive = "pkg:npm/transitive-dep@2.0.0"

	graph := modulegraph.Graph{Modules: []modulegraph.Module{mod("src/index.ts")}, Roots: []string{"src/index.ts"}}
	result := jsresolution.Result{
		Complete: true,
		// Only direct-dep is declared by a first-party manifest.
		DeclaredDependencies: []string{"direct-dep"},
	}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "direct-dep", Version: "1.0.0", PURL: direct},
		{Name: "transitive-dep", Version: "2.0.0", PURL: transitive},
	}}

	judgments := &fakeJudgments{}
	r, err := NewRecorder(fakeScanner{graph: graph}, fakeResolver{result: result}, judgments, fakeAudit{}, fixedClock{})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	minted, err := r.RecordWithSBOM(context.Background(), "eng1", "/ws", doc, []ports.ReachabilitySubject{
		{FindingID: "f-direct", Symbols: []string{direct}},
		{FindingID: "f-transitive", Symbols: []string{transitive}},
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	// Exactly one judgment: the transitive subject was dropped, not sealed as not-reachable.
	if minted != 1 {
		t.Fatalf("minted = %d, want exactly 1 (the direct dependency)", minted)
	}
	if len(judgments.minted) != 1 {
		t.Fatalf("expected one judgment, got %d", len(judgments.minted))
	}
}

// TestRecorderAttributesToTheJavaScriptEngine prevents a JavaScript proof from being credited to the
// Python import engine in the audit trail and the sealed rationale.
func TestRecorderAttributesToTheJavaScriptEngine(t *testing.T) {
	t.Parallel()

	const purl = "pkg:npm/lodash@4.17.21"
	graph := modulegraph.Graph{Modules: []modulegraph.Module{mod("src/index.ts")}, Roots: []string{"src/index.ts"}}
	imp := componentImport("src/index.ts", "lodash", purl)
	result := jsresolution.Result{
		Imports:              []jsresolution.ImportResolution{imp},
		Complete:             true,
		DeclaredDependencies: []string{"lodash"},
	}
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: purl}}}

	judgments := &fakeJudgments{}
	r, err := NewRecorder(fakeScanner{graph: graph}, fakeResolver{result: result}, judgments, fakeAudit{}, fixedClock{})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	if _, err := r.RecordWithSBOM(context.Background(), "eng1", "/ws", doc, []ports.ReachabilitySubject{
		{FindingID: "f1", Symbols: []string{purl}},
	}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if len(judgments.minted) != 1 {
		t.Fatalf("expected one judgment, got %d", len(judgments.minted))
	}
	got := judgments.minted[0]
	if got.proposer != "system:jsimport-scan" {
		t.Fatalf("proposer = %q, want the javascript import engine", got.proposer)
	}
	if got.verifier != "system:jsimport-engine" {
		t.Fatalf("verifier = %q, want the javascript import engine", got.verifier)
	}
	if got.proposer == got.verifier {
		t.Fatal("proposer and verifier must be distinct so a proof never self-confirms")
	}
	if got.claim.Reachable != judgment.Reachable || got.claim.Tier != judgment.Tier1 {
		t.Fatalf("claim = %+v, want a reachable Tier-1 claim", got.claim)
	}
}

func TestRecorderMintsNothingWhenCoverageIsIncomplete(t *testing.T) {
	t.Parallel()

	const purl = "pkg:npm/lodash@4.17.21"
	graph := modulegraph.Graph{
		Modules:  []modulegraph.Module{mod("src/index.ts")},
		Roots:    []string{"src/index.ts"},
		Coverage: []modulegraph.CoverageIssue{{Kind: modulegraph.CoverageDynamicRequire, Path: "src/index.ts"}},
	}
	result := jsresolution.Result{Complete: true, DeclaredDependencies: []string{"lodash"}}
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: purl}}}

	judgments := &fakeJudgments{}
	r, err := NewRecorder(fakeScanner{graph: graph}, fakeResolver{result: result}, judgments, fakeAudit{}, fixedClock{})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	minted, _ := r.RecordWithSBOM(context.Background(), "eng1", "/ws", doc, []ports.ReachabilitySubject{
		{FindingID: "f1", Symbols: []string{purl}},
	})
	if minted != 0 || len(judgments.minted) != 0 {
		t.Fatalf("an unobservable module load must mint nothing, got %d judgments", len(judgments.minted))
	}
}
