package taintscan

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const engID = shared.ID("eng-1")

type fakeBuilder struct {
	g   *callgraph.Graph
	err error
}

func (f *fakeBuilder) Build(context.Context, string) (*callgraph.Graph, error) { return f.g, f.err }

type proposeCall struct {
	proposer    string
	capability  judgment.Capability
	subjectKind judgment.SubjectKind
	subjectID   shared.ID
	claim       judgment.Claim
}

type fakeProposer struct {
	calls []proposeCall
	err   error
	n     int
}

// Propose records the call and exercises the REAL judgment.New (canonicalize + Validate) so a malformed
// SASTClaim from the coordinator fails the test rather than passing silently.
func (f *fakeProposer) Propose(_ context.Context, proposer string, eng shared.ID, cap judgment.Capability, sk judgment.SubjectKind, sid shared.ID, claim judgment.Claim) (judgment.Judgment, error) {
	f.calls = append(f.calls, proposeCall{proposer, cap, sk, sid, claim})
	if f.err != nil {
		return judgment.Judgment{}, f.err
	}
	f.n++
	j, err := judgment.New(shared.ID(fmt.Sprintf("j%d", f.n)), eng, cap, sk, sid, claim, proposer, time.Unix(0, 0).UTC())
	if err != nil {
		return judgment.Judgment{}, err
	}
	return j, nil
}

type fakeAudit struct{ entries []ports.AuditEntry }

func (f *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	f.entries = append(f.entries, e)
	return nil
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(0, 0).UTC() }

func newCoord(t *testing.T, b builder, p proposer, a ports.AuditLogger) *Coordinator {
	t.Helper()
	c, err := NewCoordinator(b, p, taint.DefaultCatalog(), a, fixedClock{})
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	return c
}

// The classic same-function injection (os/exec.Command on os.Getenv data) is proposed as ONE gated
// CapSAST judgment under the reserved system identity, subjected to the data flow, with the witness path
// recorded in the audit log.
func TestScanProposesSameFunctionInjection(t *testing.T) {
	b := &fakeBuilder{g: &callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.handler", Callees: []string{"os.Getenv", "os/exec.Command"}},
	}}}
	p := &fakeProposer{}
	a := &fakeAudit{}
	n, err := newCoord(t, b, p, a).Scan(context.Background(), engID, "/work/target")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 1 || len(p.calls) != 1 {
		t.Fatalf("want 1 proposal, got n=%d calls=%d", n, len(p.calls))
	}
	c := p.calls[0]
	if c.proposer != "system:taint-scan" {
		t.Errorf("must propose under the reserved system identity, got %q", c.proposer)
	}
	if c.capability != judgment.CapSAST || c.subjectKind != judgment.SubjectDataFlow {
		t.Errorf("want CapSAST/SubjectDataFlow, got %s/%s", c.capability, c.subjectKind)
	}
	sc, ok := c.claim.(judgment.SASTClaim)
	if !ok {
		t.Fatalf("claim must be a SASTClaim, got %T", c.claim)
	}
	if sc.CWE != "CWE-78" || sc.Rule != "taint-command-injection" || sc.Location != "app.handler" {
		t.Errorf("claim must carry the cmd-injection class at the sink-using function: %+v", sc)
	}
	// The witness is recorded as attributable evidence, symbols only.
	if len(a.entries) != 1 || a.entries[0].Action != "judgment.taint_proposed" {
		t.Fatalf("the proposal must record a witness audit entry: %+v", a.entries)
	}
	if got := a.entries[0].Metadata["path"]; got != "app.handler" {
		t.Errorf("witness path must be the symbol path, got %q", got)
	}
	if a.entries[0].Metadata["cwe"] != "CWE-78" {
		t.Errorf("witness must carry the injection class: %+v", a.entries[0].Metadata)
	}
}

// A sink-using function reached via a forward call chain is proposed with the cross-function witness path.
func TestScanProposesCrossFunctionWitness(t *testing.T) {
	b := &fakeBuilder{g: &callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.handler", Callees: []string{"os.Getenv", "app.dao"}},
		{Caller: "app.dao", Callees: []string{"database/sql.DB.Query"}},
	}}}
	p := &fakeProposer{}
	a := &fakeAudit{}
	n, err := newCoord(t, b, p, a).Scan(context.Background(), engID, "/work/target")
	if err != nil || n != 1 {
		t.Fatalf("want 1 proposal, got n=%d err=%v", n, err)
	}
	sc := p.calls[0].claim.(judgment.SASTClaim)
	if sc.CWE != "CWE-89" || sc.Location != "app.dao" {
		t.Errorf("want SQLi at app.dao, got %+v", sc)
	}
	if got := a.entries[0].Metadata["path"]; got != "app.handler → app.dao" {
		t.Errorf("witness must be the call chain, got %q", got)
	}
}

// A function reaching two injection classes yields a proposal per class.
func TestScanMultiClassEmitsPerClass(t *testing.T) {
	b := &fakeBuilder{g: &callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.h", Callees: []string{"os.Getenv", "database/sql.DB.Query", "os/exec.Command"}},
	}}}
	p := &fakeProposer{}
	n, err := newCoord(t, b, p, &fakeAudit{}).Scan(context.Background(), engID, "/work/target")
	if err != nil || n != 2 {
		t.Fatalf("want 2 proposals (one per class), got n=%d err=%v", n, err)
	}
	cwes := map[string]bool{}
	for _, c := range p.calls {
		cwes[c.claim.(judgment.SASTClaim).CWE] = true
	}
	if !cwes["CWE-89"] || !cwes["CWE-78"] {
		t.Errorf("both injection classes must be proposed, got %v", cwes)
	}
}

// Two sinks of the SAME class at one function (DB.Query + DB.Exec, both CWE-89) are ONE finding: the
// claim is byte-identical, so it must be proposed once (no duplicate judgments/seals/audit – the bug the
// go-arch review caught). DefaultCatalog has 10 SQLi symbols, so this is the common case, not an edge.
func TestScanSameClassSinkDedup(t *testing.T) {
	b := &fakeBuilder{g: &callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.dao", Callees: []string{"os.Getenv", "database/sql.DB.Query", "database/sql.DB.Exec"}},
	}}}
	p := &fakeProposer{}
	a := &fakeAudit{}
	n, err := newCoord(t, b, p, a).Scan(context.Background(), engID, "/work/target")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 1 || len(p.calls) != 1 {
		t.Fatalf("same-class sibling sinks must propose once, got n=%d calls=%d", n, len(p.calls))
	}
	if len(a.entries) != 1 {
		t.Errorf("only one witness entry must be recorded for the deduped class, got %d", len(a.entries))
	}
}

// A no-coverage build error proposes NOTHING and never a false "clean" (fail-closed).
func TestScanNoCoverageProposesNothing(t *testing.T) {
	b := &fakeBuilder{err: errors.New("module cache offline")}
	p := &fakeProposer{}
	a := &fakeAudit{}
	n, err := newCoord(t, b, p, a).Scan(context.Background(), engID, "/work/target")
	if err == nil {
		t.Error("a build error must surface (no coverage), not be swallowed as clean")
	}
	if n != 0 || len(p.calls) != 0 || len(a.entries) != 0 {
		t.Errorf("no coverage must propose + audit nothing, got n=%d calls=%d entries=%d", n, len(p.calls), len(a.entries))
	}
}

// A contract-violating builder returning (nil, nil) is treated as no-coverage, not dereferenced.
func TestScanNilGraphFailsClosed(t *testing.T) {
	b := &fakeBuilder{g: nil, err: nil}
	p := &fakeProposer{}
	if _, err := newCoord(t, b, p, &fakeAudit{}).Scan(context.Background(), engID, "/t"); err == nil {
		t.Error("a nil graph with nil error must fail closed, not panic or propose")
	}
}

// A successful build with no catalog hits proposes nothing (a genuinely clean target – no error).
func TestScanCleanTargetProposesNothing(t *testing.T) {
	b := &fakeBuilder{g: &callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.main", Callees: []string{"fmt.Println", "app.helper"}},
	}}}
	p := &fakeProposer{}
	n, err := newCoord(t, b, p, &fakeAudit{}).Scan(context.Background(), engID, "/work/target")
	if err != nil || n != 0 || len(p.calls) != 0 {
		t.Errorf("a clean build must propose nothing with no error, got n=%d err=%v", n, err)
	}
}

// The subject id is a stable idempotency key: the same flow across two scans maps to the same subject.
func TestScanSubjectIDStable(t *testing.T) {
	mk := func() *fakeProposer {
		b := &fakeBuilder{g: &callgraph.Graph{Edges: []callgraph.Edge{
			{Caller: "app.handler", Callees: []string{"os.Getenv", "os/exec.Command"}},
		}}}
		p := &fakeProposer{}
		if _, err := newCoord(t, b, p, &fakeAudit{}).Scan(context.Background(), engID, "/work/target"); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		return p
	}
	a, b := mk(), mk()
	if a.calls[0].subjectID != b.calls[0].subjectID || a.calls[0].subjectID.IsZero() {
		t.Errorf("the same flow must map to the same non-zero subject id across scans: %q vs %q", a.calls[0].subjectID, b.calls[0].subjectID)
	}
}

// A proposer error aborts the pass (returns the error + the partial count) rather than silently dropping.
func TestScanProposerErrorAborts(t *testing.T) {
	b := &fakeBuilder{g: &callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.h", Callees: []string{"os.Getenv", "os/exec.Command"}},
	}}}
	p := &fakeProposer{err: errors.New("store down")}
	if _, err := newCoord(t, b, p, &fakeAudit{}).Scan(context.Background(), engID, "/work/target"); err == nil {
		t.Error("a propose error must surface")
	}
}

func TestNewCoordinatorValidates(t *testing.T) {
	good := taint.DefaultCatalog()
	b, p, a, c := &fakeBuilder{}, &fakeProposer{}, &fakeAudit{}, fixedClock{}
	if _, err := NewCoordinator(nil, p, good, a, c); err == nil {
		t.Error("nil builder must be rejected")
	}
	if _, err := NewCoordinator(b, nil, good, a, c); err == nil {
		t.Error("nil proposer must be rejected")
	}
	if _, err := NewCoordinator(b, p, taint.Catalog{}, a, c); err == nil {
		t.Error("an empty catalog must be rejected (it would silently propose nothing)")
	}
}

// The reserved proposer identity must be in the system namespace (no agent/human factory can mint it).
func TestProposerActorIsSystemNamespace(t *testing.T) {
	if !strings.HasPrefix(proposerActor, "system:") {
		t.Errorf("proposer identity must be a reserved system: identity, got %q", proposerActor)
	}
}
