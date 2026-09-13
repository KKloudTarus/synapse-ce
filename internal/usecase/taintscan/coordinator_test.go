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
	"github.com/KKloudTarus/synapse-ce/internal/domain/symbolcanon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const engID = shared.ID("eng-1")

type fakeBuilder struct {
	g     *callgraph.Graph
	facts taint.ExecFacts // value-level exec-sink verdicts (D5.4); zero value = no de-escalation (keep CWE-78)
	err   error
}

func (f *fakeBuilder) BuildWithExecFacts(context.Context, string) (*callgraph.Graph, taint.ExecFacts, error) {
	return f.g, f.facts, f.err
}

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

type fakeAudit struct {
	entries []ports.AuditEntry
	err     error
}

func (f *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	f.entries = append(f.entries, e)
	return f.err
}
func (f *fakeAudit) RecordOnce(ctx context.Context, e ports.AuditEntry) error {
	return f.Record(ctx, e)
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

// #1050: a taint flow whose dangerous callee is an advisory's vulnerable symbol correlates to that SCA
// finding (the vuln is taint-reachable). The link is recorded in the witness metadata; a sink that is not
// an advisory symbol, or a coordinator without the index, records NO link (no fabricated correlation).
func TestScanCorrelatesSinkToSCAFinding(t *testing.T) {
	// app.handler reads a request value (source) and passes it to database/sql.DB.Query (sink, CWE-89).
	graph := func() *callgraph.Graph {
		return &callgraph.Graph{Edges: []callgraph.Edge{
			{Caller: "app.handler", Callees: []string{"net/http.Request.FormValue", "database/sql.DB.Query"}},
		}}
	}

	// With the advisory index naming database/sql.DB.Query as finding-sql's vulnerable symbol: correlated.
	p := &fakeProposer{}
	a := &fakeAudit{}
	c := newCoord(t, &fakeBuilder{g: graph()}, p, a).WithVulnerableSymbols(symbolcanon.Go, map[shared.ID][]string{
		"finding-sql":   {"database/sql.DB.Query"},
		"finding-other": {"github.com/unrelated/pkg.Safe"},
	})
	if _, err := c.Scan(context.Background(), engID, "/work/target"); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(a.entries) != 1 {
		t.Fatalf("want 1 witness entry, got %d", len(a.entries))
	}
	if got := a.entries[0].Metadata["correlated_findings"]; got != "finding-sql" {
		t.Errorf("sink into a vulnerable symbol must correlate to its finding, got %q", got)
	}

	// Without the index: no correlation recorded (default behavior unchanged).
	p2 := &fakeProposer{}
	a2 := &fakeAudit{}
	if _, err := newCoord(t, &fakeBuilder{g: graph()}, p2, a2).Scan(context.Background(), engID, "/work/target"); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if _, ok := a2.entries[0].Metadata["correlated_findings"]; ok {
		t.Errorf("no index must record no correlation, got %+v", a2.entries[0].Metadata)
	}

	// With an index whose symbols do not match the sink: no fabricated link.
	p3 := &fakeProposer{}
	a3 := &fakeAudit{}
	c3 := newCoord(t, &fakeBuilder{g: graph()}, p3, a3).WithVulnerableSymbols(symbolcanon.Go, map[shared.ID][]string{
		"finding-x": {"github.com/unrelated/pkg.Vuln"},
	})
	if _, err := c3.Scan(context.Background(), engID, "/work/target"); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if _, ok := a3.entries[0].Metadata["correlated_findings"]; ok {
		t.Errorf("a non-matching index must record no correlation, got %+v", a3.entries[0].Metadata)
	}
}

// D5.4: a same-function command-injection finding DE-ESCALATES from CWE-78 to CWE-88 when the SSA pass
// proves the exec program name (argv[0]) is a compile-time-constant, non-interpreter string at every call
// site (e.g. exec.Command("echo", userInput)). The finding is NOT removed — it still fires, at the same
// location and with the same witness path — only its injection class narrows.
func TestScanDeEscalatesConstantArgvToArgumentInjection(t *testing.T) {
	b := &fakeBuilder{
		g: &callgraph.Graph{Edges: []callgraph.Edge{
			{Caller: "app.handler", Callees: []string{"os.Getenv", "os/exec.Command"}},
		}},
		facts: taint.ExecFacts{Funcs: map[string]taint.ExecFuncFacts{
			"app.handler": {SafeSinks: map[string]bool{"os/exec.Command": true}},
		}},
	}
	p := &fakeProposer{}
	a := &fakeAudit{}
	n, err := newCoord(t, b, p, a).Scan(context.Background(), engID, "/work/target")
	if err != nil || n != 1 || len(p.calls) != 1 {
		t.Fatalf("want 1 proposal, got n=%d calls=%d err=%v", n, len(p.calls), err)
	}
	sc := p.calls[0].claim.(judgment.SASTClaim)
	if sc.CWE != "CWE-88" || sc.Rule != "taint-argument-injection" {
		t.Errorf("constant argv[0] must de-escalate to CWE-88 argument injection, got %+v", sc)
	}
	if a.entries[0].Metadata["cwe"] != "CWE-88" {
		t.Errorf("the witness must carry the de-escalated class, got %+v", a.entries[0].Metadata)
	}
}

// D5.4 fail-closed: an exec fact for a DIFFERENT function must not de-escalate one it does not cover. The
// unsafe twin (exec.Command(parts[0], parts[1:]...), a variable argv[0]) emits no constant-safe fact, so it
// keeps CWE-78.
func TestScanKeepsCommandInjectionWithoutConstantSafeFact(t *testing.T) {
	b := &fakeBuilder{
		g: &callgraph.Graph{Edges: []callgraph.Edge{
			{Caller: "app.unsafe", Callees: []string{"os.Getenv", "os/exec.Command"}},
		}},
		facts: taint.ExecFacts{Funcs: map[string]taint.ExecFuncFacts{
			"app.other": {SafeSinks: map[string]bool{"os/exec.Command": true}}, // unrelated function; app.unsafe is uncovered
		}},
	}
	p := &fakeProposer{}
	if _, err := newCoord(t, b, p, &fakeAudit{}).Scan(context.Background(), engID, "/work/target"); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	sc := p.calls[0].claim.(judgment.SASTClaim)
	if sc.CWE != "CWE-78" || sc.Rule != "taint-command-injection" {
		t.Errorf("a function with no constant-safe fact must keep CWE-78, got %+v", sc)
	}
}

// With def-use positions from the build (#163), the claim Location is the sink-using function's file:line
// (not just its symbol), and the witness records source/sink file:line.
func TestScanUsesFileLinePositions(t *testing.T) {
	b := &fakeBuilder{g: &callgraph.Graph{
		Edges: []callgraph.Edge{
			{Caller: "app.handler", Callees: []string{"os.Getenv", "os/exec.Command"}},
		},
		Positions: map[string]string{"app.handler": "internal/app/handler.go:42"},
	}}
	p := &fakeProposer{}
	a := &fakeAudit{}
	if _, err := newCoord(t, b, p, a).Scan(context.Background(), engID, "/work/target"); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	sc := p.calls[0].claim.(judgment.SASTClaim)
	if sc.Location != "internal/app/handler.go:42" {
		t.Errorf("Location must be the sink-using function's file:line, got %q", sc.Location)
	}
	md := a.entries[0].Metadata
	if md["sink_pos"] != "internal/app/handler.go:42" || md["source_pos"] != "internal/app/handler.go:42" {
		t.Errorf("witness must carry source/sink file:line, got source_pos=%q sink_pos=%q", md["source_pos"], md["sink_pos"])
	}
}

// Without positions (older builder / non-first-party), the claim falls back to the symbol and the witness
// omits the position keys (never blank values).
func TestScanFallsBackToSymbolWithoutPositions(t *testing.T) {
	b := &fakeBuilder{g: &callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.handler", Callees: []string{"os.Getenv", "os/exec.Command"}},
	}}}
	p := &fakeProposer{}
	a := &fakeAudit{}
	if _, err := newCoord(t, b, p, a).Scan(context.Background(), engID, "/work/target"); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := p.calls[0].claim.(judgment.SASTClaim).Location; got != "app.handler" {
		t.Errorf("Location must fall back to the symbol, got %q", got)
	}
	if _, ok := a.entries[0].Metadata["sink_pos"]; ok {
		t.Errorf("witness must OMIT sink_pos when unavailable (not a blank value): %+v", a.entries[0].Metadata)
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

func TestScanCorrelatedLinksReachedVulnerableSymbolToSCAFinding(t *testing.T) {
	b := &fakeBuilder{g: &callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.handler", Callees: []string{"os.Getenv", "os/exec.Command"}},
	}}}
	p := &fakeProposer{}
	outcome, err := newCoord(t, b, p, &fakeAudit{}).ScanCorrelated(context.Background(), engID, "/work/target", []ports.ReachabilitySubject{
		{FindingID: "finding-command", Symbols: []string{"os/exec.Command"}},
		{FindingID: "finding-other", Symbols: []string{"database/sql.DB.Query"}},
	})
	if err != nil || outcome.Proposed != 1 || len(p.calls) != 1 {
		t.Fatalf("want one correlated proposal, got outcome=%+v calls=%d err=%v", outcome, len(p.calls), err)
	}
	claim := p.calls[0].claim.(judgment.SASTClaim)
	if len(claim.SinkSymbols) != 1 || claim.SinkSymbols[0] != "os/exec.Command" {
		t.Fatalf("claim must retain the reached library sink, got %+v", claim.SinkSymbols)
	}
	if len(claim.Correlations) != 1 || claim.Correlations[0].FindingID != "finding-command" {
		t.Fatalf("taint flow must link only the matching SCA finding, got %+v", claim.Correlations)
	}
}

func TestScanCorrelatedLeavesUnmatchedFlowUnlinked(t *testing.T) {
	b := &fakeBuilder{g: &callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.handler", Callees: []string{"os.Getenv", "os/exec.Command"}},
	}}}
	p := &fakeProposer{}
	if _, err := newCoord(t, b, p, &fakeAudit{}).ScanCorrelated(context.Background(), engID, "/work/target", []ports.ReachabilitySubject{
		{FindingID: "finding-local", Symbols: []string{"app.Command"}},
	}); err != nil {
		t.Fatal(err)
	}
	if got := p.calls[0].claim.(judgment.SASTClaim).Correlations; len(got) != 0 {
		t.Fatalf("non-advisory sink must not fabricate a finding link: %+v", got)
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
