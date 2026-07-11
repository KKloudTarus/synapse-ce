// Package taintscan is the coordinator that turns a target's deterministic taint analysis
// into PROPOSED, gated CapSAST judgments – one per reported injection path × injection class – reusing the
// existing propose→verify gate. It builds the workspace call graph (sandboxed, via the CallGraphBuilder
// port), assembles the taint.FlowGraph over the injection catalog, and proposes a SASTClaim for each
// source→sink flow Vulnerabilities() reports.
//
// SAFETY (security-reviewed):
// PROPOSE-ONLY. CapSAST is GATED and the taint model is a coarse over-approximation (function-granular
// FPs by design), so the engine must NEVER self-confirm: every judgment is born StateProposed/score-0
// and a DISTINCT verifier's verdict ≥75 is the only thing that confirms it. There is one reserved
// "system:" proposer identity and deliberately NO verifier identity here (contrast reachproof, whose
// deterministic proof legitimately auto-confirms).
// The proposer slice is NARROW (Propose only – no Verify/score path) and composition-root-only; the
// arch_test keeps this package off the agent surface (defense-in-depth, mirroring reachproof), even
// though propose-only already grants no confirm power.
// No coverage (the build failed / un-buildable target) proposes NOTHING – never a false "clean" (the
// SCA pipeline drives this best-effort and IGNORES the error). The build error (which may wrap tool
// stderr) is returned but never written to the audit log or an LLM transcript (GR3).
// The proposal's witness is recorded as append-only, attributable evidence carrying ONLY normalized
// importPath.Symbol frames + the injection class (GR6/GR3 – no file contents, env, or secrets).
package taintscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// proposerActor is the reserved, system-namespace identity the taint engine proposes under – distinct from
// the "agent:<sid>" / "human:<id>" namespaces no real principal can collide with, and not mintable by the
// agent/human actor factories. It only ever PROPOSES; a gated CapSAST judgment is confirmed solely by a
// DISTINCT verifier's sealed verdict ≥75.
const proposerActor = "system:taint-scan"

// maxWitnessElems bounds the proof path recorded in the audit metadata so a hostile/huge call graph cannot
// seal an unbounded string (generous – a real taint path is far smaller).
const maxWitnessElems = 64

// builder builds a target's call graph (ports.CallGraphBuilder satisfies it). A build error is NO COVERAGE
// – the coordinator proposes nothing rather than a false "clean".
type builder interface {
	Build(ctx context.Context, targetRef string) (*callgraph.Graph, error)
}

// proposer is the NARROW propose-only slice of the judgment lifecycle the coordinator needs
// (analysis.Service satisfies it). It deliberately EXCLUDES Verify: the taint engine cannot move a score,
// so wiring it can never grant a self-confirm path.
type proposer interface {
	Propose(ctx context.Context, proposer string, engagementID shared.ID, capability judgment.Capability, subjectKind judgment.SubjectKind, subjectID shared.ID, claim judgment.Claim) (judgment.Judgment, error)
}

// Coordinator proposes gated CapSAST judgments from a target's deterministic taint analysis. It implements
// ports.TaintScanner so the SCA pipeline can drive it best-effort without importing this package.
type Coordinator struct {
	builder  builder
	proposer proposer
	catalog  taint.Catalog
	audit    ports.AuditLogger
	clock    ports.Clock
}

var _ ports.TaintScanner = (*Coordinator)(nil)

// NewCoordinator validates and returns the coordinator. The catalog must be non-empty (an empty catalog
// would silently propose nothing – a misconfiguration, not a clean result).
func NewCoordinator(b builder, p proposer, catalog taint.Catalog, audit ports.AuditLogger, clock ports.Clock) (*Coordinator, error) {
	if b == nil || p == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: taintscan coordinator is missing a dependency", shared.ErrValidation)
	}
	if len(catalog.Sources) == 0 || len(catalog.Sinks) == 0 {
		return nil, fmt.Errorf("%w: taintscan coordinator needs a non-empty catalog (sources+sinks)", shared.ErrValidation)
	}
	return &Coordinator{builder: b, proposer: p, catalog: catalog, audit: audit, clock: clock}, nil
}

// Scan builds the target's call graph, assembles the taint FlowGraph over the catalog, and PROPOSES a
// gated CapSAST judgment per reported injection path × injection class. Returns the number proposed. A
// no-coverage build error proposes NOTHING (never a false "clean"). Every judgment is born
// StateProposed/score-0 and awaits a distinct verifier.
func (c *Coordinator) Scan(ctx context.Context, engagementID shared.ID, targetRef string) (int, error) {
	if engagementID.IsZero() {
		return 0, fmt.Errorf("%w: engagement id is required", shared.ErrValidation)
	}
	g, err := c.builder.Build(ctx, targetRef)
	if err != nil {
		// No coverage: propose nothing. The wrapped error may carry tool stderr – it is returned to the
		// best-effort caller (which ignores it) and never reaches the audit log or an LLM transcript.
		return 0, fmt.Errorf("taint call-graph build (no coverage – no judgments proposed): %w", err)
	}
	if g == nil { // defensive: a contract-violating builder returning (nil,nil) is no-coverage, not a deref
		return 0, fmt.Errorf("%w: taint call-graph build returned no graph", shared.ErrValidation)
	}

	fg, sinkClass := taint.Assemble(*g, c.catalog)
	proposed := 0
	for _, v := range fg.Vulnerabilities() {
		// Join the sink-class index against the REPORTED path: every injection CLASS the reached
		// sink-using function calls is reachable via this flow. Dedup by (CWE, Rule) – two sinks of the
		// same class at one function (e.g. DB.Query + DB.Exec, both CWE-89) produce a byte-identical claim
		// (Location is the function, not the specific sink call), so they are the SAME finding and must be
		// proposed once. This also matches flowSubjectID's per-class key (no duplicate subjects/seals).
		seen := map[string]bool{}
		for _, sink := range sinkClass[v.Sink] {
			classKey := sink.CWE + "|" + sink.Rule
			if seen[classKey] {
				continue
			}
			seen[classKey] = true
			// Location is the sink-using function's importPath.Symbol – function-granular: the current build
			// carries no file:line (precise positions are the deferred def-use follow-up), so the claim's
			// "path[:line]" field holds the symbol.
			claim := judgment.SASTClaim{CWE: sink.CWE, Location: v.Sink, Rule: sink.Rule}
			j, err := c.proposer.Propose(ctx, proposerActor, engagementID, judgment.CapSAST, judgment.SubjectDataFlow, flowSubjectID(engagementID, v, sink), claim)
			if err != nil {
				return proposed, fmt.Errorf("propose taint judgment: %w", err)
			}
			if err := c.recordWitness(ctx, engagementID, j.ID, v, sink); err != nil {
				return proposed, err
			}
			proposed++
		}
	}
	return proposed, nil
}

// flowSubjectID derives the stable SubjectDataFlow id for a (source→sink, injection class) triple so a
// re-scan of the same flow+class yields the SAME subject (no churn within a pass), tenant-scoped by
// engagement. Keyed on source/sink importPath.Symbol + CWE + Rule (the fields that distinguish a claim) –
// never file contents (mirrors sca.findingID's derivation). Cross-scan idempotency additionally depends on
// the judgment store, as with reachproof.
func flowSubjectID(engagementID shared.ID, v taint.TaintPath, sink taint.Sink) shared.ID {
	sum := sha256.Sum256([]byte(engagementID.String() + "|taint|" + v.Source + "|" + v.Sink + "|" + sink.CWE + "|" + sink.Rule))
	return shared.ID(hex.EncodeToString(sum[:16]))
}

// recordWitness records the taint proof path as append-only, attributable evidence for the proposed
// judgment (GR6). The metadata carries ONLY normalized importPath.Symbol frames + the injection class –
// never file contents, env, build stderr, or secrets (GR3), mirroring reachproof's proof rationale.
func (c *Coordinator) recordWitness(ctx context.Context, engagementID, judgmentID shared.ID, v taint.TaintPath, sink taint.Sink) error {
	if err := c.audit.Record(ctx, ports.AuditEntry{
		Actor:  proposerActor,
		Action: "judgment.taint_proposed",
		Target: judgmentID.String(),
		Metadata: map[string]string{
			"engagement": engagementID.String(),
			"cwe":        sink.CWE,
			"rule":       sink.Rule,
			"path":       witnessPath(v.Path),
		},
		At: c.clock.Now(),
	}); err != nil {
		return fmt.Errorf("audit taint proposal: %w", err)
	}
	return nil
}

// witnessPath renders the bounded importPath.Symbol witness for the audit metadata.
func witnessPath(path []string) string {
	if len(path) > maxWitnessElems {
		return strings.Join(path[:maxWitnessElems], " → ") + " → … (truncated)"
	}
	return strings.Join(path, " → ")
}
