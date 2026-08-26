package taintscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/pythonprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	pythonProposerActor       = "system:python-taint-scan"
	maxPythonTaintProposals   = 10_000
	maxPythonWitnessBytes     = 16 * 1024
	maxPythonWitnessFrameSize = 384
	maxPythonLocationBytes    = 500
)

// PythonCoordinator turns source-only Python semantic facts into proposed CapSAST judgments. It is
// intentionally a separate coordinator from the legacy Go function-level engine: Python propagation is
// value-slot based, and sharing the coarse FlowGraph would reintroduce sibling-call false positives.
//
// The coordinator has a propose-only judgment port. Partial coverage may still support a positive witness,
// but it never emits a negative/clean judgment. Target source, literal values, parser stderr, and environment
// data are never written to the audit log.
type PythonCoordinator struct {
	provider ports.PythonFactsProvider
	proposer proposer
	catalog  taint.PythonCatalog
	audit    ports.AuditLogger
	clock    ports.Clock
}

var _ ports.TaintScanner = (*PythonCoordinator)(nil)
var _ ports.TaintCoverageScanner = (*PythonCoordinator)(nil)

func NewPythonCoordinator(provider ports.PythonFactsProvider, p proposer, catalog taint.PythonCatalog, audit ports.AuditLogger, clock ports.Clock) (*PythonCoordinator, error) {
	if provider == nil || p == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: python taint coordinator is missing a dependency", shared.ErrValidation)
	}
	if len(catalog.Sources) == 0 || len(catalog.Sinks) == 0 {
		return nil, fmt.Errorf("%w: python taint coordinator needs a non-empty catalog", shared.ErrValidation)
	}
	return &PythonCoordinator{provider: provider, proposer: p, catalog: catalog, audit: audit, clock: clock}, nil
}

// Scan extracts semantic facts, resolves calls, builds the interprocedural value graph, and proposes at
// most maxPythonTaintProposals stable, deduplicated judgments. No-coverage errors are returned to the
// best-effort SCA hook and propose nothing; partial coverage is recorded on positive witnesses.
func (c *PythonCoordinator) Scan(ctx context.Context, engagementID shared.ID, targetRef string) (int, error) {
	outcome, err := c.ScanWithCoverage(ctx, engagementID, targetRef)
	return outcome.Proposed, err
}

// ScanWithCoverage is the coverage-aware form of Scan. Failures retain a closed, non-sensitive reason
// so callers can distinguish zero findings from zero analysis without exposing parser or target data.
func (c *PythonCoordinator) ScanWithCoverage(ctx context.Context, engagementID shared.ID, targetRef string) (ports.TaintScanOutcome, error) {
	outcome := ports.TaintScanOutcome{Coverage: ports.AnalysisCoverage{
		Analyzer: "python-semantic-taint-v1", Language: "python", Status: ports.AnalysisCoverageUnavailable,
	}}
	if ctx == nil || engagementID.IsZero() || strings.TrimSpace(targetRef) == "" {
		outcome.Coverage.Reason = ports.AnalysisReasonAnalysisFailed
		return outcome, fmt.Errorf("%w: python taint scan needs context, engagement, and target", shared.ErrValidation)
	}
	document, available, err := c.provider.PythonFacts(ctx, targetRef)
	if err != nil {
		outcome.Coverage.Reason = ports.AnalysisReasonExtractionFailed
		return outcome, fmt.Errorf("python taint semantic extraction (no coverage): %w", err)
	}
	if !available {
		outcome.Coverage.Reason = ports.AnalysisReasonSidecarUnavailable
		return outcome, fmt.Errorf("%w: python taint semantic sidecar is unavailable", shared.ErrNotFound)
	}
	if err := ctx.Err(); err != nil {
		outcome.Coverage.Reason = ports.AnalysisReasonAnalysisFailed
		return outcome, err
	}
	outcome.Coverage.Available = true
	outcome.Coverage.FilesSeen = document.FilesSeen
	outcome.Coverage.FilesParsed = document.FilesParsed
	outcome.Coverage.Symbols = len(document.Symbols)
	outcome.Coverage.Calls = len(document.Calls)
	outcome.Coverage.Values = len(document.Values)
	outcome.Coverage.Flows = len(document.Flows)
	outcome.Coverage.Truncated = document.Truncated
	if document.FilesSeen == 0 {
		outcome.Coverage.Status = ports.AnalysisCoverageNotApplicable
		outcome.Coverage.Reason = ports.AnalysisReasonNoSource
		return outcome, nil
	}
	resolution, err := pythonprogram.Resolve(document)
	if err != nil {
		outcome.Coverage.Reason = ports.AnalysisReasonResolutionFailed
		return outcome, fmt.Errorf("python taint semantic resolution (no coverage): %w", err)
	}
	outcome.Coverage.Gaps = pythonCoverageGaps(resolution.Gaps)
	outcome.Coverage.Complete = resolution.Complete
	if resolution.Complete {
		outcome.Coverage.Status = ports.AnalysisCoverageComplete
	} else {
		outcome.Coverage.Status = ports.AnalysisCoveragePartial
	}
	graph, err := taint.BuildPythonValueGraph(document, resolution, c.catalog)
	if err != nil {
		outcome.Coverage.Status = ports.AnalysisCoverageUnavailable
		outcome.Coverage.Complete = false
		outcome.Coverage.Reason = ports.AnalysisReasonAnalysisFailed
		return outcome, err
	}
	outcome.Coverage.Truncated = outcome.Coverage.Truncated || graph.Truncated
	if graph.Truncated {
		outcome.Coverage.Status = ports.AnalysisCoveragePartial
		outcome.Coverage.Complete = false
	}
	analysisComplete := resolution.Complete && !graph.Truncated

	paths := deduplicatePythonTaintPaths(graph.Vulnerabilities())
	proposed := 0
	for _, finding := range paths {
		if err := ctx.Err(); err != nil {
			outcome.Proposed = proposed
			outcome.Coverage.Proposals = proposed
			outcome.Coverage.Status = ports.AnalysisCoveragePartial
			outcome.Coverage.Complete = false
			outcome.Coverage.Reason = ports.AnalysisReasonAnalysisFailed
			return outcome, err
		}
		if proposed >= maxPythonTaintProposals {
			outcome.Proposed = proposed
			outcome.Coverage.Proposals = proposed
			outcome.Coverage.Status = ports.AnalysisCoveragePartial
			outcome.Coverage.Complete = false
			outcome.Coverage.Reason = ports.AnalysisReasonProposalBudgetExceeded
			return outcome, fmt.Errorf("%w: python taint proposal budget exceeded", shared.ErrValidation)
		}
		location := boundedPythonLocation(positionLineString(finding.SinkPos), finding.Callee)
		claim := judgment.SASTClaim{
			CWE: finding.CWE, Location: location, Rule: finding.Rule,
			DataFlow: pythonClaimDataFlow(finding, graph, analysisComplete),
		}
		judged, err := c.proposer.Propose(
			ctx, pythonProposerActor, engagementID, judgment.CapSAST, judgment.SubjectDataFlow,
			pythonFlowSubjectID(engagementID, finding), claim,
		)
		if err != nil {
			outcome.Proposed = proposed
			outcome.Coverage.Proposals = proposed
			outcome.Coverage.Status = ports.AnalysisCoveragePartial
			outcome.Coverage.Complete = false
			outcome.Coverage.Reason = ports.AnalysisReasonAnalysisFailed
			return outcome, fmt.Errorf("propose python taint judgment: %w", err)
		}
		if err := c.recordPythonWitness(ctx, engagementID, judged.ID, finding, graph, analysisComplete); err != nil {
			outcome.Proposed = proposed + 1
			outcome.Coverage.Proposals = proposed + 1
			outcome.Coverage.Status = ports.AnalysisCoveragePartial
			outcome.Coverage.Complete = false
			outcome.Coverage.Reason = ports.AnalysisReasonAnalysisFailed
			return outcome, err
		}
		proposed++
	}
	outcome.Proposed = proposed
	outcome.Coverage.Proposals = proposed
	return outcome, nil
}

func pythonClaimDataFlow(finding taint.PythonTaintPath, graph taint.ValueFlowGraph, complete bool) *judgment.SASTDataFlow {
	source, ok := pythonFlowLocation(finding.SourcePos)
	if !ok {
		return nil
	}
	sink, ok := pythonFlowLocation(finding.SinkPos)
	if !ok {
		return nil
	}
	steps := make([]judgment.SASTFlowLocation, 0, min(len(finding.Path)+2, judgment.MaxSASTDataFlowSteps))
	appendStep := func(location judgment.SASTFlowLocation) {
		if len(steps) == 0 || steps[len(steps)-1] != location {
			steps = append(steps, location)
		}
	}
	appendStep(source)
	for _, valueID := range finding.Path {
		location, exists := pythonFlowLocation(graph.Positions[valueID])
		if !exists || len(steps) >= judgment.MaxSASTDataFlowSteps-1 {
			continue
		}
		appendStep(location)
	}
	if len(steps) == judgment.MaxSASTDataFlowSteps && steps[len(steps)-1] != sink {
		steps[len(steps)-1] = sink
	} else {
		appendStep(sink)
	}
	return &judgment.SASTDataFlow{
		Language: "python", Source: source, Sink: sink, Steps: steps,
		CoverageComplete: complete, GraphTruncated: graph.Truncated,
	}
}

func pythonFlowLocation(pos pythonprogram.Position) (judgment.SASTFlowLocation, bool) {
	if pos.File == "" || len(pos.File) > maxPythonLocationBytes || pos.Line <= 0 || pos.Column < 0 {
		return judgment.SASTFlowLocation{}, false
	}
	return judgment.SASTFlowLocation{File: pos.File, Line: pos.Line, Column: pos.Column}, true
}

func pythonCoverageGaps(gaps []pythonprogram.CoverageGap) []ports.AnalysisCoverageGap {
	counts := make(map[string]int, len(gaps))
	for _, gap := range gaps {
		if gap.Kind != "" {
			counts[string(gap.Kind)]++
		}
	}
	kinds := make([]string, 0, len(counts))
	for kind := range counts {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	out := make([]ports.AnalysisCoverageGap, 0, len(kinds))
	for _, kind := range kinds {
		out = append(out, ports.AnalysisCoverageGap{Kind: kind, Count: counts[kind]})
	}
	return out
}

// One dangerous call and class is one review item even if several sources reach it. Sort shortest witnesses
// first so the selected evidence is deterministic and concise.
func deduplicatePythonTaintPaths(paths []taint.PythonTaintPath) []taint.PythonTaintPath {
	paths = append([]taint.PythonTaintPath(nil), paths...)
	sort.Slice(paths, func(i, j int) bool {
		if len(paths[i].Path) != len(paths[j].Path) {
			return len(paths[i].Path) < len(paths[j].Path)
		}
		left := string(paths[i].Class) + "\x00" + paths[i].Rule + "\x00" + paths[i].CallID + "\x00" + paths[i].SourceID
		right := string(paths[j].Class) + "\x00" + paths[j].Rule + "\x00" + paths[j].CallID + "\x00" + paths[j].SourceID
		return left < right
	})
	seen := map[string]bool{}
	out := make([]taint.PythonTaintPath, 0, len(paths))
	for _, item := range paths {
		key := item.CallID + "\x00" + string(item.Class) + "\x00" + item.Rule
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		left := out[i].CallID + "\x00" + string(out[i].Class) + "\x00" + out[i].Rule
		right := out[j].CallID + "\x00" + string(out[j].Class) + "\x00" + out[j].Rule
		return left < right
	})
	return out
}

func pythonFlowSubjectID(engagementID shared.ID, finding taint.PythonTaintPath) shared.ID {
	key := engagementID.String() + "|python-taint-v1|" + finding.CallID + "|" + string(finding.Class) + "|" + finding.Rule
	sum := sha256.Sum256([]byte(key))
	return shared.ID(hex.EncodeToString(sum[:16]))
}

func (c *PythonCoordinator) recordPythonWitness(ctx context.Context, engagementID, judgmentID shared.ID, finding taint.PythonTaintPath, graph taint.ValueFlowGraph, complete bool) error {
	metadata := map[string]string{
		"engagement":        engagementID.String(),
		"language":          "python",
		"class":             string(finding.Class),
		"cwe":               finding.CWE,
		"rule":              finding.Rule,
		"callee":            boundedUTF8(finding.Callee, maxPythonWitnessFrameSize),
		"path":              pythonWitnessPath(finding.Path, graph.Positions),
		"coverage_complete": strconv.FormatBool(complete),
		"graph_truncated":   strconv.FormatBool(graph.Truncated),
	}
	if source := positionString(finding.SourcePos, false); source != "" {
		metadata["source_pos"] = boundedUTF8(source, maxPythonWitnessFrameSize)
	}
	if sink := positionString(finding.SinkPos, false); sink != "" {
		metadata["sink_pos"] = boundedUTF8(sink, maxPythonWitnessFrameSize)
	}
	if err := c.audit.Record(ctx, ports.AuditEntry{
		Actor: pythonProposerActor, Action: "judgment.python_taint_proposed", Target: judgmentID.String(),
		Metadata: metadata, At: c.clock.Now(),
	}); err != nil {
		return fmt.Errorf("audit python taint proposal: %w", err)
	}
	return nil
}

func pythonWitnessPath(values []string, positions map[string]pythonprogram.Position) string {
	frames := make([]string, 0, min(len(values), maxWitnessElems))
	bytes := 0
	for index, valueID := range values {
		if index >= maxWitnessElems {
			frames = append(frames, "… (frame limit)")
			break
		}
		frame := positionString(positions[valueID], false)
		if frame == "" {
			sum := sha256.Sum256([]byte(valueID))
			frame = "value:" + hex.EncodeToString(sum[:6])
		}
		frame = boundedUTF8(frame, maxPythonWitnessFrameSize)
		additional := len(frame)
		if len(frames) > 0 {
			additional += len(" → ")
		}
		if bytes+additional > maxPythonWitnessBytes {
			frames = append(frames, "… (byte limit)")
			break
		}
		frames = append(frames, frame)
		bytes += additional
	}
	return boundedUTF8Prefix(strings.Join(frames, " → "), maxPythonWitnessBytes)
}

func positionString(pos pythonprogram.Position, omitZeroColumn bool) string {
	if pos.File == "" || pos.Line <= 0 {
		return ""
	}
	label := pos.File + ":" + strconv.Itoa(pos.Line)
	if !omitZeroColumn || pos.Column > 0 {
		label += ":" + strconv.Itoa(pos.Column)
	}
	return label
}

func positionLineString(pos pythonprogram.Position) string {
	if pos.File == "" || pos.Line <= 0 {
		return ""
	}
	return pos.File + ":" + strconv.Itoa(pos.Line)
}

func boundedPythonLocation(location, fallback string) string {
	if location == "" {
		location = fallback
	}
	if location == "" {
		location = "python:unknown-sink"
	}
	return boundedUTF8(location, maxPythonLocationBytes)
}

func boundedUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	const prefix = "…/"
	budget := limit - len(prefix)
	start := len(value) - budget
	for start < len(value) && !utf8.RuneStart(value[start]) {
		start++
	}
	return prefix + value[start:]
}

func boundedUTF8Prefix(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	const suffix = "…"
	end := limit - len(suffix)
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end] + suffix
}
