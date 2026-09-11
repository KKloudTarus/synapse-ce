package taintscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	jsProposerActor       = "system:js-taint-scan"
	maxJsTaintProposals   = 10_000
	maxJsWitnessBytes     = 16 * 1024
	maxJsWitnessFrameSize = 384
	maxJsLocationBytes    = 500
)

// JsCoordinator turns source-only JavaScript/TypeScript semantic facts into proposed CapSAST judgments. It
// mirrors PythonCoordinator's propose-only lifecycle: a positive witness becomes a gated CapSAST proposal,
// while missing or partial coverage never becomes a clean negative. It never writes target source, literal
// values, or environment data to the audit log.
type JsCoordinator struct {
	provider ports.JsFactsProvider
	proposer proposer
	catalog  taint.JsCatalog
	audit    ports.AuditLogger
	clock    ports.Clock
}

var _ ports.TaintScanner = (*JsCoordinator)(nil)
var _ ports.TaintCoverageScanner = (*JsCoordinator)(nil)

func NewJsCoordinator(provider ports.JsFactsProvider, p proposer, catalog taint.JsCatalog, audit ports.AuditLogger, clock ports.Clock) (*JsCoordinator, error) {
	if provider == nil || p == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: js taint coordinator is missing a dependency", shared.ErrValidation)
	}
	if len(catalog.Sinks) == 0 {
		return nil, fmt.Errorf("%w: js taint coordinator needs a non-empty catalog", shared.ErrValidation)
	}
	return &JsCoordinator{provider: provider, proposer: p, catalog: catalog, audit: audit, clock: clock}, nil
}

// Scan extracts semantic facts, builds the interprocedural value graph, and proposes at most
// maxJsTaintProposals stable, deduplicated judgments. No-coverage errors propose nothing.
func (c *JsCoordinator) Scan(ctx context.Context, engagementID shared.ID, targetRef string) (int, error) {
	outcome, err := c.ScanWithCoverage(ctx, engagementID, targetRef)
	return outcome.Proposed, err
}

// ScanWithCoverage is the coverage-aware form of Scan. Failures retain a closed, non-sensitive reason so a
// caller can tell zero findings from zero analysis without exposing parser or target data.
func (c *JsCoordinator) ScanWithCoverage(ctx context.Context, engagementID shared.ID, targetRef string) (ports.TaintScanOutcome, error) {
	outcome := ports.TaintScanOutcome{Coverage: ports.AnalysisCoverage{
		Analyzer: "js-semantic-taint-v1", Language: "javascript", Status: ports.AnalysisCoverageUnavailable,
	}}
	if ctx == nil || engagementID.IsZero() || strings.TrimSpace(targetRef) == "" {
		outcome.Coverage.Reason = ports.AnalysisReasonAnalysisFailed
		return outcome, fmt.Errorf("%w: js taint scan needs context, engagement, and target", shared.ErrValidation)
	}
	document, available, err := c.provider.JsFacts(ctx, targetRef)
	if err != nil {
		outcome.Coverage.Reason = ports.AnalysisReasonExtractionFailed
		return outcome, fmt.Errorf("js taint semantic extraction (no coverage): %w", err)
	}
	if !available {
		outcome.Coverage.Reason = ports.AnalysisReasonSidecarUnavailable
		return outcome, fmt.Errorf("%w: js taint semantic sidecar is unavailable", shared.ErrNotFound)
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
	outcome.Coverage.Gaps = jsCoverageGaps(document.CoverageGaps)
	outcome.Coverage.Complete = document.Complete()
	if document.Complete() {
		outcome.Coverage.Status = ports.AnalysisCoverageComplete
	} else {
		outcome.Coverage.Status = ports.AnalysisCoveragePartial
	}
	graph, err := taint.BuildJsValueGraph(document, c.catalog)
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
	paths := deduplicateJsTaintPaths(graph.Vulnerabilities())
	if graph.Truncated {
		outcome.Coverage.Truncated = true
		outcome.Coverage.Status = ports.AnalysisCoveragePartial
		outcome.Coverage.Complete = false
	}
	analysisComplete := document.Complete() && !graph.Truncated
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
		if proposed >= maxJsTaintProposals {
			outcome.Proposed = proposed
			outcome.Coverage.Proposals = proposed
			outcome.Coverage.Status = ports.AnalysisCoveragePartial
			outcome.Coverage.Complete = false
			outcome.Coverage.Reason = ports.AnalysisReasonProposalBudgetExceeded
			return outcome, fmt.Errorf("%w: js taint proposal budget exceeded", shared.ErrValidation)
		}
		location := boundedJsLocation(jsPositionLineString(finding.SinkPos), finding.Callee)
		claim := judgment.SASTClaim{
			CWE: finding.CWE, Location: location, Rule: finding.Rule,
			DataFlow: jsClaimDataFlow(finding, graph, analysisComplete),
		}
		judged, err := c.proposer.Propose(
			ctx, jsProposerActor, engagementID, judgment.CapSAST, judgment.SubjectDataFlow,
			jsFlowSubjectID(engagementID, finding), claim,
		)
		if err != nil {
			outcome.Proposed = proposed
			outcome.Coverage.Proposals = proposed
			outcome.Coverage.Status = ports.AnalysisCoveragePartial
			outcome.Coverage.Complete = false
			outcome.Coverage.Reason = ports.AnalysisReasonAnalysisFailed
			return outcome, fmt.Errorf("propose js taint judgment: %w", err)
		}
		if err := c.recordJsWitness(ctx, engagementID, judged.ID, finding, graph, analysisComplete); err != nil {
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

func jsClaimDataFlow(finding taint.JsTaintPath, graph taint.JsValueFlowGraph, complete bool) *judgment.SASTDataFlow {
	source, ok := jsFlowLocation(finding.SourcePos)
	if !ok {
		return nil
	}
	sink, ok := jsFlowLocation(finding.SinkPos)
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
		location, exists := jsFlowLocation(graph.Positions[valueID])
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
		Language: "javascript", Source: source, Sink: sink, Steps: steps,
		CoverageComplete: complete, GraphTruncated: graph.Truncated,
	}
}

func jsFlowLocation(pos jsprogram.Position) (judgment.SASTFlowLocation, bool) {
	if pos.File == "" || len(pos.File) > maxJsLocationBytes || pos.Line <= 0 || pos.Column < 0 {
		return judgment.SASTFlowLocation{}, false
	}
	return judgment.SASTFlowLocation{File: pos.File, Line: pos.Line, Column: pos.Column}, true
}

func jsCoverageGaps(gaps []jsprogram.CoverageGap) []ports.AnalysisCoverageGap {
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

// deduplicateJsTaintPaths collapses several sources reaching the same dangerous call+class into one review
// item, choosing the shortest witness so the selected evidence is deterministic and concise.
func deduplicateJsTaintPaths(paths []taint.JsTaintPath) []taint.JsTaintPath {
	paths = append([]taint.JsTaintPath(nil), paths...)
	sort.Slice(paths, func(i, j int) bool {
		if len(paths[i].Path) != len(paths[j].Path) {
			return len(paths[i].Path) < len(paths[j].Path)
		}
		left := string(paths[i].Class) + "\x00" + paths[i].Rule + "\x00" + paths[i].CallID + "\x00" + paths[i].SourceID
		right := string(paths[j].Class) + "\x00" + paths[j].Rule + "\x00" + paths[j].CallID + "\x00" + paths[j].SourceID
		return left < right
	})
	seen := map[string]bool{}
	out := make([]taint.JsTaintPath, 0, len(paths))
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

func jsFlowSubjectID(engagementID shared.ID, finding taint.JsTaintPath) shared.ID {
	key := engagementID.String() + "|js-taint-v1|" + finding.CallID + "|" + string(finding.Class) + "|" + finding.Rule
	sum := sha256.Sum256([]byte(key))
	return shared.ID(hex.EncodeToString(sum[:16]))
}

func (c *JsCoordinator) recordJsWitness(ctx context.Context, engagementID, judgmentID shared.ID, finding taint.JsTaintPath, graph taint.JsValueFlowGraph, complete bool) error {
	metadata := map[string]string{
		"engagement":        engagementID.String(),
		"language":          "javascript",
		"class":             string(finding.Class),
		"cwe":               finding.CWE,
		"rule":              finding.Rule,
		"callee":            boundedUTF8(finding.Callee, maxJsWitnessFrameSize),
		"path":              jsWitnessPath(finding.Path, graph.Positions),
		"coverage_complete": strconv.FormatBool(complete),
		"graph_truncated":   strconv.FormatBool(graph.Truncated),
	}
	if source := jsPositionString(finding.SourcePos, false); source != "" {
		metadata["source_pos"] = boundedUTF8(source, maxJsWitnessFrameSize)
	}
	if sink := jsPositionString(finding.SinkPos, false); sink != "" {
		metadata["sink_pos"] = boundedUTF8(sink, maxJsWitnessFrameSize)
	}
	if err := c.audit.Record(ctx, ports.AuditEntry{
		Actor: jsProposerActor, Action: "judgment.js_taint_proposed", Target: judgmentID.String(),
		Metadata: metadata, At: c.clock.Now(),
	}); err != nil {
		return fmt.Errorf("audit js taint proposal: %w", err)
	}
	return nil
}

func jsWitnessPath(values []string, positions map[string]jsprogram.Position) string {
	frames := make([]string, 0, min(len(values), maxWitnessElems))
	bytes := 0
	for index, valueID := range values {
		if index >= maxWitnessElems {
			frames = append(frames, "… (frame limit)")
			break
		}
		frame := jsPositionString(positions[valueID], false)
		if frame == "" {
			sum := sha256.Sum256([]byte(valueID))
			frame = "value:" + hex.EncodeToString(sum[:6])
		}
		frame = boundedUTF8(frame, maxJsWitnessFrameSize)
		additional := len(frame)
		if len(frames) > 0 {
			additional += len(" → ")
		}
		if bytes+additional > maxJsWitnessBytes {
			frames = append(frames, "… (byte limit)")
			break
		}
		frames = append(frames, frame)
		bytes += additional
	}
	return boundedUTF8Prefix(strings.Join(frames, " → "), maxJsWitnessBytes)
}

func jsPositionString(pos jsprogram.Position, omitZeroColumn bool) string {
	if pos.File == "" || pos.Line <= 0 {
		return ""
	}
	label := pos.File + ":" + strconv.Itoa(pos.Line)
	if !omitZeroColumn || pos.Column > 0 {
		label += ":" + strconv.Itoa(pos.Column)
	}
	return label
}

func jsPositionLineString(pos jsprogram.Position) string {
	if pos.File == "" || pos.Line <= 0 {
		return ""
	}
	return pos.File + ":" + strconv.Itoa(pos.Line)
}

func boundedJsLocation(location, fallback string) string {
	if location == "" {
		location = fallback
	}
	if location == "" {
		location = "js:unknown-sink"
	}
	return boundedUTF8(location, maxJsLocationBytes)
}
