package taintscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/javaprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/symbolcanon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	javaProposerActor       = "system:java-taint-scan"
	maxJavaTaintProposals   = 10_000
	maxJavaWitnessBytes     = 16 * 1024
	maxJavaWitnessFrameSize = 384
	maxJavaLocationBytes    = 500
)

// JavaCoordinator turns source-only Java semantic facts into proposed CapSAST judgments. It mirrors the
// JS/Python coordinators' propose-only lifecycle: a positive witness becomes a gated CapSAST proposal, while
// missing or partial coverage never becomes a clean negative. It never writes target source, literal values,
// or environment data to the audit log.
type JavaCoordinator struct {
	provider ports.JavaFactsProvider
	proposer proposer
	catalog  taint.JavaCatalog
	audit    ports.AuditLogger
	clock    ports.Clock
}

var _ ports.TaintScanner = (*JavaCoordinator)(nil)
var _ ports.TaintCoverageScanner = (*JavaCoordinator)(nil)
var _ ports.CorrelatedTaintScanner = (*JavaCoordinator)(nil)

func NewJavaCoordinator(provider ports.JavaFactsProvider, p proposer, catalog taint.JavaCatalog, audit ports.AuditLogger, clock ports.Clock) (*JavaCoordinator, error) {
	if provider == nil || p == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: java taint coordinator is missing a dependency", shared.ErrValidation)
	}
	if len(catalog.Sinks) == 0 {
		return nil, fmt.Errorf("%w: java taint coordinator needs a non-empty catalog", shared.ErrValidation)
	}
	return &JavaCoordinator{provider: provider, proposer: p, catalog: catalog, audit: audit, clock: clock}, nil
}

// Scan extracts semantic facts, builds the value graph, and proposes at most maxJavaTaintProposals stable,
// deduplicated judgments. No-coverage errors propose nothing.
func (c *JavaCoordinator) Scan(ctx context.Context, engagementID shared.ID, targetRef string) (int, error) {
	outcome, err := c.ScanWithCoverage(ctx, engagementID, targetRef)
	return outcome.Proposed, err
}

// ScanWithCoverage is the coverage-aware form of Scan. Failures retain a closed, non-sensitive reason so a
// caller can tell zero findings from zero analysis without exposing parser or target data.
func (c *JavaCoordinator) ScanWithCoverage(ctx context.Context, engagementID shared.ID, targetRef string) (ports.TaintScanOutcome, error) {
	return c.scanWithCoverage(ctx, engagementID, targetRef, nil)
}

// ScanCorrelated is the finding-aware form of ScanWithCoverage. It records only whole-symbol matches to
// existing SCA findings, leaving unmatched taint paths as their original gated SAST proposals.
func (c *JavaCoordinator) ScanCorrelated(ctx context.Context, engagementID shared.ID, targetRef string, subjects []ports.ReachabilitySubject) (ports.TaintScanOutcome, error) {
	return c.scanWithCoverage(ctx, engagementID, targetRef, subjects)
}

func (c *JavaCoordinator) scanWithCoverage(ctx context.Context, engagementID shared.ID, targetRef string, subjects []ports.ReachabilitySubject) (ports.TaintScanOutcome, error) {
	outcome := ports.TaintScanOutcome{Coverage: ports.AnalysisCoverage{
		Analyzer: "java-semantic-taint-v1", Language: "java", Status: ports.AnalysisCoverageUnavailable,
	}}
	if ctx == nil || engagementID.IsZero() || strings.TrimSpace(targetRef) == "" {
		outcome.Coverage.Reason = ports.AnalysisReasonAnalysisFailed
		return outcome, fmt.Errorf("%w: java taint scan needs context, engagement, and target", shared.ErrValidation)
	}
	document, available, err := c.provider.JavaFacts(ctx, targetRef)
	if err != nil {
		outcome.Coverage.Reason = ports.AnalysisReasonExtractionFailed
		return outcome, fmt.Errorf("java taint semantic extraction (no coverage): %w", err)
	}
	if !available {
		outcome.Coverage.Reason = ports.AnalysisReasonSidecarUnavailable
		return outcome, fmt.Errorf("%w: java taint semantic sidecar is unavailable", shared.ErrNotFound)
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
	outcome.Coverage.Gaps = javaCoverageGaps(document.CoverageGaps)
	outcome.Coverage.Complete = document.Complete()
	if document.Complete() {
		outcome.Coverage.Status = ports.AnalysisCoverageComplete
	} else {
		outcome.Coverage.Status = ports.AnalysisCoveragePartial
	}
	graph, err := taint.BuildJavaValueGraph(document, c.catalog)
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
	paths := deduplicateJavaTaintPaths(graph.Vulnerabilities())
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
		if proposed >= maxJavaTaintProposals {
			outcome.Proposed = proposed
			outcome.Coverage.Proposals = proposed
			outcome.Coverage.Status = ports.AnalysisCoveragePartial
			outcome.Coverage.Complete = false
			outcome.Coverage.Reason = ports.AnalysisReasonProposalBudgetExceeded
			return outcome, fmt.Errorf("%w: java taint proposal budget exceeded", shared.ErrValidation)
		}
		location := boundedJavaLocation(javaPositionLineString(finding.SinkPos), finding.Callee)
		claim := judgment.SASTClaim{
			CWE: finding.CWE, Location: location, Rule: finding.Rule,
			DataFlow: javaClaimDataFlow(finding, graph, analysisComplete), SinkSymbols: []string{finding.Callee},
			Correlations: correlateSASTFindings(symbolcanon.Generic, []string{finding.Callee}, subjects),
		}
		judged, err := c.proposer.Propose(
			ctx, javaProposerActor, engagementID, judgment.CapSAST, judgment.SubjectDataFlow,
			javaFlowSubjectID(engagementID, finding), claim,
		)
		if err != nil {
			outcome.Proposed = proposed
			outcome.Coverage.Proposals = proposed
			outcome.Coverage.Status = ports.AnalysisCoveragePartial
			outcome.Coverage.Complete = false
			outcome.Coverage.Reason = ports.AnalysisReasonAnalysisFailed
			return outcome, fmt.Errorf("propose java taint judgment: %w", err)
		}
		if err := c.recordJavaWitness(ctx, engagementID, judged.ID, finding, graph, analysisComplete); err != nil {
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

func javaClaimDataFlow(finding taint.JavaTaintPath, graph taint.JavaValueFlowGraph, complete bool) *judgment.SASTDataFlow {
	source, ok := javaFlowLocation(finding.SourcePos)
	if !ok {
		return nil
	}
	sink, ok := javaFlowLocation(finding.SinkPos)
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
		location, exists := javaFlowLocation(graph.Positions[valueID])
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
		Language: "java", Source: source, Sink: sink, Steps: steps,
		CoverageComplete: complete, GraphTruncated: graph.Truncated,
	}
}

func javaFlowLocation(pos javaprogram.Position) (judgment.SASTFlowLocation, bool) {
	if pos.File == "" || len(pos.File) > maxJavaLocationBytes || pos.Line <= 0 || pos.Column < 0 {
		return judgment.SASTFlowLocation{}, false
	}
	return judgment.SASTFlowLocation{File: pos.File, Line: pos.Line, Column: pos.Column}, true
}

func javaCoverageGaps(gaps []javaprogram.CoverageGap) []ports.AnalysisCoverageGap {
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

// deduplicateJavaTaintPaths collapses several sources reaching the same dangerous call+class into one review
// item, choosing the shortest witness so the selected evidence is deterministic and concise.
func deduplicateJavaTaintPaths(paths []taint.JavaTaintPath) []taint.JavaTaintPath {
	paths = append([]taint.JavaTaintPath(nil), paths...)
	sort.Slice(paths, func(i, j int) bool {
		if len(paths[i].Path) != len(paths[j].Path) {
			return len(paths[i].Path) < len(paths[j].Path)
		}
		left := string(paths[i].Class) + "\x00" + paths[i].Rule + "\x00" + paths[i].CallID + "\x00" + paths[i].SourceID
		right := string(paths[j].Class) + "\x00" + paths[j].Rule + "\x00" + paths[j].CallID + "\x00" + paths[j].SourceID
		return left < right
	})
	seen := map[string]bool{}
	out := make([]taint.JavaTaintPath, 0, len(paths))
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

func javaFlowSubjectID(engagementID shared.ID, finding taint.JavaTaintPath) shared.ID {
	key := engagementID.String() + "|java-taint-v1|" + finding.CallID + "|" + string(finding.Class) + "|" + finding.Rule
	sum := sha256.Sum256([]byte(key))
	return shared.ID(hex.EncodeToString(sum[:16]))
}

func (c *JavaCoordinator) recordJavaWitness(ctx context.Context, engagementID, judgmentID shared.ID, finding taint.JavaTaintPath, graph taint.JavaValueFlowGraph, complete bool) error {
	metadata := map[string]string{
		"engagement":        engagementID.String(),
		"language":          "java",
		"class":             string(finding.Class),
		"cwe":               finding.CWE,
		"rule":              finding.Rule,
		"callee":            boundedUTF8(finding.Callee, maxJavaWitnessFrameSize),
		"path":              javaWitnessPath(finding.Path, graph.Positions),
		"coverage_complete": strconv.FormatBool(complete),
		"graph_truncated":   strconv.FormatBool(graph.Truncated),
	}
	if source := javaPositionString(finding.SourcePos, false); source != "" {
		metadata["source_pos"] = boundedUTF8(source, maxJavaWitnessFrameSize)
	}
	if sink := javaPositionString(finding.SinkPos, false); sink != "" {
		metadata["sink_pos"] = boundedUTF8(sink, maxJavaWitnessFrameSize)
	}
	if err := c.audit.Record(ctx, ports.AuditEntry{
		Actor: javaProposerActor, Action: "judgment.java_taint_proposed", Target: judgmentID.String(),
		Metadata: metadata, At: c.clock.Now(),
	}); err != nil {
		return fmt.Errorf("audit java taint proposal: %w", err)
	}
	return nil
}

func javaWitnessPath(values []string, positions map[string]javaprogram.Position) string {
	frames := make([]string, 0, min(len(values), maxWitnessElems))
	bytes := 0
	for index, valueID := range values {
		if index >= maxWitnessElems {
			frames = append(frames, "… (frame limit)")
			break
		}
		frame := javaPositionString(positions[valueID], false)
		if frame == "" {
			sum := sha256.Sum256([]byte(valueID))
			frame = "value:" + hex.EncodeToString(sum[:6])
		}
		frame = boundedUTF8(frame, maxJavaWitnessFrameSize)
		additional := len(frame)
		if len(frames) > 0 {
			additional += len(" → ")
		}
		if bytes+additional > maxJavaWitnessBytes {
			frames = append(frames, "… (byte limit)")
			break
		}
		frames = append(frames, frame)
		bytes += additional
	}
	return boundedUTF8Prefix(strings.Join(frames, " → "), maxJavaWitnessBytes)
}

func javaPositionString(pos javaprogram.Position, omitZeroColumn bool) string {
	if pos.File == "" || pos.Line <= 0 {
		return ""
	}
	label := pos.File + ":" + strconv.Itoa(pos.Line)
	if !omitZeroColumn || pos.Column > 0 {
		label += ":" + strconv.Itoa(pos.Column)
	}
	return label
}

func javaPositionLineString(pos javaprogram.Position) string {
	if pos.File == "" || pos.Line <= 0 {
		return ""
	}
	return pos.File + ":" + strconv.Itoa(pos.Line)
}

func boundedJavaLocation(location, fallback string) string {
	if location == "" {
		location = fallback
	}
	if location == "" {
		location = "java:unknown-sink"
	}
	return boundedUTF8(location, maxJavaLocationBytes)
}
