package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// AnalysisCoverageStatus describes whether a semantic analyzer can support a negative conclusion.
// Positive evidence may still be useful when coverage is partial.
type AnalysisCoverageStatus string

const (
	AnalysisCoverageComplete      AnalysisCoverageStatus = "complete"
	AnalysisCoveragePartial       AnalysisCoverageStatus = "partial"
	AnalysisCoverageUnavailable   AnalysisCoverageStatus = "unavailable"
	AnalysisCoverageNotApplicable AnalysisCoverageStatus = "not_applicable"
)

// AnalysisCoverageReason is a closed, non-sensitive explanation for degraded coverage. It must never
// contain tool stderr, source text, target paths, or other attacker-controlled strings.
type AnalysisCoverageReason string

const (
	AnalysisReasonNone                   AnalysisCoverageReason = ""
	AnalysisReasonNoSource               AnalysisCoverageReason = "no_source"
	AnalysisReasonSidecarUnavailable     AnalysisCoverageReason = "sidecar_unavailable"
	AnalysisReasonExtractionFailed       AnalysisCoverageReason = "extraction_failed"
	AnalysisReasonResolutionFailed       AnalysisCoverageReason = "resolution_failed"
	AnalysisReasonAnalysisFailed         AnalysisCoverageReason = "analysis_failed"
	AnalysisReasonProposalBudgetExceeded AnalysisCoverageReason = "proposal_budget_exceeded"
)

// AnalysisCoverageGap aggregates one trusted semantic coverage-gap kind. Kind is emitted by a closed
// domain vocabulary; details and source positions are deliberately excluded from the scan result.
type AnalysisCoverageGap struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

// AnalysisCoverage is a bounded summary of one deterministic source analyzer. Counts are operational
// metadata only: no source content, local path, parser output, value identifier, or environment data is
// exposed. Complete is the explicit negative-proof invariant; Available only says the analyzer ran.
type AnalysisCoverage struct {
	Analyzer    string                 `json:"analyzer"`
	Language    string                 `json:"language"`
	Status      AnalysisCoverageStatus `json:"status"`
	Reason      AnalysisCoverageReason `json:"reason,omitempty"`
	Available   bool                   `json:"available"`
	Complete    bool                   `json:"complete"`
	Truncated   bool                   `json:"truncated"`
	FilesSeen   int                    `json:"files_seen,omitempty"`
	FilesParsed int                    `json:"files_parsed,omitempty"`
	Symbols     int                    `json:"symbols,omitempty"`
	Calls       int                    `json:"calls,omitempty"`
	Values      int                    `json:"values,omitempty"`
	Flows       int                    `json:"flows,omitempty"`
	Gaps        []AnalysisCoverageGap  `json:"gaps,omitempty"`
	Proposals   int                    `json:"proposals,omitempty"`
}

// TaintScanOutcome preserves both proposed-positive count and the coverage needed to interpret an empty
// result safely.
type TaintScanOutcome struct {
	Proposed int              `json:"proposed"`
	Coverage AnalysisCoverage `json:"coverage"`
}

// TaintCoverageScanner is an optional extension of TaintScanner. The SCA pipeline uses it when present
// and falls back to Scan for legacy implementations, keeping the existing port source-compatible.
type TaintCoverageScanner interface {
	TaintScanner
	ScanWithCoverage(ctx context.Context, engagementID shared.ID, targetRef string) (TaintScanOutcome, error)
}
