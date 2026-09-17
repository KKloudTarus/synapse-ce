package projectuc

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
)

// MeasureAvailabilityState describes whether a measure has a meaningful value.
type MeasureAvailabilityState string

const (
	// AvailabilityAvailable indicates the measure value is present and valid.
	AvailabilityAvailable MeasureAvailabilityState = "available"
	// AvailabilityUnavailable indicates the measure value could not be computed.
	AvailabilityUnavailable MeasureAvailabilityState = "unavailable"
	// AvailabilityNotApplicable indicates the measure does not apply to this node type.
	AvailabilityNotApplicable MeasureAvailabilityState = "not_applicable"
)

// MeasureCountMetric represents an integer measure and its availability state.
type MeasureCountMetric struct {
	Availability MeasureAvailabilityState `json:"availability"`
	Value        *int                     `json:"value"`
	Reason       *string                  `json:"unavailable_reason"`
}

// MeasureDecimalMetric represents a floating-point measure and its availability state.
type MeasureDecimalMetric struct {
	Availability MeasureAvailabilityState `json:"availability"`
	Value        *float64                 `json:"value"`
	Reason       *string                  `json:"unavailable_reason"`
}

// MeasureGradeMetric represents a letter grade (e.g., A, B, C) and its availability state.
type MeasureGradeMetric struct {
	Availability MeasureAvailabilityState `json:"availability"`
	Grade        *string                  `json:"grade"`
	Reason       *string                  `json:"unavailable_reason"`
}

// SizeMeasures encapsulates size-related metrics such as line counts and functions.
type SizeMeasures struct {
	Files          MeasureCountMetric   `json:"files"`
	NCLOC          MeasureCountMetric   `json:"ncloc"`
	CommentLines   MeasureCountMetric   `json:"comment_lines"`
	BlankLines     MeasureCountMetric   `json:"blank_lines"`
	Functions      MeasureCountMetric   `json:"functions"`
	CommentDensity MeasureDecimalMetric `json:"comment_density"`
}

// ComplexityMeasures encapsulates structural complexity metrics.
type ComplexityMeasures struct {
	Cyclomatic      MeasureCountMetric       `json:"cyclomatic"`
	Cognitive       MeasureCountMetric       `json:"cognitive"`
	CyclomaticDelta MeasureSignedMetric      `json:"cyclomatic_delta"`
	CognitiveDelta  MeasureSignedMetric      `json:"cognitive_delta"`
	Coverage        ComplexityCoverageMetric `json:"coverage"`
	Baseline        *ComplexityBaseline      `json:"baseline,omitempty"`
}

// MeasureSignedMetric is a signed delta. Negative values are meaningful and never clamped.
type MeasureSignedMetric struct {
	Availability MeasureAvailabilityState `json:"availability"`
	Value        *int                     `json:"value"`
	Reason       *string                  `json:"unavailable_reason"`
}

// ComplexityCoverageMetric records how much of a node's source scope has usable complexity evidence.
type ComplexityCoverageMetric struct {
	Version       int                      `json:"version"`
	EligibleFiles MeasureCountMetric       `json:"eligible_files"`
	MeasuredFiles MeasureCountMetric       `json:"measured_files"`
	Availability  MeasureAvailabilityState `json:"availability"`
	Reason        *string                  `json:"unavailable_reason"`
}

// ComplexityBaseline identifies the baseline analysis used for computing complexity deltas.
type ComplexityBaseline struct {
	AnalysisID string    `json:"analysis_id"`
	CreatedAt  time.Time `json:"created_at"`
	SourceRef  string    `json:"source_ref,omitempty"`
}

// CouplingMeasures describes incoming and outgoing first-party module
// dependencies. Instability is Ce/(Ca+Ce) and is unavailable for an isolated module.
type CouplingMeasures struct {
	Afferent    MeasureCountMetric   `json:"afferent"`
	Efferent    MeasureCountMetric   `json:"efferent"`
	Instability MeasureDecimalMetric `json:"instability"`
}

// BehavioralMeasures exposes per-file complexity/churn scores. For directory and project nodes,
// ChangeCount is the number of measured descendant files and Score is the maximum descendant score.
type BehavioralMeasures struct {
	CyclomaticSum MeasureCountMetric `json:"cyclomatic_sum"`
	ChangeCount   MeasureCountMetric `json:"change_count"`
	Score         MeasureCountMetric `json:"score"`
}

// CoverageMeasures encapsulates code coverage metrics.
type CoverageMeasures struct {
	CoveredLines    MeasureCountMetric   `json:"covered_lines"`
	CoverableLines  MeasureCountMetric   `json:"coverable_lines"`
	Coverage        MeasureDecimalMetric `json:"coverage"`
	NewCodeCoverage MeasureDecimalMetric `json:"new_code_coverage"`
}

// DuplicationMeasures encapsulates source code duplication metrics.
type DuplicationMeasures struct {
	DuplicatedLines    MeasureCountMetric   `json:"duplicated_lines"`
	DuplicationBlocks  MeasureCountMetric   `json:"duplication_blocks"`
	DuplicationDensity MeasureDecimalMetric `json:"duplication_density"`
}

// IssueMeasures encapsulates finding counts broken down by type and severity.
type IssueMeasures struct {
	ByType     map[string]MeasureCountMetric `json:"by_type"`
	BySeverity map[string]MeasureCountMetric `json:"by_severity"`
}

// DebtMeasures encapsulates technical debt metrics.
type DebtMeasures struct {
	RemediationEffortMinutes MeasureCountMetric `json:"remediation_effort_minutes"`
}

// RatingsMeasures encapsulates high-level grades for security, reliability, and maintainability.
type RatingsMeasures struct {
	Security        MeasureGradeMetric `json:"security"`
	Reliability     MeasureGradeMetric `json:"reliability"`
	Maintainability MeasureGradeMetric `json:"maintainability"`
}

// ProjectNodeInfo provides basic identifying information about the project.
type ProjectNodeInfo struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

// AnalysisMetadata provides contextual information about the analysis snapshot.
type AnalysisMetadata struct {
	ID           string    `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	SourceRef    string    `json:"source_ref,omitempty"`
	SourceCommit string    `json:"source_commit,omitempty"`
}

// MeasureNode represents a single directory, file, or project root with its computed measures.
type MeasureNode struct {
	Path               string               `json:"path"`
	Name               string               `json:"name"`
	Kind               measure.NodeKind     `json:"kind"`
	Language           string               `json:"language,omitempty"`
	Size               *SizeMeasures        `json:"size,omitempty"`
	Complexity         *ComplexityMeasures  `json:"complexity,omitempty"`
	Coupling           *CouplingMeasures    `json:"coupling,omitempty"`
	BehavioralHotspots *BehavioralMeasures  `json:"behavioral_hotspots,omitempty"`
	Coverage           *CoverageMeasures    `json:"coverage,omitempty"`
	Duplication        *DuplicationMeasures `json:"duplication,omitempty"`
	Issues             *IssueMeasures       `json:"issues,omitempty"`
	Debt               *DebtMeasures        `json:"debt,omitempty"`
	Ratings            *RatingsMeasures     `json:"ratings,omitempty"`
}

// BehavioralHotspotItem is one immutable, globally ranked file row.
type BehavioralHotspotItem struct {
	Path        string `json:"path"`
	Language    string `json:"language,omitempty"`
	Cyclomatic  int    `json:"cyclomatic"`
	ChangeCount int    `json:"change_count"`
	Score       int    `json:"score"`
}

// BehavioralHotspotsResponse is a bounded top-list pinned to one analysis.
type BehavioralHotspotsResponse struct {
	Project          ProjectNodeInfo                `json:"project"`
	Analysis         AnalysisMetadata               `json:"analysis"`
	Path             string                         `json:"path"`
	Availability     measure.BehavioralAvailability `json:"availability"`
	Reason           *string                        `json:"unavailable_reason"`
	FormulaVersion   int                            `json:"formula_version"`
	RequestedCommits int                            `json:"requested_commits"`
	EvaluatedCommits int                            `json:"evaluated_commits"`
	ReachedRoot      bool                           `json:"reached_root"`
	TotalEligible    int                            `json:"total_eligible"`
	TotalMeasured    int                            `json:"total_measured"`
	TotalExcluded    int                            `json:"total_excluded"`
	Shown            int                            `json:"shown"`
	Omitted          int                            `json:"omitted"`
	Items            []BehavioralHotspotItem        `json:"items"`
}

// ChildCollection wraps a paginated list of immediate child nodes.
type ChildCollection struct {
	Items      []MeasureNode `json:"items"`
	NextCursor *string       `json:"next_cursor"`
}

// ProjectMeasureResponse is the root response payload for the measures API endpoint.
type ProjectMeasureResponse struct {
	State           string            `json:"state"` // "analyzed", "not_analyzed"
	Project         ProjectNodeInfo   `json:"project"`
	Analysis        *AnalysisMetadata `json:"analysis"`
	Path            string            `json:"path"`
	IncludedDomains []string          `json:"included_domains"`
	Node            *MeasureNode      `json:"node"`
	Children        ChildCollection   `json:"children"`
}

// MeasureCursor is the opaque pagination token used to iterate through children.
type MeasureCursor struct {
	Version       int    `json:"v"`
	AnalysisID    string `json:"a"`
	Path          string `json:"r"`
	LastKindRank  int    `json:"k"`
	LastChildPath string `json:"l"`
}

type signedCursor struct {
	Payload   MeasureCursor `json:"p"`
	Signature string        `json:"s"` // base64 string of HMAC-SHA256
}

// Encode serializes the cursor and cryptographically signs it to prevent tampering.
func (c *MeasureCursor) Encode(secret []byte) string {
	b, _ := json.Marshal(c)
	mac := hmac.New(sha256.New, secret)
	mac.Write(b)
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	sc := signedCursor{
		Payload:   *c,
		Signature: signature,
	}
	sb, _ := json.Marshal(sc)
	return base64.RawURLEncoding.EncodeToString(sb)
}

// DecodeMeasureCursor decodes, verifies the signature, and validates the integrity of a pagination cursor.
func DecodeMeasureCursor(s string, secret []byte) (*MeasureCursor, error) {
	if s == "" {
		return nil, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor encoding: %w", err)
	}

	var sc signedCursor
	if err := json.Unmarshal(b, &sc); err != nil {
		return nil, fmt.Errorf("invalid cursor json: %w", err)
	}

	if sc.Payload.Version != 1 {
		return nil, fmt.Errorf("unsupported cursor version: %d", sc.Payload.Version)
	}
	if sc.Payload.AnalysisID == "" {
		return nil, errors.New("missing analysis identity in cursor")
	}
	if sc.Payload.LastKindRank != 1 && sc.Payload.LastKindRank != 2 {
		return nil, errors.New("invalid cursor kind rank")
	}

	// Verify signature
	pb, _ := json.Marshal(sc.Payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write(pb)
	expectedSignature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(sc.Signature), []byte(expectedSignature)) != 1 {
		return nil, errors.New("invalid cursor signature")
	}

	return &sc.Payload, nil
}
