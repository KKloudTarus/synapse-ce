package finding

import (
	"errors"
	"fmt"
)

const (
	// MaxDataFlowSteps caps the source-to-sink positions persisted with one finding.
	MaxDataFlowSteps    = 64
	maxDataFlowFileSize = 512
)

var (
	ErrDataFlowLanguage = errors.New("data-flow language is invalid")
	ErrDataFlowSteps    = errors.New("data-flow steps are invalid")
)

// DataFlowTrace is the persistent, source-only witness for a confirmed taint finding. Steps are ordered
// from Source to Sink and contain positions only; source text, value identifiers, and parser output never
// cross this domain boundary.
type DataFlowTrace struct {
	Language         string           `json:"language"`
	Source           SourceLocation   `json:"source"`
	Sink             SourceLocation   `json:"sink"`
	Steps            []SourceLocation `json:"steps"`
	CoverageComplete bool             `json:"coverage_complete"`
	GraphTruncated   bool             `json:"graph_truncated"`
}

func (d DataFlowTrace) Validate() error {
	if d.Language != "python" {
		return ErrDataFlowLanguage
	}
	if len(d.Steps) == 0 || len(d.Steps) > MaxDataFlowSteps {
		return ErrDataFlowSteps
	}
	locations := make([]SourceLocation, 0, len(d.Steps)+2)
	locations = append(locations, d.Source, d.Sink)
	locations = append(locations, d.Steps...)
	for _, location := range locations {
		if len(location.File) > maxDataFlowFileSize {
			return fmt.Errorf("%w: file exceeds %d bytes", ErrSourceLocationFile, maxDataFlowFileSize)
		}
		if err := location.Validate(); err != nil {
			return err
		}
	}
	if !sameSourceLocation(d.Steps[0], d.Source) || !sameSourceLocation(d.Steps[len(d.Steps)-1], d.Sink) {
		return ErrDataFlowSteps
	}
	return nil
}

// CloneDataFlowTrace deep-copies pointer columns and the ordered step list at repository boundaries.
func CloneDataFlowTrace(in *DataFlowTrace) *DataFlowTrace {
	if in == nil {
		return nil
	}
	out := *in
	out.Source = cloneSourceLocation(in.Source)
	out.Sink = cloneSourceLocation(in.Sink)
	out.Steps = make([]SourceLocation, len(in.Steps))
	for i := range in.Steps {
		out.Steps[i] = cloneSourceLocation(in.Steps[i])
	}
	return &out
}

func EqualDataFlowTrace(left, right *DataFlowTrace) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	if left.Language != right.Language || left.CoverageComplete != right.CoverageComplete || left.GraphTruncated != right.GraphTruncated ||
		!sameSourceLocation(left.Source, right.Source) || !sameSourceLocation(left.Sink, right.Sink) || len(left.Steps) != len(right.Steps) {
		return false
	}
	for i := range left.Steps {
		if !sameSourceLocation(left.Steps[i], right.Steps[i]) {
			return false
		}
	}
	return true
}

func cloneSourceLocation(in SourceLocation) SourceLocation {
	out := in
	if in.StartColumn != nil {
		value := *in.StartColumn
		out.StartColumn = &value
	}
	if in.EndColumn != nil {
		value := *in.EndColumn
		out.EndColumn = &value
	}
	return out
}

func sameSourceLocation(left, right SourceLocation) bool {
	return left.File == right.File && left.StartLine == right.StartLine && left.EndLine == right.EndLine &&
		sameOptionalInt(left.StartColumn, right.StartColumn) && sameOptionalInt(left.EndColumn, right.EndColumn)
}

func sameOptionalInt(left, right *int) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
