package sca

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aitriagereview"
)

const (
	aiTriageDriftBaselineSchema = "synapse-ai-triage-drift-baseline-v1"
	aiTriageDriftReportSchema   = "synapse-ai-triage-drift-report-v1"
	maxDistributionEntries      = 10_000
)

// AITriageDriftBaseline is a versioned, human-approved reference population.
// It carries policy as data so CI cannot silently substitute a threshold.
type AITriageDriftBaseline struct {
	SchemaVersion                    string                       `json:"schema_version"`
	Version                          string                       `json:"version"`
	Provenance                       string                       `json:"provenance"`
	ApprovedBy                       string                       `json:"approved_by"`
	MinimumSamples                   int                          `json:"minimum_samples"`
	MaximumTotalVariationBasisPoints int                          `json:"maximum_total_variation_basis_points"`
	Distribution                     AITriageDistributionSnapshot `json:"distribution"`
}

type AITriageDriftAlert struct {
	Dimension                 string `json:"dimension"`
	TotalVariationBasisPoints int    `json:"total_variation_basis_points"`
	ThresholdBasisPoints      int    `json:"threshold_basis_points"`
	SampleSize                int    `json:"sample_size"`
	Message                   string `json:"message"`
}

// AITriageDriftReport is deterministic CI evidence. It reports population
// change only; it cannot promote a model, change a prompt, or exempt a finding.
type AITriageDriftReport struct {
	SchemaVersion                    string                       `json:"schema_version"`
	ReportID                         string                       `json:"report_id"`
	Status                           string                       `json:"status"`
	ReviewRequired                   bool                         `json:"review_required"`
	BaselineVersion                  string                       `json:"baseline_version"`
	BaselineProvenance               string                       `json:"baseline_provenance"`
	BaselineApprovedBy               string                       `json:"baseline_approved_by"`
	MinimumSamples                   int                          `json:"minimum_samples"`
	MaximumTotalVariationBasisPoints int                          `json:"maximum_total_variation_basis_points"`
	Baseline                         AITriageDistributionSnapshot `json:"baseline"`
	Observed                         AITriageDistributionSnapshot `json:"observed"`
	Alerts                           []AITriageDriftAlert         `json:"alerts"`
}

func LoadAITriageDriftBaseline(data []byte) (AITriageDriftBaseline, error) {
	var baseline AITriageDriftBaseline
	if err := decodeStrictJSON(data, &baseline); err != nil {
		return baseline, fmt.Errorf("decode AI triage drift baseline: %w", err)
	}
	if err := baseline.Validate(); err != nil {
		return baseline, err
	}
	return baseline, nil
}

// LoadAITriageDistributionSnapshot accepts either a snapshot or the saved JSON
// response from GET /api/v1/ai-triage/observability.
func LoadAITriageDistributionSnapshot(data []byte) (AITriageDistributionSnapshot, error) {
	var envelope map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&envelope); err != nil {
		return AITriageDistributionSnapshot{}, fmt.Errorf("decode AI triage distribution: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return AITriageDistributionSnapshot{}, fmt.Errorf("decode AI triage distribution: %w", err)
	}
	payload := data
	if distribution, ok := envelope["distribution"]; ok {
		for _, field := range []string{"schema_version", "sample_size", "language_basis_points", "cwe_basis_points", "project_basis_points"} {
			if _, ambiguous := envelope[field]; ambiguous {
				return AITriageDistributionSnapshot{}, fmt.Errorf("decode AI triage distribution: ambiguous snapshot envelope")
			}
		}
		payload = distribution
	}
	var snapshot AITriageDistributionSnapshot
	if err := decodeStrictJSON(payload, &snapshot); err != nil {
		return snapshot, fmt.Errorf("decode AI triage distribution: %w", err)
	}
	if err := snapshot.Validate(); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func (b AITriageDriftBaseline) Validate() error {
	if b.SchemaVersion != aiTriageDriftBaselineSchema {
		return fmt.Errorf("AI triage drift baseline requires schema %q", aiTriageDriftBaselineSchema)
	}
	for _, field := range []struct{ name, value string }{
		{"version", b.Version}, {"provenance", b.Provenance}, {"approved_by", b.ApprovedBy},
	} {
		if strings.TrimSpace(field.value) == "" || field.value != strings.TrimSpace(field.value) {
			return fmt.Errorf("AI triage drift baseline %s must be non-empty canonical text", field.name)
		}
	}
	if aitriagereview.IsMachineActor(b.ApprovedBy) {
		return fmt.Errorf("AI triage drift baseline must be approved by a human actor")
	}
	if b.MinimumSamples < 1 || b.MinimumSamples > 1_000_000_000 {
		return fmt.Errorf("AI triage drift baseline minimum_samples must be between 1 and 1000000000")
	}
	if b.MaximumTotalVariationBasisPoints < 0 || b.MaximumTotalVariationBasisPoints > 10_000 {
		return fmt.Errorf("AI triage drift baseline maximum total variation must be between 0 and 10000 basis points")
	}
	if err := b.Distribution.Validate(); err != nil {
		return fmt.Errorf("AI triage drift baseline distribution: %w", err)
	}
	if b.Distribution.SampleSize < b.MinimumSamples {
		return fmt.Errorf("AI triage drift baseline distribution has %d samples, below minimum %d", b.Distribution.SampleSize, b.MinimumSamples)
	}
	return nil
}

func (s AITriageDistributionSnapshot) Validate() error {
	if s.SchemaVersion != aiTriageDistributionSchemaVersion {
		return fmt.Errorf("AI triage distribution requires schema %q", aiTriageDistributionSchemaVersion)
	}
	if s.SampleSize < 0 || s.SampleSize > 1_000_000_000 {
		return fmt.Errorf("AI triage distribution sample_size must be between 0 and 1000000000")
	}
	dimensions := []struct {
		name   string
		values map[string]int
		valid  func(string) bool
	}{
		{"language", s.Language, func(value string) bool {
			return value != "" && value == strings.TrimSpace(value) && value == strings.ToLower(value)
		}},
		{"cwe", s.CWE, func(value string) bool { return value == canonicalDistributionCWE(value) }},
		{"project", s.Project, func(value string) bool { return value != "" && value == strings.TrimSpace(value) }},
	}
	for _, dimension := range dimensions {
		if s.SampleSize == 0 {
			if len(dimension.values) != 0 {
				return fmt.Errorf("AI triage distribution %s must be empty when sample_size is zero", dimension.name)
			}
			continue
		}
		if len(dimension.values) == 0 || len(dimension.values) > maxDistributionEntries {
			return fmt.Errorf("AI triage distribution %s must contain between 1 and %d entries", dimension.name, maxDistributionEntries)
		}
		total := 0
		for key, value := range dimension.values {
			if !dimension.valid(key) || value <= 0 || value > 10_000 {
				return fmt.Errorf("AI triage distribution %s entry %q is not canonical positive basis points", dimension.name, key)
			}
			total += value
		}
		if total != 10_000 {
			return fmt.Errorf("AI triage distribution %s sums to %d basis points, want 10000", dimension.name, total)
		}
	}
	return nil
}

func DetectAITriageDistributionDrift(baseline AITriageDriftBaseline, observed AITriageDistributionSnapshot) (AITriageDriftReport, error) {
	if err := baseline.Validate(); err != nil {
		return AITriageDriftReport{}, err
	}
	if err := observed.Validate(); err != nil {
		return AITriageDriftReport{}, err
	}
	report := AITriageDriftReport{
		SchemaVersion: aiTriageDriftReportSchema, Status: "stable",
		BaselineVersion: baseline.Version, BaselineProvenance: baseline.Provenance, BaselineApprovedBy: baseline.ApprovedBy,
		MinimumSamples: baseline.MinimumSamples, MaximumTotalVariationBasisPoints: baseline.MaximumTotalVariationBasisPoints,
		Baseline: baseline.Distribution, Observed: observed, Alerts: []AITriageDriftAlert{},
	}
	if observed.SampleSize < baseline.MinimumSamples {
		report.Status = "insufficient_samples"
		report.ReviewRequired = true
		report.Alerts = append(report.Alerts, AITriageDriftAlert{
			Dimension: "all", ThresholdBasisPoints: baseline.MaximumTotalVariationBasisPoints, SampleSize: observed.SampleSize,
			Message: fmt.Sprintf("observed sample size %d is below the approved minimum %d", observed.SampleSize, baseline.MinimumSamples),
		})
	} else {
		dimensions := []struct {
			name               string
			baseline, observed map[string]int
		}{
			{"language", baseline.Distribution.Language, observed.Language},
			{"cwe", baseline.Distribution.CWE, observed.CWE},
			{"project", baseline.Distribution.Project, observed.Project},
		}
		for _, dimension := range dimensions {
			distance := totalVariationBasisPoints(dimension.baseline, dimension.observed)
			if distance > baseline.MaximumTotalVariationBasisPoints {
				report.Alerts = append(report.Alerts, AITriageDriftAlert{
					Dimension: dimension.name, TotalVariationBasisPoints: distance,
					ThresholdBasisPoints: baseline.MaximumTotalVariationBasisPoints, SampleSize: observed.SampleSize,
					Message: fmt.Sprintf("%s distribution drift is %d basis points, above the approved maximum %d", dimension.name, distance, baseline.MaximumTotalVariationBasisPoints),
				})
			}
		}
		if len(report.Alerts) > 0 {
			report.Status = "drift_detected"
			report.ReviewRequired = true
		}
	}
	report.ReportID = aiTriageDriftReportID(report)
	return report, nil
}

func totalVariationBasisPoints(baseline, observed map[string]int) int {
	keys := make(map[string]struct{}, len(baseline)+len(observed))
	for key := range baseline {
		keys[key] = struct{}{}
	}
	for key := range observed {
		keys[key] = struct{}{}
	}
	difference := 0
	for key := range keys {
		delta := baseline[key] - observed[key]
		if delta < 0 {
			delta = -delta
		}
		difference += delta
	}
	return difference / 2
}

func aiTriageDriftReportID(report AITriageDriftReport) string {
	report.ReportID = ""
	data, _ := json.Marshal(report)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func decodeStrictJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func requireJSONEOF(decoder *json.Decoder) error {
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON content")
		}
		return err
	}
	return nil
}
