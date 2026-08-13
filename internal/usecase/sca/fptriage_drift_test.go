package sca

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDetectAITriageDistributionDriftReportsExactDistances(t *testing.T) {
	baseline := validDriftBaseline()
	observed := distributionSnapshot(80,
		map[string]int{"go": 3000, "typescript": 7000},
		map[string]int{"CWE-79": 8000, "CWE-89": 2000},
		map[string]int{"project-a": 10_000},
	)
	report, err := DetectAITriageDistributionDrift(baseline, observed)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "drift_detected" || !report.ReviewRequired || len(report.Alerts) != 2 {
		t.Fatalf("report = %+v", report)
	}
	if report.Alerts[0].Dimension != "language" || report.Alerts[0].TotalVariationBasisPoints != 3000 ||
		report.Alerts[1].Dimension != "cwe" || report.Alerts[1].TotalVariationBasisPoints != 2000 {
		t.Fatalf("alerts = %+v", report.Alerts)
	}
	again, err := DetectAITriageDistributionDrift(baseline, observed)
	if err != nil || report.ReportID == "" || report.ReportID != again.ReportID {
		t.Fatalf("report IDs = %q and %q, err %v", report.ReportID, again.ReportID, err)
	}
}

func TestDetectAITriageDistributionDriftHandlesStableAndSmallSamples(t *testing.T) {
	baseline := validDriftBaseline()
	baseline.MaximumTotalVariationBasisPoints = 3000
	observed := distributionSnapshot(50,
		map[string]int{"go": 3000, "typescript": 7000},
		map[string]int{"CWE-79": 10_000},
		map[string]int{"project-a": 10_000},
	)
	report, err := DetectAITriageDistributionDrift(baseline, observed)
	if err != nil || report.Status != "stable" || report.ReviewRequired || len(report.Alerts) != 0 {
		t.Fatalf("stable report = %+v, err %v", report, err)
	}

	observed.SampleSize = 49
	report, err = DetectAITriageDistributionDrift(baseline, observed)
	if err != nil || report.Status != "insufficient_samples" || len(report.Alerts) != 1 || report.Alerts[0].Dimension != "all" {
		t.Fatalf("small-sample report = %+v, err %v", report, err)
	}
}

func TestAITriageDriftBaselineValidationFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AITriageDriftBaseline)
		want   string
	}{
		{"machine approver", func(b *AITriageDriftBaseline) { b.ApprovedBy = "bot:baseline" }, "human actor"},
		{"insufficient baseline", func(b *AITriageDriftBaseline) { b.MinimumSamples = 101 }, "below minimum"},
		{"invalid total", func(b *AITriageDriftBaseline) { b.Distribution.Language["go"] = 5999 }, "sums to"},
		{"noncanonical cwe", func(b *AITriageDriftBaseline) { b.Distribution.CWE = map[string]int{"cwe-79": 10_000} }, "not canonical"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseline := validDriftBaseline()
			test.mutate(&baseline)
			if err := baseline.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestAITriageDriftLoadersRejectAmbiguousJSON(t *testing.T) {
	baseline := validDriftBaseline()
	data, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAITriageDriftBaseline(append(data, []byte(` {}`)...)); err == nil {
		t.Fatal("baseline loader accepted trailing JSON")
	}
	withUnknown := append(data[:len(data)-1], []byte(`,"unexpected":true}`)...)
	if _, err := LoadAITriageDriftBaseline(withUnknown); err == nil {
		t.Fatal("baseline loader accepted an unknown field")
	}

	snapshotData, err := json.Marshal(map[string]any{
		"generated_at": "2026-08-13T00:00:00Z",
		"distribution": baseline.Distribution,
	})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadAITriageDistributionSnapshot(snapshotData)
	if err != nil || loaded.SampleSize != baseline.Distribution.SampleSize {
		t.Fatalf("load dashboard snapshot = %+v, %v", loaded, err)
	}
	ambiguousData, err := json.Marshal(map[string]any{
		"schema_version": "synapse-ai-triage-distribution-v1",
		"distribution":   baseline.Distribution,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAITriageDistributionSnapshot(ambiguousData); err == nil {
		t.Fatal("snapshot loader accepted ambiguous direct and envelope fields")
	}
}

func validDriftBaseline() AITriageDriftBaseline {
	return AITriageDriftBaseline{
		SchemaVersion: aiTriageDriftBaselineSchema,
		Version:       "production-2026-08", Provenance: "security/review-42", ApprovedBy: "security@example.com",
		MinimumSamples: 50, MaximumTotalVariationBasisPoints: 1000,
		Distribution: distributionSnapshot(100,
			map[string]int{"go": 6000, "typescript": 4000},
			map[string]int{"CWE-79": 10_000},
			map[string]int{"project-a": 10_000},
		),
	}
}

func distributionSnapshot(sampleSize int, language, cwe, project map[string]int) AITriageDistributionSnapshot {
	return AITriageDistributionSnapshot{
		SchemaVersion: aiTriageDistributionSchemaVersion, SampleSize: sampleSize,
		Language: language, CWE: cwe, Project: project,
	}
}
