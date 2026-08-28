package sensorstate

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func testWindow() CoverageWindow {
	at := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	return CoverageWindow{
		AssetID: "asset-1", AgentID: "agent-1", HostID: "host-1", Since: at.Add(-time.Hour), Until: at, CreatedAt: at,
		InputDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		States: []detection.ClassCoverage{
			{Class: detection.ClassProcess, HostID: "host-1", AgentID: "agent-1", State: detection.StateActive, Since: at.Add(-time.Hour)},
			{Class: detection.ClassNetwork, HostID: "host-1", AgentID: "agent-1", State: detection.StateDegraded, Reason: "kernel_capability_missing", Since: at.Add(-time.Hour)},
			{Class: detection.ClassFile, HostID: "host-1", AgentID: "agent-1", State: detection.StateDisabled, Since: at.Add(-time.Hour)},
			{Class: detection.ClassPrivilege, HostID: "host-1", AgentID: "agent-1", State: detection.StateFailed, Reason: "sensor_error", Since: at.Add(-time.Hour)},
		},
	}
}

func TestBuildCoverageVectorIsDeterministicAndCoverageHonest(t *testing.T) {
	window := testWindow()
	window.SampledCount = 1
	window.TruncatedCount = 2
	window.DroppedCount = 3
	window.GapCount = 4

	got := BuildCoverageVector(window)
	if got.Process != 80 || got.Network != 60 || got.File != 25 || got.Privilege != 0 {
		t.Fatalf("vector = %#v, want process=80 network=60 file=25 privilege=0", got)
	}
	wantReasons := []string{
		"file:disabled", "network:degraded:kernel_capability_missing", "privilege:failed:sensor_error", "telemetry_dropped:3",
		"telemetry_gap:4", "telemetry_sampled:1", "telemetry_truncated:2",
	}
	if len(got.Reasons) != len(wantReasons) {
		t.Fatalf("reasons = %#v, want %#v", got.Reasons, wantReasons)
	}
	for i := range wantReasons {
		if got.Reasons[i] != wantReasons[i] {
			t.Fatalf("reason[%d] = %q, want %q", i, got.Reasons[i], wantReasons[i])
		}
	}
}

func TestBuildCoverageVectorPreservesIndependentLossCounters(t *testing.T) {
	window := testWindow()
	baseline := BuildCoverageVector(window)
	for _, tt := range []struct {
		name   string
		mutate func(*CoverageWindow)
		want   string
	}{
		{"sampled", func(w *CoverageWindow) { w.SampledCount = 1 }, "telemetry_sampled:1"},
		{"truncated", func(w *CoverageWindow) { w.TruncatedCount = 1 }, "telemetry_truncated:1"},
		{"dropped", func(w *CoverageWindow) { w.DroppedCount = 1 }, "telemetry_dropped:1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w := window
			tt.mutate(&w)
			got := BuildCoverageVector(w)
			if got.Process != 80 {
				t.Fatalf("process coverage = %d, want 80", got.Process)
			}
			if got.Process == baseline.Process {
				t.Fatalf("%s did not lower active coverage: got %d", tt.name, got.Process)
			}
			found := false
			for _, reason := range got.Reasons {
				found = found || reason == tt.want
			}
			if !found {
				t.Fatalf("reasons = %#v, missing %q", got.Reasons, tt.want)
			}
		})
	}
}

func TestBuildCoverageVectorReportsMissingState(t *testing.T) {
	window := testWindow()
	window.States = window.States[:1]

	got := BuildCoverageVector(window)
	if got.Network != 0 || got.File != 0 || got.Privilege != 0 {
		t.Fatalf("missing coverage = %#v, want zero values", got)
	}
	for _, want := range []string{"network:missing_state", "file:missing_state", "privilege:missing_state"} {
		found := false
		for _, reason := range got.Reasons {
			found = found || reason == want
		}
		if !found {
			t.Fatalf("reasons = %#v, missing %q", got.Reasons, want)
		}
	}
}

func TestRevisionForIsStableAcrossStateOrder(t *testing.T) {
	window := testWindow()
	window.SampledCount = 1
	window.Vector = BuildCoverageVector(window)
	window.Revision = RevisionFor(window)
	if err := window.Validate(); err != nil {
		t.Fatalf("validate window: %v", err)
	}
	reordered := window
	reordered.States = []detection.ClassCoverage{window.States[3], window.States[1], window.States[0], window.States[2]}
	if got := RevisionFor(reordered); got != window.Revision {
		t.Fatalf("revision = %q, want %q after equivalent reordering", got, window.Revision)
	}
}

func TestRevisionForCommitsClassIdentity(t *testing.T) {
	window := testWindow()
	window.Vector = BuildCoverageVector(window)
	window.Revision = RevisionFor(window)

	changed := window
	changed.States = append([]detection.ClassCoverage(nil), window.States...)
	changed.States[0].HostID = "other-host"
	if got := RevisionFor(changed); got == window.Revision {
		t.Fatal("class-state host identity did not change coverage revision")
	}
	changed = window
	changed.States = append([]detection.ClassCoverage(nil), window.States...)
	changed.States[0].AgentID = "other-agent"
	if got := RevisionFor(changed); got == window.Revision {
		t.Fatal("class-state agent identity did not change coverage revision")
	}
}

func TestRevisionForCommitsExactSourceInput(t *testing.T) {
	window := testWindow()
	first := RevisionFor(window)
	window.InputDigest = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	if second := RevisionFor(window); second == first {
		t.Fatal("different immutable source facts produced the same revision")
	}
}

func TestCoverageWindowRequiresNonEmptyHalfOpenInterval(t *testing.T) {
	for _, until := range []time.Time{testWindow().Since, testWindow().Since.Add(-time.Nanosecond)} {
		window := testWindow()
		window.Until = until
		window.Vector = BuildCoverageVector(window)
		window.Revision = RevisionFor(window)
		if err := window.Validate(); err == nil {
			t.Fatalf("Validate() accepted interval [%s,%s)", window.Since, window.Until)
		}
	}
}

func TestCoverageWindowRequiresCanonicalRevisionTimestamps(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*CoverageWindow)
	}{
		{
			name: "since sub-microsecond",
			mutate: func(window *CoverageWindow) {
				window.Since = window.Since.Add(time.Nanosecond)
			},
		},
		{
			name: "until sub-microsecond",
			mutate: func(window *CoverageWindow) {
				window.Until = window.Until.Add(time.Nanosecond)
			},
		},
		{
			name: "class state since sub-microsecond",
			mutate: func(window *CoverageWindow) {
				window.States[0].Since = window.States[0].Since.Add(time.Nanosecond)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			window := testWindow()
			tt.mutate(&window)
			window.Vector = BuildCoverageVector(window)
			window.Revision = RevisionFor(window)
			if err := window.Validate(); err == nil {
				t.Fatal("Validate() accepted a noncanonical revision-bearing timestamp")
			}
		})
	}
}

func TestCoverageWindowAllowsNoncanonicalServerCreatedAt(t *testing.T) {
	window := testWindow()
	window.CreatedAt = window.CreatedAt.Add(time.Nanosecond)
	window.Vector = BuildCoverageVector(window)
	window.Revision = RevisionFor(window)
	if err := window.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want server-owned CreatedAt excluded from revision precision", err)
	}
}

func TestCoverageWindowRequiresExactSourceDigest(t *testing.T) {
	for _, digest := range []string{"", "not-a-digest"} {
		window := testWindow()
		window.InputDigest = digest
		window.Vector = BuildCoverageVector(window)
		window.Revision = RevisionFor(window)
		if err := window.Validate(); err == nil {
			t.Fatalf("Validate() accepted input digest %q", digest)
		}
	}
}

func TestCoverageWindowRejectsStaleFacts(t *testing.T) {
	window := testWindow()
	window.Vector = BuildCoverageVector(window)
	window.Revision = RevisionFor(window)
	window.DroppedCount = 1
	if err := window.Validate(); err == nil {
		t.Fatal("Validate() succeeded with a vector that ignores dropped records")
	}

	window = testWindow()
	window.Vector = BuildCoverageVector(window)
	window.Revision = RevisionFor(window)
	window.BatchCount = 1
	if err := window.Validate(); err == nil {
		t.Fatal("Validate() succeeded with a revision that ignores batch count")
	}

	window = testWindow()
	window.Vector = BuildCoverageVector(window)
	window.Revision = RevisionFor(window)
	window.Vector.Reasons = []string{"z", "a"}
	if err := window.Validate(); err == nil {
		t.Fatal("Validate() succeeded with unsorted reasons")
	}
}

func TestCoverageWindowRejectsNegativeIndependentCounters(t *testing.T) {
	for _, mutate := range []func(*CoverageWindow){
		func(w *CoverageWindow) { w.SampledCount = -1 },
		func(w *CoverageWindow) { w.TruncatedCount = -1 },
		func(w *CoverageWindow) { w.DroppedCount = -1 },
	} {
		window := testWindow()
		window.Vector = BuildCoverageVector(window)
		window.Revision = RevisionFor(window)
		mutate(&window)
		if err := window.Validate(); err == nil {
			t.Fatal("Validate() succeeded with a negative independent loss counter")
		}
	}
}

func TestCoverageWindowRejectsMismatchedOrRepeatedClassState(t *testing.T) {
	for _, mutate := range []func(*CoverageWindow){
		func(w *CoverageWindow) { w.States[0].HostID = "other" },
		func(w *CoverageWindow) { w.States[0].AgentID = "other" },
		func(w *CoverageWindow) { w.States = append(w.States, w.States[0]) },
	} {
		window := testWindow()
		mutate(&window)
		window.Vector = BuildCoverageVector(window)
		window.Revision = RevisionFor(window)
		if err := window.Validate(); err == nil {
			t.Fatal("Validate() succeeded for an invalid class-state identity")
		}
	}
}

func TestObservationValidationRejectsMismatchedClassIdentity(t *testing.T) {
	at := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	observation := Observation{
		ReportID: "report-1", AgentID: "agent-1", HostID: "agent-1", AssetID: "asset-1", Kind: RecordSensorState,
		ObservedAt: at, RecordedAt: at, SchemaVersion: 1,
		PayloadDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		States:        []detection.ClassCoverage{{Class: detection.ClassProcess, HostID: "other", AgentID: shared.ID("agent-1"), State: detection.StateActive, Since: at}},
	}
	if err := observation.Validate(); err == nil {
		t.Fatal("Validate() succeeded for mismatched class host")
	}
}
