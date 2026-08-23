package benchmark

import (
	"bytes"
	"strings"
	"testing"
)

func TestEvaluateDeterministicMeasuredObservations(t *testing.T) {
	input := fixtureInput()
	first, err := Evaluate(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Evaluate(input)
	if err != nil {
		t.Fatal(err)
	}
	var firstJSON, secondJSON bytes.Buffer
	if err := EncodeReport(&firstJSON, first); err != nil {
		t.Fatal(err)
	}
	if err := EncodeReport(&secondJSON, second); err != nil {
		t.Fatal(err)
	}
	if firstJSON.String() != secondJSON.String() {
		t.Fatalf("report is not deterministic:\n%s\n---\n%s", firstJSON.String(), secondJSON.String())
	}
	if first.SchemaVersion != OutputSchemaVersion || first.Throughput.RequestsPerSecond != 500 || first.Requests.Count != 5 || first.Requests.Successes != 3 || first.Requests.Failures != 2 {
		t.Fatalf("request summary = %+v throughput=%+v", first.Requests, first.Throughput)
	}
	if got, want := first.Requests.Duration, (Quantiles{Count: 5, P50: 30, P95: 50, P99: 50}); got != want {
		t.Fatalf("request quantiles = %+v, want %+v", got, want)
	}
	if got, want := first.Queue.Delay, (Quantiles{Count: 3, P50: 4, P95: 9, P99: 9}); got != want {
		t.Fatalf("queue delay = %+v, want %+v", got, want)
	}
	if first.Pool.SaturationEvents != 2 || first.Evidence.DatabaseGrowthBytes != 30 || first.Evidence.ObjectGrowthBytes != 50 {
		t.Fatalf("pool=%+v evidence=%+v", first.Pool, first.Evidence)
	}
	if first.APIFailover.RecoveredCount != 1 || first.APIFailover.UnrecoveredCount != 1 || first.Correctness.Failures != 1 || len(first.Correctness.Failed) != 1 || first.Correctness.Failed[0] != "evidence-chain" {
		t.Fatalf("failover=%+v correctness=%+v", first.APIFailover, first.Correctness)
	}
}

func TestDecodeInputRejectsUnknownAndInvalidInput(t *testing.T) {
	_, err := DecodeInput(strings.NewReader(`{"schema_version":"synapse-benchmark-input-v1","unknown":true}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field error = %v", err)
	}
	input := fixtureInput()
	input.SchemaVersion = "v0"
	_, err = Evaluate(input)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("schema error = %v", err)
	}
	input = fixtureInput()
	input.Window.DurationMilliseconds = 0
	_, err = Evaluate(input)
	if err == nil || !strings.Contains(err.Error(), "must be positive") {
		t.Fatalf("window error = %v", err)
	}
}

func fixtureInput() Input {
	return Input{
		SchemaVersion: InputSchemaVersion,
		Metadata:      Metadata{Environment: "fixture", EnvironmentDigest: "sha256:environment", Release: "v1.2.3", ReleaseDigest: "sha256:release", DataDigest: "sha256:data"},
		Window:        Window{DurationMilliseconds: 10},
		Requests:      []RequestObservation{{10, true}, {20, false}, {30, true}, {40, true}, {50, false}},
		Queue:         QueueObservation{DelayMilliseconds: []int64{9, 1, 4}, RecoveryMilliseconds: []int64{7, 3}},
		Pool:          PoolObservation{AcquisitionMilliseconds: []int64{6, 2, 4}, SaturationEvents: 2},
		Evidence:      EvidenceGrowth{DatabaseBeforeBytes: 100, DatabaseAfterBytes: 130, ObjectBeforeBytes: 200, ObjectAfterBytes: 250},
		Migration:     MigrationObservation{DurationMilliseconds: 11},
		APIFailovers:  []APIFailoverObservation{{DetectionMilliseconds: 1, RecoveryMilliseconds: 9, Recovered: true}, {DetectionMilliseconds: 2, RecoveryMilliseconds: 0, Recovered: false}},
		Correctness:   []CorrectnessObservation{{Name: "request-order", Passed: true}, {Name: "evidence-chain", Passed: false}},
	}
}
