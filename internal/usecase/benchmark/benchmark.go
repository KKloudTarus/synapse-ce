// Package benchmark reduces fixture-supplied benchmark observations into a
// deterministic, versioned report. It performs no workload execution or external I/O.
package benchmark

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
)

const (
	InputSchemaVersion  = "synapse-benchmark-input-v1"
	OutputSchemaVersion = "synapse-benchmark-report-v1"
)

// Input is a fixture or runner-produced set of measured benchmark observations.
type Input struct {
	SchemaVersion string                   `json:"schema_version"`
	Metadata      Metadata                 `json:"metadata"`
	Window        Window                   `json:"window"`
	Requests      []RequestObservation     `json:"requests"`
	Queue         QueueObservation         `json:"queue"`
	Pool          PoolObservation          `json:"pool"`
	Evidence      EvidenceGrowth           `json:"evidence"`
	Migration     MigrationObservation     `json:"migration"`
	APIFailovers  []APIFailoverObservation `json:"api_failovers"`
	Correctness   []CorrectnessObservation `json:"correctness"`
}

// Metadata identifies exactly what was measured without deriving release or data state.
type Metadata struct {
	Environment       string `json:"environment"`
	EnvironmentDigest string `json:"environment_digest"`
	Release           string `json:"release"`
	ReleaseDigest     string `json:"release_digest"`
	DataDigest        string `json:"data_digest"`
}

type Window struct {
	DurationMilliseconds int64 `json:"duration_milliseconds"`
}

type RequestObservation struct {
	DurationMilliseconds int64 `json:"duration_milliseconds"`
	Succeeded            bool  `json:"succeeded"`
}

type QueueObservation struct {
	DelayMilliseconds    []int64 `json:"delay_milliseconds"`
	RecoveryMilliseconds []int64 `json:"recovery_milliseconds"`
}

type PoolObservation struct {
	AcquisitionMilliseconds []int64 `json:"acquisition_milliseconds"`
	SaturationEvents        int64   `json:"saturation_events"`
}

type EvidenceGrowth struct {
	DatabaseBeforeBytes int64 `json:"database_before_bytes"`
	DatabaseAfterBytes  int64 `json:"database_after_bytes"`
	ObjectBeforeBytes   int64 `json:"object_before_bytes"`
	ObjectAfterBytes    int64 `json:"object_after_bytes"`
}

type MigrationObservation struct {
	DurationMilliseconds int64 `json:"duration_milliseconds"`
}

type APIFailoverObservation struct {
	DetectionMilliseconds int64 `json:"detection_milliseconds"`
	RecoveryMilliseconds  int64 `json:"recovery_milliseconds"`
	Recovered             bool  `json:"recovered"`
}

type CorrectnessObservation struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
}

// Report is a deterministic reduction of Input. It never asserts an SLO or target.
type Report struct {
	SchemaVersion string                `json:"schema_version"`
	Metadata      Metadata              `json:"metadata"`
	Throughput    Throughput            `json:"throughput"`
	Requests      RequestSummary        `json:"requests"`
	Queue         QueueSummary          `json:"queue"`
	Pool          PoolSummary           `json:"pool"`
	Evidence      EvidenceGrowthSummary `json:"evidence"`
	Migration     MigrationObservation  `json:"migration"`
	APIFailover   APIFailoverSummary    `json:"api_failover"`
	Correctness   CorrectnessSummary    `json:"correctness"`
}

type Throughput struct {
	WindowMilliseconds int64   `json:"window_milliseconds"`
	RequestsPerSecond  float64 `json:"requests_per_second"`
}

type RequestSummary struct {
	Count     int64     `json:"count"`
	Successes int64     `json:"successes"`
	Failures  int64     `json:"failures"`
	Duration  Quantiles `json:"duration_milliseconds"`
}

type QueueSummary struct {
	Delay    Quantiles `json:"delay_milliseconds"`
	Recovery Quantiles `json:"recovery_milliseconds"`
}

type PoolSummary struct {
	Acquisition      Quantiles `json:"acquisition_milliseconds"`
	SaturationEvents int64     `json:"saturation_events"`
}

type EvidenceGrowthSummary struct {
	DatabaseBeforeBytes int64 `json:"database_before_bytes"`
	DatabaseAfterBytes  int64 `json:"database_after_bytes"`
	DatabaseGrowthBytes int64 `json:"database_growth_bytes"`
	ObjectBeforeBytes   int64 `json:"object_before_bytes"`
	ObjectAfterBytes    int64 `json:"object_after_bytes"`
	ObjectGrowthBytes   int64 `json:"object_growth_bytes"`
}

type APIFailoverSummary struct {
	Count            int64     `json:"count"`
	RecoveredCount   int64     `json:"recovered_count"`
	UnrecoveredCount int64     `json:"unrecovered_count"`
	Detection        Quantiles `json:"detection_milliseconds"`
	Recovery         Quantiles `json:"recovery_milliseconds"`
}

type CorrectnessSummary struct {
	Checks   int64    `json:"checks"`
	Failures int64    `json:"failures"`
	Failed   []string `json:"failed"`
}

// Quantiles use the nearest-rank method: rank=ceil(p*n), with the first value at rank 1.
type Quantiles struct {
	Count int64 `json:"count"`
	P50   int64 `json:"p50"`
	P95   int64 `json:"p95"`
	P99   int64 `json:"p99"`
}

// DecodeInput accepts exactly one JSON input document and rejects unknown fields.
func DecodeInput(r io.Reader) (Input, error) {
	var input Input
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return Input{}, fmt.Errorf("decode benchmark input: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Input{}, fmt.Errorf("decode benchmark input: multiple JSON values")
		}
		return Input{}, fmt.Errorf("decode benchmark input trailing data: %w", err)
	}
	return input, nil
}

// Evaluate validates and reduces the supplied measurements without making any measurements itself.
func Evaluate(input Input) (Report, error) {
	if err := validate(input); err != nil {
		return Report{}, err
	}

	requestDurations := make([]int64, len(input.Requests))
	var successes int64
	for i, request := range input.Requests {
		requestDurations[i] = request.DurationMilliseconds
		if request.Succeeded {
			successes++
		}
	}
	failed := make([]string, 0)
	for _, check := range input.Correctness {
		if !check.Passed {
			failed = append(failed, check.Name)
		}
	}
	failoverDetection := make([]int64, len(input.APIFailovers))
	failoverRecovery := make([]int64, len(input.APIFailovers))
	var recovered int64
	for i, observation := range input.APIFailovers {
		failoverDetection[i] = observation.DetectionMilliseconds
		failoverRecovery[i] = observation.RecoveryMilliseconds
		if observation.Recovered {
			recovered++
		}
	}

	count := int64(len(input.Requests))
	return Report{
		SchemaVersion: OutputSchemaVersion,
		Metadata:      input.Metadata,
		Throughput: Throughput{
			WindowMilliseconds: input.Window.DurationMilliseconds,
			RequestsPerSecond:  float64(count) * 1000 / float64(input.Window.DurationMilliseconds),
		},
		Requests: RequestSummary{Count: count, Successes: successes, Failures: count - successes, Duration: calculateQuantiles(requestDurations)},
		Queue:    QueueSummary{Delay: calculateQuantiles(input.Queue.DelayMilliseconds), Recovery: calculateQuantiles(input.Queue.RecoveryMilliseconds)},
		Pool:     PoolSummary{Acquisition: calculateQuantiles(input.Pool.AcquisitionMilliseconds), SaturationEvents: input.Pool.SaturationEvents},
		Evidence: EvidenceGrowthSummary{
			DatabaseBeforeBytes: input.Evidence.DatabaseBeforeBytes,
			DatabaseAfterBytes:  input.Evidence.DatabaseAfterBytes,
			DatabaseGrowthBytes: input.Evidence.DatabaseAfterBytes - input.Evidence.DatabaseBeforeBytes,
			ObjectBeforeBytes:   input.Evidence.ObjectBeforeBytes,
			ObjectAfterBytes:    input.Evidence.ObjectAfterBytes,
			ObjectGrowthBytes:   input.Evidence.ObjectAfterBytes - input.Evidence.ObjectBeforeBytes,
		},
		Migration: input.Migration,
		APIFailover: APIFailoverSummary{
			Count: int64(len(input.APIFailovers)), RecoveredCount: recovered, UnrecoveredCount: int64(len(input.APIFailovers)) - recovered,
			Detection: calculateQuantiles(failoverDetection), Recovery: calculateQuantiles(failoverRecovery),
		},
		Correctness: CorrectnessSummary{Checks: int64(len(input.Correctness)), Failures: int64(len(failed)), Failed: failed},
	}, nil
}

// EncodeReport writes one stable, indented JSON document followed by a newline.
func EncodeReport(w io.Writer, report Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encode benchmark report: %w", err)
	}
	return nil
}

func calculateQuantiles(values []int64) Quantiles {
	if len(values) == 0 {
		return Quantiles{}
	}
	sorted := append([]int64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	at := func(percentile float64) int64 {
		rank := int(math.Ceil(percentile * float64(len(sorted))))
		return sorted[rank-1]
	}
	return Quantiles{Count: int64(len(sorted)), P50: at(0.50), P95: at(0.95), P99: at(0.99)}
}

func validate(input Input) error {
	if input.SchemaVersion != InputSchemaVersion {
		return fmt.Errorf("unsupported benchmark input schema version %q", input.SchemaVersion)
	}
	for _, metadataField := range []struct{ name, value string }{
		{"metadata.environment", input.Metadata.Environment}, {"metadata.environment_digest", input.Metadata.EnvironmentDigest},
		{"metadata.release", input.Metadata.Release}, {"metadata.release_digest", input.Metadata.ReleaseDigest}, {"metadata.data_digest", input.Metadata.DataDigest},
	} {
		if strings.TrimSpace(metadataField.value) == "" {
			return fmt.Errorf("%s is required", metadataField.name)
		}
	}
	if input.Window.DurationMilliseconds <= 0 {
		return fmt.Errorf("window.duration_milliseconds must be positive")
	}
	for _, value := range input.Requests {
		if value.DurationMilliseconds < 0 {
			return fmt.Errorf("request duration must not be negative")
		}
	}
	if err := validateMeasurements("queue delay", input.Queue.DelayMilliseconds); err != nil {
		return err
	}
	if err := validateMeasurements("queue recovery", input.Queue.RecoveryMilliseconds); err != nil {
		return err
	}
	if err := validateMeasurements("pool acquisition", input.Pool.AcquisitionMilliseconds); err != nil {
		return err
	}
	if input.Pool.SaturationEvents < 0 {
		return fmt.Errorf("pool saturation events must not be negative")
	}
	if input.Evidence.DatabaseBeforeBytes < 0 || input.Evidence.DatabaseAfterBytes < 0 || input.Evidence.ObjectBeforeBytes < 0 || input.Evidence.ObjectAfterBytes < 0 {
		return fmt.Errorf("evidence byte observations must not be negative")
	}
	if input.Migration.DurationMilliseconds < 0 {
		return fmt.Errorf("migration duration must not be negative")
	}
	for _, value := range input.APIFailovers {
		if value.DetectionMilliseconds < 0 || value.RecoveryMilliseconds < 0 {
			return fmt.Errorf("API failover observations must not be negative")
		}
	}
	for _, check := range input.Correctness {
		if strings.TrimSpace(check.Name) == "" {
			return fmt.Errorf("correctness check name is required")
		}
	}
	return nil
}

func validateMeasurements(name string, values []int64) error {
	for _, value := range values {
		if value < 0 {
			return fmt.Errorf("%s measurement must not be negative", name)
		}
	}
	return nil
}
