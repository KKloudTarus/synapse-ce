package agentspool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const healthContentType = "application/vnd.synapse.sensor-health+json;version=1"

// CoverageSnapshot is the agent-side P0 representation consumed by A3/A6. It
// deliberately wraps the existing coverage domain records instead of defining
// a second competing coverage state machine.
type CoverageSnapshot struct {
	SchemaVersion int                       `json:"schema_version"`
	ObservedAt    time.Time                 `json:"observed_at"`
	Classes       []detection.ClassCoverage `json:"classes"`
}

// RecordCoverage persists both an aggregate coverage window and one sensor
// state record per class. All records are P0 and never shed: absence of health
// evidence must never make an unobserved host appear clean.
func RecordCoverage(ctx context.Context, durable ports.TelemetrySpool, coverage []detection.ClassCoverage, observedAt time.Time) error {
	if durable == nil {
		return fmt.Errorf("%w: coverage spool is required", shared.ErrValidation)
	}
	if observedAt.IsZero() {
		return fmt.Errorf("%w: coverage observation time is required", shared.ErrValidation)
	}
	copyOfCoverage := append([]detection.ClassCoverage(nil), coverage...)
	for index := range copyOfCoverage {
		if err := copyOfCoverage[index].Validate(); err != nil {
			return fmt.Errorf("coverage[%d]: %w", index, err)
		}
	}
	snapshot := CoverageSnapshot{SchemaVersion: 1, ObservedAt: observedAt.UTC(), Classes: copyOfCoverage}
	if err := enqueueHealth(ctx, durable, ports.SpoolRecordCoverage, snapshot, observedAt); err != nil {
		return err
	}
	for _, state := range copyOfCoverage {
		record := struct {
			SchemaVersion int                     `json:"schema_version"`
			ObservedAt    time.Time               `json:"observed_at"`
			State         detection.ClassCoverage `json:"state"`
		}{SchemaVersion: 1, ObservedAt: observedAt.UTC(), State: state}
		if err := enqueueHealth(ctx, durable, ports.SpoolRecordSensorState, record, observedAt); err != nil {
			return err
		}
	}
	return nil
}

func enqueueHealth(ctx context.Context, durable ports.TelemetrySpool, kind ports.SpoolRecordKind, value any, observedAt time.Time) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode %s: %w", kind, err)
	}
	digest := sha256.Sum256(append([]byte(string(kind)+"\x00"), payload...))
	item := ports.SpoolItem{
		Kind: kind, Priority: fleetagent.PriorityP0,
		EventID:     shared.ID("health_" + hex.EncodeToString(digest[:16])),
		ContentType: healthContentType, Payload: payload, ObservedAt: observedAt.UTC(),
		MustNotShed: true, SchemaVersion: 1,
	}
	for {
		if _, err = durable.Enqueue(ctx, item); !errors.Is(err, ports.ErrTelemetrySpoolSaturated) {
			return err
		}
		if err := waitForSpoolCapacity(ctx); err != nil {
			return err
		}
	}
}
