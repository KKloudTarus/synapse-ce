package agentspool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const detectionContentType = "application/vnd.synapse.detection+json;version=1"

// DetectionSink persists confirmed detections in P1. Its deterministic event
// id is derived from the canonical JSON, making an engine retry idempotent.
type DetectionSink struct{ spool ports.TelemetrySpool }

func NewDetectionSink(durable ports.TelemetrySpool) (*DetectionSink, error) {
	if durable == nil {
		return nil, fmt.Errorf("%w: detection spool is required", shared.ErrValidation)
	}
	return &DetectionSink{spool: durable}, nil
}

func (s *DetectionSink) Emit(ctx context.Context, value detection.Detection) error {
	if err := value.Validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode detection for spool: %w", err)
	}
	digest := sha256.Sum256(payload)
	id := shared.ID("det_" + hex.EncodeToString(digest[:16]))
	item := ports.SpoolItem{
		Kind: ports.SpoolRecordDetection, Priority: fleetagent.PriorityP1,
		EventID: id, EventClass: value.Class, ContentType: detectionContentType,
		Payload: payload, ObservedAt: value.Observed.UTC(), MustNotShed: true,
		SchemaVersion: 1,
	}
	for {
		if _, err = s.spool.Enqueue(ctx, item); !errors.Is(err, ports.ErrTelemetrySpoolSaturated) {
			return err
		}
		if err := waitForSpoolCapacity(ctx); err != nil {
			return err
		}
	}
}

var _ ports.DetectionSink = (*DetectionSink)(nil)
