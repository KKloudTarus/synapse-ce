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
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const detectionContentType = "application/vnd.synapse.detection+json;version=1"

// DetectionSink persists confirmed detections in P1. Its deterministic event
// id is derived from the canonical JSON, making an engine retry idempotent.
type DetectionSink struct {
	spool  ports.TelemetrySpool
	policy privacy.Policy
}

func NewDetectionSink(durable ports.TelemetrySpool) (*DetectionSink, error) {
	if durable == nil {
		return nil, fmt.Errorf("%w: detection spool is required", shared.ErrValidation)
	}
	return &DetectionSink{spool: durable, policy: privacy.DefaultPolicy()}, nil
}

// SetRedactionPolicy overrides the source-side redaction policy applied to detection evidence (A6, #627).
// The sink defaults to privacy.DefaultPolicy(); an invalid policy is rejected so evidence is never shipped
// with a broken (fail-open) redaction config.
func (s *DetectionSink) SetRedactionPolicy(p privacy.Policy) error {
	if err := p.ValidateSourceFloor(); err != nil {
		return err
	}
	s.policy = p
	return nil
}

func (s *DetectionSink) Emit(ctx context.Context, value detection.Detection) error {
	if err := value.Validate(); err != nil {
		return err
	}
	// A6 (#627): redact the detection's EVIDENCE at the source before it is persisted/shipped/sealed, so a
	// rule that fired on a credential-bearing command line does not leak the secret the telemetry path
	// already scrubs. The engine keeps its own (raw) copy for local fidelity; only the shipped record is
	// redacted. The deterministic id below is derived from the REDACTED payload, so retries stay idempotent.
	value, _, err := privacy.ScrubDetection(value, s.policy)
	if err != nil {
		return fmt.Errorf("redact detection evidence: %w", err)
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode detection for spool: %w", err)
	}
	return s.enqueue(ctx, value, payload, detectionContentType, 1)
}

// EmitAttributed creates a v2 spool record only for sources that possess actual transport facts.
// The current DetectionSensor API does not expose those facts, so its ordinary Emit path remains v1
// rather than fabricating causal coordinates from a host or timestamp.
func (s *DetectionSink) EmitAttributed(ctx context.Context, value detection.Detection, attribution fleetagent.DetectionAttribution) error {
	if err := value.Validate(); err != nil {
		return err
	}
	value, _, err := privacy.ScrubDetection(value, s.policy)
	if err != nil {
		return fmt.Errorf("redact attributed detection evidence: %w", err)
	}
	attribution.RedactionPolicyDigest = privacy.RedactionPolicyDigest(s.policy)
	if err := attribution.Validate(); err != nil {
		return fmt.Errorf("validate attributed detection: %w", err)
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode attributed detection for spool: %w", err)
	}
	digest := sha256.Sum256(payload)
	id := shared.ID("det_" + hex.EncodeToString(digest[:16]))
	spooled := fleetagent.DetectionSpoolPayload{Version: 2, Item: fleetagent.DetectionBatchItemV2{
		ID: id, Detection: value, AssetID: value.HostID, TelemetryRefs: attribution.TelemetryRefs,
		Rulepack: attribution.Rulepack, RedactionPolicyDigest: attribution.RedactionPolicyDigest,
	}, ObservedAt: value.Observed.UTC()}
	if err := spooled.Validate(); err != nil {
		return err
	}
	encoded, err := json.Marshal(spooled)
	if err != nil {
		return fmt.Errorf("encode attributed detection spool payload: %w", err)
	}
	return s.enqueue(ctx, value, encoded, "application/vnd.synapse.detection+json;version=2", 2)
}

func (s *DetectionSink) enqueue(ctx context.Context, value detection.Detection, payload []byte, contentType string, schemaVersion int) error {
	digest := sha256.Sum256(payload)
	id := shared.ID("det_" + hex.EncodeToString(digest[:16]))
	if schemaVersion == 2 {
		var spooled fleetagent.DetectionSpoolPayload
		if err := json.Unmarshal(payload, &spooled); err != nil {
			return fmt.Errorf("decode attributed detection identifier: %w", err)
		}
		id = spooled.Item.ID
	}
	item := ports.SpoolItem{Kind: ports.SpoolRecordDetection, Priority: fleetagent.PriorityP1,
		EventID: id, EventClass: value.Class, ContentType: contentType, Payload: payload,
		ObservedAt: value.Observed.UTC(), MustNotShed: true, SchemaVersion: schemaVersion}
	for {
		if _, err := s.spool.Enqueue(ctx, item); !errors.Is(err, ports.ErrTelemetrySpoolSaturated) {
			return err
		}
		if err := waitForSpoolCapacity(ctx); err != nil {
			return err
		}
	}
}

var _ ports.DetectionSink = (*DetectionSink)(nil)
