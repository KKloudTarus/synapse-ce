package telemetryingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type SensorStateIngestResult struct {
	ReportID shared.ID
}

// IngestSensorState accepts one signed P0 health record. The report's asset is
// checked against the server-owned telemetry binding before immutable history is
// appended, so an agent cannot attribute its state to another asset.
func (s *Service) IngestSensorState(ctx context.Context, authAgentID shared.ID, report fleetagent.SensorStateReport) (SensorStateIngestResult, error) {
	now := s.clock.Now().UTC().Truncate(time.Microsecond)
	if s.sensorStates == nil {
		return SensorStateIngestResult{}, fmt.Errorf("%w: sensor-state ingest is not enabled", shared.ErrNotFound)
	}
	if err := report.Validate(); err != nil {
		if auditErr := s.rejectSensorState(ctx, authAgentID, report, "invalid_report", now); auditErr != nil {
			return SensorStateIngestResult{}, auditErr
		}
		return SensorStateIngestResult{}, err
	}
	if authAgentID.IsZero() || report.AgentID != authAgentID {
		if auditErr := s.rejectSensorState(ctx, authAgentID, report, "identity_mismatch", now); auditErr != nil {
			return SensorStateIngestResult{}, auditErr
		}
		return SensorStateIngestResult{}, fmt.Errorf("%w: sensor-state report agent %q is not authenticated agent %q", shared.ErrForbidden, report.AgentID, authAgentID)
	}
	if report.HostID != authAgentID {
		if auditErr := s.rejectSensorState(ctx, authAgentID, report, "host_mismatch", now); auditErr != nil {
			return SensorStateIngestResult{}, auditErr
		}
		return SensorStateIngestResult{}, fmt.Errorf("%w: sensor-state report host %q is not authenticated agent host %q", shared.ErrForbidden, report.HostID, authAgentID)
	}
	if wantSession := fleetagent.CanonicalSessionID(authAgentID); report.AgentSessionID != wantSession {
		if auditErr := s.rejectSensorState(ctx, authAgentID, report, "session_mismatch", now); auditErr != nil {
			return SensorStateIngestResult{}, auditErr
		}
		return SensorStateIngestResult{}, fmt.Errorf("%w: sensor-state report session is not the authenticated enrollment session", shared.ErrForbidden)
	}
	assetID, err := s.bindings.ResolveTelemetryAsset(ctx, authAgentID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			err = fmt.Errorf("%w: telemetry asset binding is not established", shared.ErrForbidden)
		}
		if auditErr := s.rejectSensorState(ctx, authAgentID, report, "asset_binding_missing", now); auditErr != nil {
			return SensorStateIngestResult{}, auditErr
		}
		return SensorStateIngestResult{}, err
	}
	if assetID.IsZero() || report.AssetID != assetID {
		if auditErr := s.rejectSensorState(ctx, authAgentID, report, "asset_mismatch", now); auditErr != nil {
			return SensorStateIngestResult{}, auditErr
		}
		return SensorStateIngestResult{}, fmt.Errorf("%w: sensor-state report asset does not match server-authoritative host binding", shared.ErrForbidden)
	}
	key, err := s.keys.ResolveSigningKey(ctx, report.AgentID, report.KeyID)
	if err != nil {
		if auditErr := s.rejectSensorState(ctx, authAgentID, report, "key_unresolved", now); auditErr != nil {
			return SensorStateIngestResult{}, auditErr
		}
		return SensorStateIngestResult{}, fmt.Errorf("%w: resolve sensor-state signing key %q: %v", shared.ErrForbidden, report.KeyID, err)
	}
	if err := fleetagent.VerifySensorStateWithKey(key, now, report); err != nil {
		if auditErr := s.rejectSensorState(ctx, authAgentID, report, "signature_invalid", now); auditErr != nil {
			return SensorStateIngestResult{}, auditErr
		}
		return SensorStateIngestResult{}, err
	}

	signedContent := sha256.Sum256(fleetagent.SensorStateMessage(report))
	observation := sensorstate.Observation{
		ReportID: report.ReportID, AgentID: authAgentID, HostID: report.HostID, AssetID: assetID,
		Kind: sensorstate.RecordKind(report.Kind), ObservedAt: report.ObservedAt.UTC().Truncate(time.Microsecond), RecordedAt: now,
		SchemaVersion: report.SchemaVersion, PayloadDigest: report.PayloadDigest,
		SignedContentDigest: hex.EncodeToString(signedContent[:]),
		States:              append([]detection.ClassCoverage(nil), report.States...),
	}
	intentID := "fleet.sensor_state.ingest:" + report.ReportID.String()
	intent := ports.FleetAuditIntent{
		ID: intentID,
		Entry: ports.AuditEntry{
			Actor: authAgentID.String(), Action: "fleet.sensor_state.ingest", Target: report.ReportID.String(), At: now,
			Metadata: map[string]string{
				"idempotency_key": intentID,
				"asset_id":        assetID.String(), "kind": report.Kind,
				"schema_version": fmt.Sprintf("%d", report.SchemaVersion),
			},
		},
	}
	intent, err = s.sensorStates.AppendSensorStateWithAudit(ctx, observation, intent)
	if err != nil {
		if errors.Is(err, shared.ErrConflict) {
			if auditErr := s.rejectSensorState(ctx, authAgentID, report, "report_id_equivocation", now); auditErr != nil {
				return SensorStateIngestResult{}, auditErr
			}
		}
		return SensorStateIngestResult{}, fmt.Errorf("persist sensor-state observation: %w", err)
	}
	if err := s.reconcileCoverage(ctx, authAgentID, assetID, report.HostID, report.ObservedAt, report.ObservedAt); err != nil {
		return SensorStateIngestResult{}, fmt.Errorf("reconcile sensor-state coverage: %w", err)
	}
	if err := s.audit.RecordOnce(ctx, intent.Entry); err != nil {
		return SensorStateIngestResult{}, fmt.Errorf("audit sensor-state admission: %w", err)
	}
	if err := s.sensorStates.AcknowledgeFleetAudit(ctx, intent.ID); err != nil {
		return SensorStateIngestResult{}, fmt.Errorf("acknowledge sensor-state admission audit: %w", err)
	}
	return SensorStateIngestResult{ReportID: report.ReportID}, nil
}

func (s *Service) rejectSensorState(ctx context.Context, actor shared.ID, report fleetagent.SensorStateReport, reason string, at time.Time) error {
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor.String(), Action: "fleet.sensor_state.reject", Target: report.ReportID.String(), At: at,
		Metadata: map[string]string{"manifest_agent_id": report.AgentID.String(), "asset_id": report.AssetID.String(), "reason": reason},
	}); err != nil {
		return fmt.Errorf("%w: audit sensor-state rejection: %v", shared.ErrSaturated, err)
	}
	return nil
}
