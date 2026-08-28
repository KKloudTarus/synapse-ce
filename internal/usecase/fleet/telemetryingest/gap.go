package telemetryingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type GapIngestResult struct {
	GapID shared.ID
}

// IngestGap verifies one durable A2 spool-gap report against the same server-authoritative
// identity and purpose-bound signing-key trust boundary as telemetry batches. Persistence is
// idempotent on GapID and permits only monotonic coalescing extensions.
func (s *Service) IngestGap(ctx context.Context, authAgentID shared.ID, report fleetagent.TelemetryGapReport) (GapIngestResult, error) {
	now := s.clock.Now().UTC()
	if err := report.Validate(); err != nil {
		if auditErr := s.rejectGap(ctx, authAgentID, report, "invalid_report", now); auditErr != nil {
			return GapIngestResult{}, auditErr
		}
		return GapIngestResult{}, err
	}
	if authAgentID.IsZero() || report.AgentID != authAgentID {
		if auditErr := s.rejectGap(ctx, authAgentID, report, "identity_mismatch", now); auditErr != nil {
			return GapIngestResult{}, auditErr
		}
		return GapIngestResult{}, fmt.Errorf("%w: gap report agent %q is not authenticated agent %q", shared.ErrForbidden, report.AgentID, authAgentID)
	}
	if report.HostID != authAgentID {
		if auditErr := s.rejectGap(ctx, authAgentID, report, "host_mismatch", now); auditErr != nil {
			return GapIngestResult{}, auditErr
		}
		return GapIngestResult{}, fmt.Errorf("%w: gap report host %q is not authenticated agent host %q", shared.ErrForbidden, report.HostID, authAgentID)
	}
	wantSession := fleetagent.CanonicalSessionID(authAgentID)
	if report.AgentSessionID != wantSession {
		if auditErr := s.rejectGap(ctx, authAgentID, report, "session_mismatch", now); auditErr != nil {
			return GapIngestResult{}, auditErr
		}
		return GapIngestResult{}, fmt.Errorf("%w: gap report session is not the authenticated enrollment session", shared.ErrForbidden)
	}
	wantStream, err := fleetagent.TelemetryDeliveryStreamID(authAgentID, wantSession, report.Priority)
	if err != nil {
		return GapIngestResult{}, err
	}
	if report.StreamID != wantStream {
		if auditErr := s.rejectGap(ctx, authAgentID, report, "stream_mismatch", now); auditErr != nil {
			return GapIngestResult{}, auditErr
		}
		return GapIngestResult{}, fmt.Errorf("%w: gap report stream is not server-derived for authenticated lane", shared.ErrForbidden)
	}
	assetID, err := s.bindings.ResolveTelemetryAsset(ctx, authAgentID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			err = fmt.Errorf("%w: telemetry asset binding is not established", shared.ErrForbidden)
		}
		if auditErr := s.rejectGap(ctx, authAgentID, report, "asset_binding_missing", now); auditErr != nil {
			return GapIngestResult{}, auditErr
		}
		return GapIngestResult{}, err
	}
	if assetID.IsZero() || report.AssetID != assetID {
		if auditErr := s.rejectGap(ctx, authAgentID, report, "asset_mismatch", now); auditErr != nil {
			return GapIngestResult{}, auditErr
		}
		return GapIngestResult{}, fmt.Errorf("%w: gap report asset does not match server-authoritative host binding", shared.ErrForbidden)
	}
	key, err := s.keys.ResolveSigningKey(ctx, report.AgentID, report.KeyID)
	if err != nil {
		if auditErr := s.rejectGap(ctx, authAgentID, report, "key_unresolved", now); auditErr != nil {
			return GapIngestResult{}, auditErr
		}
		return GapIngestResult{}, fmt.Errorf("%w: resolve telemetry gap signing key %q: %v", shared.ErrForbidden, report.KeyID, err)
	}
	if err := fleetagent.VerifyTelemetryGapWithKey(key, now, report); err != nil {
		if auditErr := s.rejectGap(ctx, authAgentID, report, "signature_invalid", now); auditErr != nil {
			return GapIngestResult{}, auditErr
		}
		return GapIngestResult{}, err
	}

	signedContent := sha256.Sum256(fleetagent.TelemetryGapMessage(report))
	reportDigest := hex.EncodeToString(signedContent[:])
	revision := ports.TelemetryAgentGapRevision{
		ProtocolVersion: report.ProtocolVersion, GapID: report.GapID,
		AuthenticatedAgentID: authAgentID, AgentID: report.AgentID, HostID: report.HostID,
		AgentSessionID: report.AgentSessionID, AssetID: assetID, StreamID: wantStream,
		Priority: report.Priority, Epoch: report.Epoch, KnownSequence: report.KnownSequence,
		FromSequence: report.FromSequence, ToSequence: report.ToSequence, Count: report.Count,
		Reason: report.Reason, FromAt: report.FromAt.UTC(), ToAt: report.ToAt.UTC(),
		KeyID: report.KeyID, Signature: report.Signature,
		SignedContentDigest: reportDigest, ReceivedAt: now,
	}
	intentID := "fleet.telemetry.gap_ingest:" + reportDigest
	intent := ports.FleetAuditIntent{
		ID: intentID,
		Entry: ports.AuditEntry{
			Actor: authAgentID.String(), Action: "fleet.telemetry.gap_ingest", Target: report.GapID.String(), At: now,
			Metadata: map[string]string{
				"idempotency_key": intentID, "report_digest": reportDigest,
				"asset_id": assetID.String(), "stream_id": wantStream.String(),
				"priority": report.Priority.String(), "epoch": fmt.Sprintf("%d", report.Epoch),
				"reason": string(report.Reason), "count": fmt.Sprintf("%d", report.Count),
				"known_sequence": fmt.Sprintf("%t", report.KnownSequence),
			},
		},
	}
	intent, err = s.transport.AcceptAgentGapRevisionWithAudit(ctx, revision, intent)
	if err != nil {
		if errors.Is(err, shared.ErrConflict) {
			if auditErr := s.rejectGap(ctx, authAgentID, report, "gap_id_equivocation", now); auditErr != nil {
				return GapIngestResult{}, auditErr
			}
		}
		return GapIngestResult{}, fmt.Errorf("persist telemetry agent gap: %w", err)
	}
	if err := s.reconcileCoverage(ctx, authAgentID, assetID, report.HostID, report.FromAt, report.ToAt); err != nil {
		return GapIngestResult{}, fmt.Errorf("reconcile telemetry-gap coverage: %w", err)
	}
	if err := s.audit.RecordOnce(ctx, intent.Entry); err != nil {
		return GapIngestResult{}, fmt.Errorf("audit telemetry gap admission: %w", err)
	}
	if err := s.transport.AcknowledgeFleetAudit(ctx, intent.ID); err != nil {
		return GapIngestResult{}, fmt.Errorf("acknowledge telemetry gap admission audit: %w", err)
	}
	return GapIngestResult{GapID: report.GapID}, nil
}

func (s *Service) rejectGap(ctx context.Context, actor shared.ID, report fleetagent.TelemetryGapReport, reason string, at time.Time) error {
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor.String(), Action: "fleet.telemetry.gap_reject", Target: report.GapID.String(), At: at,
		Metadata: map[string]string{
			"manifest_agent_id": report.AgentID.String(), "asset_id": report.AssetID.String(),
			"stream_id": report.StreamID.String(), "reason": reason,
		},
	}); err != nil {
		return fmt.Errorf("%w: audit telemetry-gap rejection: %v", shared.ErrSaturated, err)
	}
	return nil
}
