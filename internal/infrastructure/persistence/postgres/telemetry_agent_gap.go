package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func postgresAgentGapCompatibleExtension(current, next ports.TelemetryAgentGap) bool {
	if current.GapID != next.GapID || current.AgentID != next.AgentID || current.AssetID != next.AssetID ||
		current.StreamID != next.StreamID || current.Priority != next.Priority || current.Epoch != next.Epoch ||
		current.KnownSequence != next.KnownSequence || current.Reason != next.Reason || next.Count < current.Count {
		return false
	}
	// timestamptz keeps microseconds, so the stored projection is a truncation of the
	// signed report it came from. Compare at the resolution that actually became durable:
	// otherwise a genuine widening whose signed bounds carry sub-microsecond precision
	// reads as evidence shrinking, and honest loss evidence is rejected.
	if next.FromAt.Truncate(time.Microsecond).After(current.FromAt.Truncate(time.Microsecond)) ||
		next.ToAt.Truncate(time.Microsecond).Before(current.ToAt.Truncate(time.Microsecond)) {
		return false
	}
	if current.KnownSequence {
		return next.FromSequence <= current.FromSequence && next.ToSequence >= current.ToSequence
	}
	return next.FromSequence == 0 && next.ToSequence == 0
}

func scanAgentGapRow(row pgx.Row) (ports.TelemetryAgentGap, error) {
	var (
		gap                               ports.TelemetryAgentGap
		gapID, agentID, assetID, streamID string
		priority                          int
		epoch, count                      int64
		known                             bool
		fromSeq, toSeq                    *int64
		reason                            string
		fromAt, toAt, firstAt, updatedAt  time.Time
	)
	if err := row.Scan(&gapID, &agentID, &assetID, &streamID, &priority, &epoch, &known,
		&fromSeq, &toSeq, &count, &reason, &fromAt, &toAt, &firstAt, &updatedAt); err != nil {
		return ports.TelemetryAgentGap{}, err
	}
	gap = ports.TelemetryAgentGap{
		GapID: shared.ID(gapID), AgentID: shared.ID(agentID), AssetID: shared.ID(assetID), StreamID: shared.ID(streamID),
		Priority: fleetagent.DeliveryPriority(priority), Epoch: uint64(epoch), KnownSequence: known, Count: uint64(count),
		Reason: fleetagent.TelemetryGapReason(reason), FromAt: fromAt.UTC(), ToAt: toAt.UTC(),
		FirstReportedAt: firstAt.UTC(), UpdatedAt: updatedAt.UTC(),
	}
	if fromSeq != nil {
		gap.FromSequence = uint64(*fromSeq)
	}
	if toSeq != nil {
		gap.ToSequence = uint64(*toSeq)
	}
	return gap, nil
}

func (r *TelemetryTransportRepository) RecordAgentGap(ctx context.Context, gap ports.TelemetryAgentGap) error {
	if err := gap.Validate(); err != nil {
		return err
	}
	if err := requireTransportTenant(ctx); err != nil {
		return err
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		current, err := scanAgentGapRow(tx.QueryRow(ctx, `SELECT gap_id,agent_id,asset_id,stream_id,priority,epoch,known_sequence,
			from_sequence,to_sequence,count,reason,from_at,to_at,first_reported_at,updated_at
			FROM telemetry_agent_gaps WHERE tenant_id=$1 AND gap_id=$2 FOR UPDATE`, tenant.String(), gap.GapID.String()))
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			var fromSeq, toSeq any
			if gap.KnownSequence {
				fromSeq, toSeq = int64(gap.FromSequence), int64(gap.ToSequence)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO telemetry_agent_gaps
				(tenant_id,gap_id,agent_id,asset_id,stream_id,priority,epoch,known_sequence,from_sequence,to_sequence,count,reason,from_at,to_at,first_reported_at,updated_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
				tenant.String(), gap.GapID.String(), gap.AgentID.String(), gap.AssetID.String(), gap.StreamID.String(), int(gap.Priority),
				int64(gap.Epoch), gap.KnownSequence, fromSeq, toSeq, int64(gap.Count), string(gap.Reason),
				gap.FromAt.UTC(), gap.ToAt.UTC(), gap.FirstReportedAt.UTC(), gap.UpdatedAt.UTC()); err != nil {
				return fmt.Errorf("insert telemetry agent gap: %w", err)
			}
			return nil
		case err != nil:
			return fmt.Errorf("read telemetry agent gap collision: %w", err)
		}

		if !postgresAgentGapCompatibleExtension(current, gap) {
			return fmt.Errorf("%w: telemetry agent gap id is already committed to incompatible or larger evidence", shared.ErrConflict)
		}
		// Exact retry is intentionally a no-op except UpdatedAt: this keeps first_reported_at
		// stable while still exposing the latest successful receipt time.
		var fromSeq, toSeq any
		if gap.KnownSequence {
			fromSeq, toSeq = int64(gap.FromSequence), int64(gap.ToSequence)
		}
		updatedAt := gap.UpdatedAt.UTC()
		if updatedAt.Before(current.UpdatedAt) {
			updatedAt = current.UpdatedAt
		}
		if _, err := tx.Exec(ctx, `UPDATE telemetry_agent_gaps SET
			from_sequence=$1,to_sequence=$2,count=$3,from_at=$4,to_at=$5,updated_at=$6
			WHERE tenant_id=$7 AND gap_id=$8`,
			fromSeq, toSeq, int64(gap.Count), gap.FromAt.UTC(), gap.ToAt.UTC(), updatedAt,
			tenant.String(), gap.GapID.String()); err != nil {
			return fmt.Errorf("extend telemetry agent gap: %w", err)
		}
		return nil
	})
}

// AcceptAgentGapRevision appends the exact signed report and advances the mutable
// current projection in one tenant-scoped PostgreSQL transaction. It preserves
// nanosecond signed-time identity in dedicated integer columns because PostgreSQL
// timestamptz normalizes its queryable projection to microsecond precision.
func (r *TelemetryTransportRepository) AcceptAgentGapRevision(ctx context.Context, revision ports.TelemetryAgentGapRevision) error {
	_, err := r.acceptAgentGapRevisionWithAudit(ctx, revision, nil)
	return err
}

func (r *TelemetryTransportRepository) AcceptAgentGapRevisionWithAudit(
	ctx context.Context,
	revision ports.TelemetryAgentGapRevision,
	intent ports.FleetAuditIntent,
) (ports.FleetAuditIntent, error) {
	return r.acceptAgentGapRevisionWithAudit(ctx, revision, &intent)
}

func (r *TelemetryTransportRepository) acceptAgentGapRevisionWithAudit(
	ctx context.Context,
	revision ports.TelemetryAgentGapRevision,
	intent *ports.FleetAuditIntent,
) (ports.FleetAuditIntent, error) {
	if err := revision.Validate(); err != nil {
		return ports.FleetAuditIntent{}, err
	}
	if err := requireTransportTenant(ctx); err != nil {
		return ports.FleetAuditIntent{}, err
	}
	gap := revision.Projection()
	if err := gap.Validate(); err != nil {
		return ports.FleetAuditIntent{}, err
	}
	if intent != nil {
		normalized, _, err := validateFleetAuditIntent(*intent)
		if err != nil {
			return ports.FleetAuditIntent{}, err
		}
		intent = &normalized
	}
	var committed ports.FleetAuditIntent
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		var lockResult int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM pg_advisory_xact_lock(hashtextextended($1,0))`,
			tenant.String()+":"+revision.GapID.String()).Scan(&lockResult); err != nil {
			return fmt.Errorf("lock telemetry agent gap revision sequence: %w", err)
		}

		accepted := false
		var existingGapID string
		err := tx.QueryRow(ctx, `SELECT gap_id FROM telemetry_agent_gap_revisions
			WHERE tenant_id=$1 AND signed_content_digest=$2`, tenant.String(), revision.SignedContentDigest).Scan(&existingGapID)
		switch {
		case err == nil:
			if shared.ID(existingGapID) != revision.GapID {
				return fmt.Errorf("%w: telemetry agent gap signed content is bound to another gap", shared.ErrConflict)
			}
			accepted = true
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("read telemetry agent gap revision retry: %w", err)
		}

		if !accepted {
			current, err := scanAgentGapRow(tx.QueryRow(ctx, `SELECT gap_id,agent_id,asset_id,stream_id,priority,epoch,known_sequence,
				from_sequence,to_sequence,count,reason,from_at,to_at,first_reported_at,updated_at
				FROM telemetry_agent_gaps WHERE tenant_id=$1 AND gap_id=$2 FOR UPDATE`, tenant.String(), gap.GapID.String()))
			switch {
			case errors.Is(err, pgx.ErrNoRows):
			case err != nil:
				return fmt.Errorf("read telemetry agent gap collision: %w", err)
			default:
				if !postgresAgentGapCompatibleExtension(current, gap) {
					return fmt.Errorf("%w: telemetry agent gap id is already committed to incompatible or larger evidence", shared.ErrConflict)
				}
				gap.FirstReportedAt = current.FirstReportedAt
				if gap.UpdatedAt.Before(current.UpdatedAt) {
					gap.UpdatedAt = current.UpdatedAt
				}
			}

			if err := tx.QueryRow(ctx, `SELECT COALESCE(max(revision),0)+1
				FROM telemetry_agent_gap_revisions WHERE tenant_id=$1 AND gap_id=$2`,
				tenant.String(), revision.GapID.String()).Scan(&revision.Revision); err != nil {
				return fmt.Errorf("allocate telemetry agent gap revision: %w", err)
			}
			var fromSeq, toSeq any
			if revision.KnownSequence {
				fromSeq, toSeq = int64(revision.FromSequence), int64(revision.ToSequence)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO telemetry_agent_gap_revisions
				(tenant_id,signed_content_digest,gap_id,revision,authenticated_agent_id,agent_id,host_id,agent_session_id,
				 asset_id,stream_id,priority,epoch,known_sequence,from_sequence,to_sequence,count,reason,
				 from_at,to_at,from_at_unix_nano,to_at_unix_nano,protocol_version,key_id,signature,received_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)`,
				tenant.String(), revision.SignedContentDigest, revision.GapID.String(), int64(revision.Revision), revision.AuthenticatedAgentID.String(),
				revision.AgentID.String(), revision.HostID.String(), string(revision.AgentSessionID), revision.AssetID.String(),
				revision.StreamID.String(), int(revision.Priority), int64(revision.Epoch), revision.KnownSequence,
				fromSeq, toSeq, int64(revision.Count), string(revision.Reason), revision.FromAt.UTC(), revision.ToAt.UTC(),
				revision.FromAt.UTC().UnixNano(), revision.ToAt.UTC().UnixNano(), revision.ProtocolVersion,
				revision.KeyID, revision.Signature, revision.ReceivedAt.UTC()); err != nil {
				return fmt.Errorf("insert telemetry agent gap revision: %w", err)
			}

			if current.GapID.IsZero() {
				if _, err := tx.Exec(ctx, `INSERT INTO telemetry_agent_gaps
					(tenant_id,gap_id,agent_id,asset_id,stream_id,priority,epoch,known_sequence,from_sequence,to_sequence,count,reason,from_at,to_at,first_reported_at,updated_at)
					VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
					tenant.String(), gap.GapID.String(), gap.AgentID.String(), gap.AssetID.String(), gap.StreamID.String(), int(gap.Priority),
					int64(gap.Epoch), gap.KnownSequence, fromSeq, toSeq, int64(gap.Count), string(gap.Reason),
					gap.FromAt.UTC(), gap.ToAt.UTC(), gap.FirstReportedAt.UTC(), gap.UpdatedAt.UTC()); err != nil {
					return fmt.Errorf("insert telemetry agent gap projection: %w", err)
				}
			} else if _, err := tx.Exec(ctx, `UPDATE telemetry_agent_gaps SET
				from_sequence=$1,to_sequence=$2,count=$3,from_at=$4,to_at=$5,updated_at=$6
				WHERE tenant_id=$7 AND gap_id=$8`,
				fromSeq, toSeq, int64(gap.Count), gap.FromAt.UTC(), gap.ToAt.UTC(), gap.UpdatedAt.UTC(),
				tenant.String(), gap.GapID.String()); err != nil {
				return fmt.Errorf("extend telemetry agent gap projection: %w", err)
			}
		}

		if intent == nil {
			return nil
		}
		candidate := *intent
		var existingAt time.Time
		err = tx.QueryRow(ctx, `SELECT occurred_at FROM fleet_audit_intents
			WHERE tenant_id=$1 AND intent_id=$2`, tenant.String(), candidate.ID).Scan(&existingAt)
		if err == nil {
			candidate.Entry.At = existingAt.UTC()
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("read telemetry gap audit intention: %w", err)
		}
		transactionCtx := context.WithValue(ctx, tenantTransactionKey{}, tenantTransaction{
			tenantID: tenant.String(),
			tx:       tx,
		})
		stored, err := r.insertFleetAudit(transactionCtx, candidate)
		if err != nil {
			return err
		}
		committed = stored
		return nil
	})
	return committed, err
}

// AgentGapRevisions returns immutable signed reports in revision order. It
// reconstructs signed timestamps from their exact Unix-nanosecond identity.
func (r *TelemetryTransportRepository) AgentGapRevisions(ctx context.Context, gapID shared.ID) ([]ports.TelemetryAgentGapRevision, error) {
	if err := requireTransportTenant(ctx); err != nil {
		return nil, err
	}
	if gapID.IsZero() {
		return nil, shared.ErrValidation
	}
	var revisions []ports.TelemetryAgentGapRevision
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		rows, err := tx.Query(ctx, `SELECT revision,protocol_version,gap_id,authenticated_agent_id,agent_id,host_id,agent_session_id,
			asset_id,stream_id,priority,epoch,known_sequence,from_sequence,to_sequence,count,reason,
			from_at_unix_nano,to_at_unix_nano,key_id,signature,signed_content_digest,received_at
			FROM telemetry_agent_gap_revisions WHERE tenant_id=$1 AND gap_id=$2 ORDER BY revision`,
			tenant.String(), gapID.String())
		if err != nil {
			return fmt.Errorf("query telemetry agent gap revisions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var revision ports.TelemetryAgentGapRevision
			var revisionNumber, epoch, count, fromNanos, toNanos int64
			var priority int
			var gap, authenticatedAgent, agent, host, session, asset, stream, reason string
			var fromSeq, toSeq *int64
			if err := rows.Scan(&revisionNumber, &revision.ProtocolVersion, &gap, &authenticatedAgent, &agent, &host, &session,
				&asset, &stream, &priority, &epoch, &revision.KnownSequence, &fromSeq, &toSeq, &count, &reason,
				&fromNanos, &toNanos, &revision.KeyID, &revision.Signature, &revision.SignedContentDigest, &revision.ReceivedAt); err != nil {
				return fmt.Errorf("scan telemetry agent gap revision: %w", err)
			}
			revision.Revision = uint64(revisionNumber)
			revision.GapID = shared.ID(gap)
			revision.AuthenticatedAgentID = shared.ID(authenticatedAgent)
			revision.AgentID = shared.ID(agent)
			revision.HostID = shared.ID(host)
			revision.AgentSessionID = fleetagent.SessionID(session)
			revision.AssetID = shared.ID(asset)
			revision.StreamID = shared.ID(stream)
			revision.Priority = fleetagent.DeliveryPriority(priority)
			revision.Epoch = uint64(epoch)
			revision.Count = uint64(count)
			revision.Reason = fleetagent.TelemetryGapReason(reason)
			revision.FromAt = time.Unix(0, fromNanos).UTC()
			revision.ToAt = time.Unix(0, toNanos).UTC()
			revision.ReceivedAt = revision.ReceivedAt.UTC()
			if fromSeq != nil {
				revision.FromSequence = uint64(*fromSeq)
			}
			if toSeq != nil {
				revision.ToSequence = uint64(*toSeq)
			}
			if err := revision.Validate(); err != nil {
				return fmt.Errorf("validate telemetry agent gap revision: %w", err)
			}
			revisions = append(revisions, revision)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate telemetry agent gap revisions: %w", err)
		}
		return nil
	})
	return revisions, err
}
