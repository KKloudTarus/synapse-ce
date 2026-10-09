package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/jackc/pgx/v5"
)

func (s *NotificationSource) pollCaptured(ctx context.Context, tx pgx.Tx, tenant shared.ID, kind string, now time.Time, limit int) (int, error) {
	rows, err := tx.Query(ctx, `SELECT source_id,event_type,engagement_id,severity,occurred_at,data,subject_kind,subject_id,context,capture_version FROM notification_source_records WHERE tenant_id=$1 AND source_kind=$2 AND processed_at IS NULL ORDER BY occurred_at,source_id LIMIT $3 FOR UPDATE SKIP LOCKED`, tenant, kind, limit)
	if err != nil {
		return 0, err
	}
	type capturedEvent struct {
		event   notification.Event
		version int
	}
	var events []capturedEvent
	for rows.Next() {
		e := notification.Event{TenantID: tenant, SourceKind: kind, SchemaVersion: 1}
		var version int
		if err := rows.Scan(&e.SourceID, &e.Type, &e.EngagementID, &e.Severity, &e.OccurredAt, &e.Data, &e.SubjectKind, &e.SubjectID, &e.Context, &version); err != nil {
			rows.Close()
			return 0, err
		}
		e.ID = stableID(tenant.String(), kind, e.SourceID)
		events = append(events, capturedEvent{event: e, version: version})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	for _, captured := range events {
		e := captured.event
		// pgx uses a savepoint for a nested transaction. A bad event may have
		// reached SQL before failing, so roll back that record's work alone.
		itemTx, err := tx.Begin(ctx)
		if err != nil {
			return 0, err
		}
		err = s.publishCaptured(ctx, itemTx, tenant, kind, e, captured.version)
		if err != nil {
			if rollbackErr := itemTx.Rollback(ctx); rollbackErr != nil {
				return 0, rollbackErr
			}
			// Identity-only records are never quarantined. A missing source or a
			// miswired/invalid projector must remain retryable until a capable
			// worker can hydrate and project the record.
			if captured.version >= 2 || !errors.Is(err, shared.ErrValidation) {
				return 0, err
			}
			reason := "invalid_event"
			if len(e.Data) > 16384 {
				reason = "event_data_too_large"
			}
			if _, err := tx.Exec(ctx, `UPDATE notification_source_records SET processed_at=$4,failed_reason=$5 WHERE tenant_id=$1 AND source_kind=$2 AND source_id=$3`, tenant, kind, e.SourceID, now, reason); err != nil {
				return 0, err
			}
			continue
		}
		if err := itemTx.Commit(ctx); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `UPDATE notification_source_records SET processed_at=$4 WHERE tenant_id=$1 AND source_kind=$2 AND source_id=$3`, tenant, kind, e.SourceID, now); err != nil {
			return 0, err
		}
	}
	return len(events), nil
}

// publishCaptured reads the record's source facts and publishes it. The event builder fills the
// variables from them, and composes the data from them when the record carries only its identity.
func (s *NotificationSource) publishCaptured(ctx context.Context, tx pgx.Tx, tenant shared.ID, kind string, e notification.Event, captureVersion int) error {
	if captureVersion >= 2 && s.repo.projector == nil {
		return fmt.Errorf("identity notification source requires an event projector")
	}
	facts, err := capturedFacts(ctx, tx, tenant, kind, e.SourceID)
	if err != nil {
		return err
	}
	if captureVersion >= 2 && len(facts) == 0 {
		return fmt.Errorf("identity notification source facts are unavailable")
	}
	if kind == "scan_job" {
		if e.Context, err = withScanFacts(e.Context, facts); err != nil {
			return err
		}
		present, err := scanSummaryPresent(facts["notification_snapshot"])
		if err != nil {
			return err
		}
		if present {
			if s.repo.projector == nil {
				return fmt.Errorf("scan notification snapshot requires an event projector")
			}
			// The terminal snapshot, rather than the trigger's legacy data,
			// defines the scan.completed v2 envelope. An empty object lets the
			// projector compose the matching aggregate data from the snapshot facts.
			e.SchemaVersion = 2
			e.Data = []byte("{}")
		}
	} else if e.Context, err = withFacts(e.Context, facts); err != nil {
		return err
	}
	if captureVersion >= 2 {
		// The trigger refuses identity-only publication unless the capability is
		// transaction-local. Set it only after source hydration succeeded; failures
		// above remain retryable and cannot consume the record.
		if _, err := tx.Exec(ctx, `SELECT set_config('synapse.notification_source_capability','identity-v1',true)`); err != nil {
			return err
		}
	}
	_, err = s.repo.publishTx(ctx, tx, e, "")
	return err
}
