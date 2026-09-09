package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/correlation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CorrelationStateRepository struct{ pool *pgxpool.Pool }

var _ ports.CorrelationStateStore = (*CorrelationStateRepository)(nil)

func NewCorrelationStateRepository(pool *pgxpool.Pool) *CorrelationStateRepository {
	return &CorrelationStateRepository{pool: pool}
}

func (r *CorrelationStateRepository) LoadCorrelationState(ctx context.Context, engagementID shared.ID, ids []shared.ID, activeLimit int) (correlation.State, error) {
	tenant, err := requireCorrelationStateTenant(ctx, engagementID)
	if err != nil {
		return correlation.State{}, err
	}
	if activeLimit <= 0 {
		return correlation.State{}, fmt.Errorf("%w: invalid correlation active-session limit", shared.ErrValidation)
	}
	out := correlation.State{KnownSignalIDs: map[shared.ID]struct{}{}}
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		var max, water, completedAt, snapshotAt, retention, sourceAt, stagedAt *time.Time
		var phase, completedID, snapshotID, sourceID, stagedID, digest string
		e := tx.QueryRow(ctx, `SELECT revision,max_observed_at,watermark,phase,completed_recorded_at,completed_id,snapshot_recorded_at,snapshot_id,retention_as_of,source_cursor_recorded_at,source_cursor_id,staged_cursor_occurred_at,staged_cursor_id,policy_digest FROM correlation_checkpoints WHERE tenant_id=$1 AND engagement_id=$2`, tenant.String(), engagementID.String()).Scan(&out.Checkpoint.Revision, &max, &water, &phase, &completedAt, &completedID, &snapshotAt, &snapshotID, &retention, &sourceAt, &sourceID, &stagedAt, &stagedID, &digest)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		out.Checkpoint.Phase = correlation.Phase(phase)
		out.Checkpoint.Completed = sourcePosition(completedAt, completedID)
		out.Checkpoint.Snapshot = sourcePosition(snapshotAt, snapshotID)
		out.Checkpoint.RetentionAsOf = timeValue(retention)
		out.Checkpoint.SourceCursor = sourcePosition(sourceAt, sourceID)
		out.Checkpoint.StagedCursor = signalPosition(stagedAt, stagedID)
		out.Checkpoint.PolicyDigest = digest
		out.Checkpoint.MaxObservedAt = timeValue(max)
		out.Checkpoint.Watermark = timeValue(water)
		if len(ids) > 0 {
			values := make([]string, len(ids))
			for i, id := range ids {
				values[i] = id.String()
			}
			rows, e := tx.Query(ctx, `SELECT signal_id FROM correlation_assignments WHERE tenant_id=$1 AND engagement_id=$2 AND signal_id=ANY($3::text[])`, tenant.String(), engagementID.String(), values)
			if e != nil {
				return e
			}
			defer rows.Close()
			for rows.Next() {
				var id string
				if e = rows.Scan(&id); e != nil {
					return e
				}
				out.KnownSignalIDs[shared.ID(id)] = struct{}{}
			}
			if e = rows.Err(); e != nil {
				return e
			}
		}
		rows, e := tx.Query(ctx, `SELECT asset_id,entity_id,incident_id,min_occurred_at,max_occurred_at,reflected_count,max_severity FROM correlation_active_sessions WHERE tenant_id=$1 AND engagement_id=$2 ORDER BY asset_id COLLATE "C",entity_id COLLATE "C",incident_id COLLATE "C" LIMIT $3`, tenant.String(), engagementID.String(), activeLimit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var s correlation.ActiveSession
			var asset, entity, id, severity string
			if e = rows.Scan(&asset, &entity, &id, &s.MinOccurredAt, &s.MaxOccurredAt, &s.ReflectedCount, &severity); e != nil {
				return e
			}
			s.AssetID, s.EntityID, s.IncidentID, s.MaxSeverity = shared.ID(asset), shared.ID(entity), shared.ID(id), shared.Severity(severity)
			out.ActiveSessions = append(out.ActiveSessions, s)
		}
		if e = rows.Err(); e != nil {
			return e
		}
		if len(out.ActiveSessions) > activeLimit {
			return fmt.Errorf("%w: correlation active-session limit exceeded", shared.ErrSaturated)
		}
		return nil
	})
	if err != nil {
		return correlation.State{}, err
	}
	if err = out.Validate(); err != nil {
		return correlation.State{}, err
	}
	return out, nil
}

func (r *CorrelationStateRepository) BeginCorrelationSnapshot(ctx context.Context, engagementID shared.ID, expected uint64, upper correlation.SourcePosition, asOf time.Time, digest string) (correlation.Checkpoint, error) {
	if upper.RecordedAt.IsZero() || upper.ID.IsZero() || asOf.IsZero() || digest == "" {
		return correlation.Checkpoint{}, fmt.Errorf("%w: invalid correlation snapshot", shared.ErrValidation)
	}
	tenant, err := requireCorrelationStateTenant(ctx, engagementID)
	if err != nil {
		return correlation.Checkpoint{}, err
	}
	next := correlation.Checkpoint{}
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO correlation_checkpoints(tenant_id,engagement_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, tenant.String(), engagementID.String()); err != nil {
			return err
		}
		var revision uint64
		var phase, completedID string
		var max, watermark, completedAt *time.Time
		if err := tx.QueryRow(ctx, `SELECT revision,phase,max_observed_at,watermark,completed_recorded_at,completed_id FROM correlation_checkpoints WHERE tenant_id=$1 AND engagement_id=$2 FOR UPDATE`, tenant.String(), engagementID.String()).Scan(&revision, &phase, &max, &watermark, &completedAt, &completedID); err != nil {
			return err
		}
		if revision != expected || phase != "" {
			return fmt.Errorf("%w: correlation snapshot changed", shared.ErrConflict)
		}
		next = correlation.Checkpoint{Revision: expected + 1, MaxObservedAt: timeValue(max), Watermark: timeValue(watermark), Completed: sourcePosition(completedAt, completedID), Phase: correlation.PhaseSource, Snapshot: upper, RetentionAsOf: asOf.UTC(), PolicyDigest: digest}
		return updateCheckpoint(ctx, tx, tenant, engagementID, expected, next)
	})
	return next, err
}
func (r *CorrelationStateRepository) StageCorrelationSignals(ctx context.Context, engagementID shared.ID, expected uint64, next correlation.Checkpoint, signals []correlation.Signal) error {
	tenant, err := requireCorrelationStateTenant(ctx, engagementID)
	if err != nil {
		return err
	}
	for _, signal := range signals {
		if err := signal.Validate(); err != nil {
			return err
		}
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		current, err := lockCorrelationCheckpoint(ctx, tx, tenant, engagementID)
		if err != nil {
			return err
		}
		if current == next { // An exact retry only verifies that its immutable staged payload agrees.
			return validateStagedSignalsTx(ctx, tx, tenant, engagementID, next.Snapshot, signals, true)
		}
		if current.Revision != expected || current.Phase != correlation.PhaseSource {
			return fmt.Errorf("%w: stale correlation source checkpoint", shared.ErrConflict)
		}
		if err := validateStageCheckpoint(current, expected, next); err != nil {
			return err
		}
		if err := validateStagedSignalsTx(ctx, tx, tenant, engagementID, next.Snapshot, signals, false); err != nil {
			return err
		}
		for _, signal := range signals {
			var timeline []byte
			if signal.Timeline != nil {
				timeline, err = json.Marshal(signal.Timeline)
				if err != nil {
					return fmt.Errorf("marshal staged timeline: %w", err)
				}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO correlation_staged_signals(tenant_id,engagement_id,snapshot_recorded_at,snapshot_id,signal_id,occurred_at,asset_id,entity_id,severity,rule_id,title,timeline) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT DO NOTHING`, tenant.String(), engagementID.String(), next.Snapshot.RecordedAt.UTC(), next.Snapshot.ID.String(), signal.ID.String(), signal.OccurredAt.UTC(), signal.AssetID.String(), signal.EntityID.String(), string(signal.Severity), signal.RuleID, signal.Title, timeline); err != nil {
				return fmt.Errorf("insert staged correlation signal: %w", err)
			}
		}
		return updateCheckpoint(ctx, tx, tenant, engagementID, expected, next)
	})
}
func (r *CorrelationStateRepository) ListStagedCorrelationSignals(ctx context.Context, engagementID shared.ID, snapshot correlation.SourcePosition, after correlation.SignalPosition, limit int) ([]correlation.Signal, bool, error) {
	if limit <= 0 {
		return nil, false, fmt.Errorf("%w: invalid correlation page limit", shared.ErrValidation)
	}
	tenant, err := requireCorrelationStateTenant(ctx, engagementID)
	if err != nil {
		return nil, false, err
	}
	var out []correlation.Signal
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT signal_id,occurred_at,asset_id,entity_id,severity,rule_id,title,timeline FROM correlation_staged_signals WHERE tenant_id=$1 AND engagement_id=$2 AND snapshot_recorded_at=$3 AND snapshot_id=$4 AND ($5::timestamptz IS NULL OR (occurred_at,signal_id)>($5,$6)) ORDER BY occurred_at,signal_id LIMIT $7`, tenant.String(), engagementID.String(), snapshot.RecordedAt.UTC(), snapshot.ID.String(), nullableCorrelationTime(after.OccurredAt), after.ID.String(), limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s correlation.Signal
			var id, asset, entity, severity string
			var timeline []byte
			if err := rows.Scan(&id, &s.OccurredAt, &asset, &entity, &severity, &s.RuleID, &s.Title, &timeline); err != nil {
				return err
			}
			s.ID, s.AssetID, s.EntityID, s.Severity = shared.ID(id), shared.ID(asset), shared.ID(entity), shared.Severity(severity)
			if len(timeline) > 0 {
				var ref incident.TimelineRef
				if err := json.Unmarshal(timeline, &ref); err != nil {
					return err
				}
				s.Timeline = &ref
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, false, err
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}
func (r *CorrelationStateRepository) CommitCorrelationConsume(ctx context.Context, engagementID shared.ID, expected uint64, next correlation.Checkpoint, added []correlation.Assignment, active []correlation.ActiveSession, snapshot correlation.SourcePosition, complete bool) error {
	tenant, err := requireCorrelationStateTenant(ctx, engagementID)
	if err != nil {
		return err
	}
	if err := validateConsumeArguments(added, active); err != nil {
		return err
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		current, err := lockCorrelationCheckpoint(ctx, tx, tenant, engagementID)
		if err != nil {
			return err
		}
		if err := validateConsumeCheckpoint(current, expected, next, snapshot, complete); err != nil {
			return err
		}
		for _, assignment := range added {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM correlation_assignments WHERE tenant_id=$1 AND engagement_id=$2 AND signal_id=$3)`, tenant.String(), engagementID.String(), assignment.SignalID.String()).Scan(&exists); err != nil {
				return fmt.Errorf("check correlation assignment: %w", err)
			}
			if exists {
				return fmt.Errorf("%w: assigned correlation signal", shared.ErrConflict)
			}
		}
		for _, a := range added {
			if _, err := tx.Exec(ctx, `INSERT INTO correlation_assignments(tenant_id,engagement_id,signal_id,incident_id,asset_id,entity_id,occurred_at,severity,outcome) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, tenant.String(), engagementID.String(), a.SignalID.String(), a.IncidentID.String(), a.AssetID.String(), a.EntityID.String(), a.OccurredAt.UTC(), string(a.Severity), string(a.Outcome)); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM correlation_active_sessions WHERE tenant_id=$1 AND engagement_id=$2`, tenant.String(), engagementID.String()); err != nil {
			return err
		}
		for _, s := range active {
			if _, err := tx.Exec(ctx, `INSERT INTO correlation_active_sessions(tenant_id,engagement_id,asset_id,entity_id,incident_id,min_occurred_at,max_occurred_at,reflected_count,max_severity) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, tenant.String(), engagementID.String(), s.AssetID.String(), s.EntityID.String(), s.IncidentID.String(), s.MinOccurredAt.UTC(), s.MaxOccurredAt.UTC(), s.ReflectedCount, string(s.MaxSeverity)); err != nil {
				return err
			}
		}
		if complete {
			next = finalizedCheckpoint(next, snapshot)
			if _, err := tx.Exec(ctx, `DELETE FROM correlation_staged_signals WHERE tenant_id=$1 AND engagement_id=$2 AND snapshot_recorded_at=$3 AND snapshot_id=$4`, tenant.String(), engagementID.String(), snapshot.RecordedAt.UTC(), snapshot.ID.String()); err != nil {
				return err
			}
		}
		return updateCheckpoint(ctx, tx, tenant, engagementID, expected, next)
	})
}
func lockCorrelationCheckpoint(ctx context.Context, tx pgx.Tx, tenant, engagement shared.ID) (correlation.Checkpoint, error) {
	var checkpoint correlation.Checkpoint
	var phase, completedID, snapshotID, sourceID, stagedID, digest string
	var max, watermark, completedAt, snapshotAt, retention, sourceAt, stagedAt *time.Time
	err := tx.QueryRow(ctx, `SELECT revision,max_observed_at,watermark,phase,completed_recorded_at,completed_id,snapshot_recorded_at,snapshot_id,retention_as_of,source_cursor_recorded_at,source_cursor_id,staged_cursor_occurred_at,staged_cursor_id,policy_digest FROM correlation_checkpoints WHERE tenant_id=$1 AND engagement_id=$2 FOR UPDATE`, tenant.String(), engagement.String()).Scan(&checkpoint.Revision, &max, &watermark, &phase, &completedAt, &completedID, &snapshotAt, &snapshotID, &retention, &sourceAt, &sourceID, &stagedAt, &stagedID, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return correlation.Checkpoint{}, fmt.Errorf("%w: correlation checkpoint missing", shared.ErrConflict)
	}
	if err != nil {
		return correlation.Checkpoint{}, fmt.Errorf("lock correlation checkpoint: %w", err)
	}
	checkpoint.Phase = correlation.Phase(phase)
	checkpoint.Completed = sourcePosition(completedAt, completedID)
	checkpoint.Snapshot = sourcePosition(snapshotAt, snapshotID)
	checkpoint.RetentionAsOf = timeValue(retention)
	checkpoint.SourceCursor = sourcePosition(sourceAt, sourceID)
	checkpoint.StagedCursor = signalPosition(stagedAt, stagedID)
	checkpoint.PolicyDigest = digest
	checkpoint.MaxObservedAt = timeValue(max)
	checkpoint.Watermark = timeValue(watermark)
	return checkpoint, nil
}

func validateStageCheckpoint(current correlation.Checkpoint, expected uint64, next correlation.Checkpoint) error {
	if next.Revision != expected+1 || (next.Phase != correlation.PhaseSource && next.Phase != correlation.PhaseConsume) || next.Snapshot != current.Snapshot || !next.RetentionAsOf.Equal(current.RetentionAsOf) || next.PolicyDigest != current.PolicyDigest || next.Completed != current.Completed || next.MaxObservedAt != current.MaxObservedAt || next.Watermark != current.Watermark || next.StagedCursor != current.StagedCursor {
		return fmt.Errorf("%w: invalid correlation source transition", shared.ErrValidation)
	}
	if !validSourcePosition(next.SourceCursor) || !validSourcePosition(current.SourceCursor) || sourcePositionAfterState(next.SourceCursor, next.Snapshot) {
		return fmt.Errorf("%w: invalid correlation source cursor", shared.ErrValidation)
	}
	if next.Phase == correlation.PhaseSource && !sourcePositionAfterState(next.SourceCursor, current.SourceCursor) {
		return fmt.Errorf("%w: source correlation cursor did not advance", shared.ErrValidation)
	}
	if next.Phase == correlation.PhaseConsume && next.SourceCursor != current.SourceCursor && !sourcePositionAfterState(next.SourceCursor, current.SourceCursor) {
		return fmt.Errorf("%w: source correlation cursor regressed", shared.ErrValidation)
	}
	return nil
}

func validateStagedSignalsTx(ctx context.Context, tx pgx.Tx, tenant, engagement shared.ID, snapshot correlation.SourcePosition, signals []correlation.Signal, strictRetry bool) error {
	for _, signal := range signals {
		var stored correlation.Signal
		var id, asset, entity, severity string
		var timeline []byte
		err := tx.QueryRow(ctx, `SELECT signal_id,occurred_at,asset_id,entity_id,severity,rule_id,title,timeline FROM correlation_staged_signals WHERE tenant_id=$1 AND engagement_id=$2 AND snapshot_recorded_at=$3 AND snapshot_id=$4 AND signal_id=$5`, tenant.String(), engagement.String(), snapshot.RecordedAt.UTC(), snapshot.ID.String(), signal.ID.String()).Scan(&id, &stored.OccurredAt, &asset, &entity, &severity, &stored.RuleID, &stored.Title, &timeline)
		if errors.Is(err, pgx.ErrNoRows) {
			if strictRetry {
				return fmt.Errorf("%w: staged correlation signal %s conflicts", shared.ErrConflict, signal.ID)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("load staged correlation signal: %w", err)
		}
		stored.ID, stored.AssetID, stored.EntityID, stored.Severity = shared.ID(id), shared.ID(asset), shared.ID(entity), shared.Severity(severity)
		if len(timeline) > 0 {
			var ref incident.TimelineRef
			if err := json.Unmarshal(timeline, &ref); err != nil {
				return fmt.Errorf("unmarshal staged timeline: %w", err)
			}
			stored.Timeline = &ref
		}
		if !correlation.SameSignal(stored, signal) {
			return fmt.Errorf("%w: staged correlation signal %s conflicts", shared.ErrConflict, signal.ID)
		}
	}
	return nil
}

func validateConsumeArguments(added []correlation.Assignment, active []correlation.ActiveSession) error {
	seenAssignments := make(map[shared.ID]struct{}, len(added))
	for _, assignment := range added {
		if err := assignment.ValidateForStore(); err != nil {
			return err
		}
		if _, duplicate := seenAssignments[assignment.SignalID]; duplicate {
			return fmt.Errorf("%w: duplicate correlation assignment", shared.ErrConflict)
		}
		seenAssignments[assignment.SignalID] = struct{}{}
	}
	seenSessions := make(map[shared.ID]struct{}, len(active))
	for _, session := range active {
		if err := session.ValidateForStore(); err != nil {
			return err
		}
		key := session.AssetID + "\x00" + session.EntityID + "\x00" + session.IncidentID
		if _, duplicate := seenSessions[key]; duplicate {
			return fmt.Errorf("%w: duplicate active correlation session", shared.ErrValidation)
		}
		seenSessions[key] = struct{}{}
	}
	return nil
}

func validateConsumeCheckpoint(current correlation.Checkpoint, expected uint64, next correlation.Checkpoint, snapshot correlation.SourcePosition, complete bool) error {
	if current.Revision != expected || current.Phase != correlation.PhaseConsume || current.Snapshot != snapshot {
		return fmt.Errorf("%w: stale correlation consume checkpoint", shared.ErrConflict)
	}
	if snapshot.RecordedAt.IsZero() || snapshot.ID.IsZero() || next.Revision != expected+1 {
		return fmt.Errorf("%w: invalid correlation consume transition", shared.ErrValidation)
	}
	if (!current.MaxObservedAt.IsZero() && next.MaxObservedAt.Before(current.MaxObservedAt)) || (!current.Watermark.IsZero() && next.Watermark.Before(current.Watermark)) {
		return fmt.Errorf("%w: correlation event-time checkpoint cannot move backward", shared.ErrValidation)
	}
	if next.Snapshot != current.Snapshot || !next.RetentionAsOf.Equal(current.RetentionAsOf) || next.PolicyDigest != current.PolicyDigest || next.SourceCursor != current.SourceCursor || next.Completed != current.Completed || (!complete && !validStagedAdvance(current.StagedCursor, next.StagedCursor)) || (complete && next.StagedCursor != current.StagedCursor && !validStagedAdvance(current.StagedCursor, next.StagedCursor)) {
		return fmt.Errorf("%w: invalid correlation consume transition", shared.ErrValidation)
	}
	if !complete && next.Phase != correlation.PhaseConsume {
		return fmt.Errorf("%w: invalid intermediate correlation consume transition", shared.ErrValidation)
	}
	if complete && next.Phase != "" {
		return fmt.Errorf("%w: invalid final correlation consume transition", shared.ErrValidation)
	}
	return nil
}

func validSourcePosition(position correlation.SourcePosition) bool {
	return position.RecordedAt.IsZero() == position.ID.IsZero()
}

func sourcePositionAfterState(left, right correlation.SourcePosition) bool {
	return left.RecordedAt.After(right.RecordedAt) || (left.RecordedAt.Equal(right.RecordedAt) && left.ID > right.ID)
}

func validStagedAdvance(current, next correlation.SignalPosition) bool {
	if current.OccurredAt.IsZero() {
		return (next.OccurredAt.IsZero() && next.ID.IsZero()) || (!next.OccurredAt.IsZero() && !next.ID.IsZero())
	}
	return !next.OccurredAt.IsZero() && !next.ID.IsZero() && (next.OccurredAt.After(current.OccurredAt) || (next.OccurredAt.Equal(current.OccurredAt) && next.ID > current.ID))
}

func finalizedCheckpoint(next correlation.Checkpoint, snapshot correlation.SourcePosition) correlation.Checkpoint {
	next.Phase = ""
	next.Completed = snapshot
	next.Snapshot = correlation.SourcePosition{}
	next.RetentionAsOf = time.Time{}
	next.SourceCursor = correlation.SourcePosition{}
	next.StagedCursor = correlation.SignalPosition{}
	next.PolicyDigest = ""
	return next
}

func updateCheckpoint(ctx context.Context, tx pgx.Tx, tenant, engagement shared.ID, expected uint64, next correlation.Checkpoint) error {
	tag, err := tx.Exec(ctx, `UPDATE correlation_checkpoints SET revision=$3,max_observed_at=$4,watermark=$5,phase=$6,completed_recorded_at=$7,completed_id=$8,snapshot_recorded_at=$9,snapshot_id=$10,retention_as_of=$11,source_cursor_recorded_at=$12,source_cursor_id=$13,staged_cursor_occurred_at=$14,staged_cursor_id=$15,policy_digest=$16,updated_at=now() WHERE tenant_id=$1 AND engagement_id=$2 AND revision=$17`, tenant.String(), engagement.String(), next.Revision, nullableCorrelationTime(next.MaxObservedAt), nullableCorrelationTime(next.Watermark), string(next.Phase), nullableCorrelationTime(next.Completed.RecordedAt), next.Completed.ID.String(), nullableCorrelationTime(next.Snapshot.RecordedAt), next.Snapshot.ID.String(), nullableCorrelationTime(next.RetentionAsOf), nullableCorrelationTime(next.SourceCursor.RecordedAt), next.SourceCursor.ID.String(), nullableCorrelationTime(next.StagedCursor.OccurredAt), next.StagedCursor.ID.String(), next.PolicyDigest, expected)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: correlation checkpoint changed concurrently", shared.ErrConflict)
	}
	return nil
}
func requireCorrelationStateTenant(ctx context.Context, engagementID shared.ID) (shared.ID, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() || engagementID.IsZero() {
		return "", fmt.Errorf("%w: correlation state requires tenant and engagement ids", shared.ErrValidation)
	}
	return tenant, nil
}
func nullableCorrelationTime(v time.Time) any {
	if v.IsZero() {
		return nil
	}
	return v.UTC()
}
func timeValue(v *time.Time) time.Time {
	if v == nil {
		return time.Time{}
	}
	return v.UTC()
}
func sourcePosition(at *time.Time, id string) correlation.SourcePosition {
	return correlation.SourcePosition{RecordedAt: timeValue(at), ID: shared.ID(id)}
}
func signalPosition(at *time.Time, id string) correlation.SignalPosition {
	return correlation.SignalPosition{OccurredAt: timeValue(at), ID: shared.ID(id)}
}
