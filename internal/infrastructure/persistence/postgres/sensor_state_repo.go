package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type SensorStateRepository struct {
	pool *pgxpool.Pool
	*FleetAuditRepository
}

var _ ports.SensorStateStore = (*SensorStateRepository)(nil)
var _ ports.CoverageSensorStateReader = (*SensorStateRepository)(nil)
var _ ports.SensorStateAuditStore = (*SensorStateRepository)(nil)

func NewSensorStateRepository(pool *pgxpool.Pool) (*SensorStateRepository, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: sensor-state repository requires a database pool", shared.ErrValidation)
	}
	audits, err := NewFleetAuditRepository(pool)
	if err != nil {
		return nil, err
	}
	return &SensorStateRepository{pool: pool, FleetAuditRepository: audits}, nil
}

func (r *SensorStateRepository) AppendSensorState(ctx context.Context, observation sensorstate.Observation) error {
	if err := observation.Validate(); err != nil {
		return err
	}
	if err := requireTransportTenant(ctx); err != nil {
		return err
	}
	observation = sensorstate.NormalizeObservation(observation)
	states, err := json.Marshal(observation.States)
	if err != nil {
		return fmt.Errorf("marshal sensor-state classes: %w", err)
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		tag, err := tx.Exec(ctx, `INSERT INTO sensor_state_history
			(tenant_id,report_id,agent_id,asset_id,host_id,record_kind,observed_at,recorded_at,schema_version,payload_digest,signed_content_digest,states)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			ON CONFLICT (tenant_id,report_id) DO NOTHING`,
			tenant.String(), observation.ReportID.String(), observation.AgentID.String(), observation.AssetID.String(), observation.HostID.String(), string(observation.Kind), observation.ObservedAt, observation.RecordedAt, observation.SchemaVersion, observation.PayloadDigest, observation.SignedContentDigest, states)
		if err != nil {
			return fmt.Errorf("insert sensor-state observation: %w", err)
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var existing sensorstate.Observation
		if err := tx.QueryRow(ctx, `SELECT signed_content_digest
			FROM sensor_state_history WHERE tenant_id=$1 AND report_id=$2`, tenant.String(), observation.ReportID.String()).Scan(&existing.SignedContentDigest); err != nil {
			return fmt.Errorf("read sensor-state collision: %w", err)
		}
		existing.ReportID = observation.ReportID
		if !sensorstate.SameSignedObservation(existing, observation) {
			return fmt.Errorf("%w: sensor-state report id is already committed to different signed content", shared.ErrConflict)
		}
		return nil
	})
}

func (r *SensorStateRepository) AppendSensorStateWithAudit(
	ctx context.Context,
	observation sensorstate.Observation,
	intent ports.FleetAuditIntent,
) (ports.FleetAuditIntent, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return ports.FleetAuditIntent{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	var committed ports.FleetAuditIntent
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		transactionCtx := context.WithValue(ctx, tenantTransactionKey{}, tenantTransaction{
			tenantID: tenantID.String(),
			tx:       tx,
		})
		if err := r.AppendSensorState(transactionCtx, observation); err != nil {
			return err
		}
		// Normalize BEFORE using the id as a lookup key. Reading with an untrimmed id
		// would miss the existing row, keep the retry's wall clock, then collide on the
		// trimmed primary key and report a spurious equivocation conflict.
		intent, _, err := validateFleetAuditIntent(intent)
		if err != nil {
			return err
		}
		var existingAt time.Time
		err = tx.QueryRow(ctx, `SELECT occurred_at FROM fleet_audit_intents
			WHERE tenant_id=$1 AND intent_id=$2`, tenantID.String(), intent.ID).Scan(&existingAt)
		if err == nil {
			intent.Entry.At = existingAt.UTC()
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("read sensor-state audit intention: %w", err)
		}
		stored, err := r.InsertFleetAudit(transactionCtx, intent)
		if err != nil {
			return err
		}
		committed = stored
		return nil
	})
	return committed, err
}

func (r *SensorStateRepository) ListSensorStates(ctx context.Context, q ports.SensorStateQuery) ([]sensorstate.Observation, error) {
	if !q.Valid() {
		return nil, fmt.Errorf("%w: sensor-state query until precedes since", shared.ErrValidation)
	}
	if err := requireTransportTenant(ctx); err != nil {
		return nil, err
	}
	out := make([]sensorstate.Observation, 0)
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		args := []any{tenant.String()}
		conditions := []string{"tenant_id=$1"}
		add := func(format string, value any) {
			args = append(args, value)
			conditions = append(conditions, fmt.Sprintf(format, len(args)))
		}
		if !q.AgentID.IsZero() {
			add("agent_id=$%d", q.AgentID.String())
		}
		if !q.AssetID.IsZero() {
			add("asset_id=$%d", q.AssetID.String())
		}
		if !q.HostID.IsZero() {
			add("host_id=$%d", q.HostID.String())
		}
		if !q.Since.IsZero() {
			add("observed_at >= $%d", q.Since.UTC())
		}
		if !q.Until.IsZero() {
			add("observed_at < $%d", q.Until.UTC())
		}
		limit := q.Limit
		if limit <= 0 || limit > 1000 {
			limit = 1000
		}
		args = append(args, limit)
		rows, err := tx.Query(ctx, `SELECT report_id,agent_id,asset_id,host_id,record_kind,observed_at,recorded_at,schema_version,payload_digest,signed_content_digest,states FROM sensor_state_history WHERE `+strings.Join(conditions, " AND ")+fmt.Sprintf(" ORDER BY observed_at,report_id LIMIT $%d", len(args)), args...)
		if err != nil {
			return fmt.Errorf("query sensor-state history: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var observation sensorstate.Observation
			var states []byte
			if err := rows.Scan(&observation.ReportID, &observation.AgentID, &observation.AssetID, &observation.HostID, &observation.Kind, &observation.ObservedAt, &observation.RecordedAt, &observation.SchemaVersion, &observation.PayloadDigest, &observation.SignedContentDigest, &states); err != nil {
				return fmt.Errorf("scan sensor-state history: %w", err)
			}
			if err := json.Unmarshal(states, &observation.States); err != nil {
				return fmt.Errorf("decode sensor-state history: %w", err)
			}
			out = append(out, observation)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *SensorStateRepository) ListCoverageSensorStates(ctx context.Context, q ports.CoverageSensorStateQuery) ([]sensorstate.Observation, error) {
	if !q.Valid() {
		return nil, fmt.Errorf("%w: coverage sensor-state query has invalid identity or half-open interval", shared.ErrValidation)
	}
	if err := requireTransportTenant(ctx); err != nil {
		return nil, err
	}
	out := make([]sensorstate.Observation, 0)
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		rows, err := tx.Query(ctx, `WITH effective_report_ids AS (
			SELECT DISTINCT report_id
			FROM (
				SELECT DISTINCT ON (state->>'Class') history.report_id
				FROM sensor_state_history AS history
				CROSS JOIN LATERAL jsonb_array_elements(history.states) AS state
				WHERE history.tenant_id=$1 AND history.agent_id=$2 AND history.asset_id=$3
				  AND history.host_id=$4 AND history.observed_at < $5
				ORDER BY state->>'Class',history.observed_at DESC,history.report_id DESC
			) AS per_class
		), effective AS (
			SELECT history.report_id,history.agent_id,history.asset_id,history.host_id,history.record_kind,
				history.observed_at,history.recorded_at,history.schema_version,history.payload_digest,
				history.signed_content_digest,history.states
			FROM sensor_state_history AS history
			JOIN effective_report_ids AS selected ON selected.report_id=history.report_id
			WHERE history.tenant_id=$1
		), in_window AS (
			SELECT report_id,agent_id,asset_id,host_id,record_kind,observed_at,recorded_at,
				schema_version,payload_digest,signed_content_digest,states
			FROM sensor_state_history
			WHERE tenant_id=$1 AND agent_id=$2 AND asset_id=$3 AND host_id=$4
			  AND observed_at >= $5 AND observed_at < $6
		)
		SELECT * FROM effective
		UNION ALL
		SELECT * FROM in_window
		ORDER BY observed_at,report_id`,
			tenant.String(), q.AgentID.String(), q.AssetID.String(), q.HostID.String(), q.Since.UTC(), q.Until.UTC())
		if err != nil {
			return fmt.Errorf("query coverage sensor-state history: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var observation sensorstate.Observation
			var states []byte
			if err := rows.Scan(
				&observation.ReportID, &observation.AgentID, &observation.AssetID, &observation.HostID,
				&observation.Kind, &observation.ObservedAt, &observation.RecordedAt, &observation.SchemaVersion,
				&observation.PayloadDigest, &observation.SignedContentDigest, &states,
			); err != nil {
				return fmt.Errorf("scan coverage sensor-state history: %w", err)
			}
			if err := json.Unmarshal(states, &observation.States); err != nil {
				return fmt.Errorf("decode coverage sensor-state history: %w", err)
			}
			out = append(out, observation)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
