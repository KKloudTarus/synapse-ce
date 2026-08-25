package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TelemetryTransportRepository is the Postgres tier for A3 transport state. The
// ACK snapshot remains the sequencing source of truth; migration 0110 materializes
// its open gaps transactionally and stores the authenticated agent->asset binding.
type TelemetryTransportRepository struct {
	pool *pgxpool.Pool
}

var _ ports.TelemetryTransportStore = (*TelemetryTransportRepository)(nil)
var _ ports.TelemetryAssetBindingStore = (*TelemetryTransportRepository)(nil)

func NewTelemetryTransportRepository(pool *pgxpool.Pool) *TelemetryTransportRepository {
	return &TelemetryTransportRepository{pool: pool}
}

func requireTransportTenant(ctx context.Context) error {
	if _, ok := shared.TenantFrom(ctx); !ok {
		return fmt.Errorf("%w: telemetry transport operation requires a tenant in context", shared.ErrValidation)
	}
	return nil
}

func (r *TelemetryTransportRepository) StreamState(ctx context.Context, agentID, streamID shared.ID, epoch uint64) (ports.TelemetryStreamState, error) {
	if agentID.IsZero() || streamID.IsZero() || epoch == 0 {
		return ports.TelemetryStreamState{}, fmt.Errorf("%w: agent id, stream id and epoch are required", shared.ErrValidation)
	}
	if err := requireTransportTenant(ctx); err != nil {
		return ports.TelemetryStreamState{}, err
	}
	state := ports.TelemetryStreamState{AgentID: agentID, StreamID: streamID, Epoch: epoch}
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		var contiguous, version int64
		var pending []int64
		tenant, _ := shared.TenantFrom(ctx)
		row := tx.QueryRow(ctx, `SELECT contiguous, pending, version FROM telemetry_stream_positions
			WHERE tenant_id=$1 AND agent_id=$2 AND stream_id=$3 AND epoch=$4`,
			tenant.String(), agentID.String(), streamID.String(), int64(epoch))
		switch err := row.Scan(&contiguous, &pending, &version); {
		case errors.Is(err, pgx.ErrNoRows):
			return nil
		case err != nil:
			return fmt.Errorf("read stream position: %w", err)
		}
		state.Contiguous = uint64(contiguous)
		state.Version = uint64(version)
		state.Pending = make([]uint64, len(pending))
		for i, p := range pending {
			state.Pending[i] = uint64(p)
		}
		return nil
	})
	if err != nil {
		return ports.TelemetryStreamState{}, err
	}
	return state, nil
}

func (r *TelemetryTransportRepository) SaveStreamState(ctx context.Context, state ports.TelemetryStreamState) error {
	if err := state.Validate(); err != nil {
		return err
	}
	if err := requireTransportTenant(ctx); err != nil {
		return err
	}
	pending := make([]int64, len(state.Pending))
	for i, p := range state.Pending {
		pending[i] = int64(p)
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		if state.Version == 0 {
			tag, err := tx.Exec(ctx, `
				INSERT INTO telemetry_stream_positions (tenant_id, agent_id, stream_id, epoch, contiguous, pending, version, updated_at)
				VALUES ($1,$2,$3,$4,$5,$6,1,$7)
				ON CONFLICT (tenant_id, agent_id, stream_id, epoch) DO NOTHING`,
				tenant.String(), state.AgentID.String(), state.StreamID.String(), int64(state.Epoch),
				int64(state.Contiguous), pending, state.UpdatedAt.UTC())
			if err != nil {
				return fmt.Errorf("insert stream position: %w", err)
			}
			if tag.RowsAffected() != 1 {
				return shared.ErrConflict
			}
		} else {
			tag, err := tx.Exec(ctx, `
				UPDATE telemetry_stream_positions
				SET contiguous=$5, pending=$6, version=version+1, updated_at=$7
				WHERE tenant_id=$1 AND agent_id=$2 AND stream_id=$3 AND epoch=$4 AND version=$8`,
				tenant.String(), state.AgentID.String(), state.StreamID.String(), int64(state.Epoch),
				int64(state.Contiguous), pending, state.UpdatedAt.UTC(), int64(state.Version))
			if err != nil {
				return fmt.Errorf("update stream position: %w", err)
			}
			if tag.RowsAffected() != 1 {
				return shared.ErrConflict
			}
		}
		return reconcileTransportGaps(ctx, tx, tenant, state)
	})
}

type postgresGapCoverage struct {
	assetID  shared.ID
	priority fleetagent.DeliveryPriority
	fromAt   time.Time
	toAt     time.Time
}

// postgresGapCoverageFor derives a conservative observed-time span from the received
// batch immediately before and after a missing sequence range. The successor is required:
// AckLedger can only know a gap once a later sequence arrived. Missing-prefix gaps have no
// predecessor, so Unix epoch is used as a conservative lower bound rather than a point
// timestamp that could let an earlier hunt falsely report Complete=true.
func postgresGapCoverageFor(ctx context.Context, tx pgx.Tx, tenant shared.ID, state ports.TelemetryStreamState, gap ports.TelemetryGap) (postgresGapCoverage, bool, error) {
	var nextAsset string
	var nextPriority int
	var nextFrom time.Time
	err := tx.QueryRow(ctx, `SELECT asset_id,priority,event_time_min FROM telemetry_batch_commits
		WHERE tenant_id=$1 AND agent_id=$2 AND stream_id=$3 AND epoch=$4 AND sequence=$5`,
		tenant.String(), state.AgentID.String(), state.StreamID.String(), int64(state.Epoch), int64(gap.ToSequence+1)).
		Scan(&nextAsset, &nextPriority, &nextFrom)
	if errors.Is(err, pgx.ErrNoRows) {
		return postgresGapCoverage{}, false, nil
	}
	if err != nil {
		return postgresGapCoverage{}, false, fmt.Errorf("read telemetry gap successor commitment: %w", err)
	}
	if !fleetagent.DeliveryPriority(nextPriority).Valid() {
		return postgresGapCoverage{}, false, fmt.Errorf("%w: stored telemetry batch priority %d is invalid", shared.ErrValidation, nextPriority)
	}
	coverage := postgresGapCoverage{
		assetID: shared.ID(nextAsset), priority: fleetagent.DeliveryPriority(nextPriority),
		fromAt: time.Unix(0, 0).UTC(), toAt: nextFrom.UTC(),
	}
	if gap.FromSequence > 1 {
		var prevAsset string
		var prevPriority int
		var prevTo time.Time
		err := tx.QueryRow(ctx, `SELECT asset_id,priority,event_time_max FROM telemetry_batch_commits
			WHERE tenant_id=$1 AND agent_id=$2 AND stream_id=$3 AND epoch=$4 AND sequence=$5`,
			tenant.String(), state.AgentID.String(), state.StreamID.String(), int64(state.Epoch), int64(gap.FromSequence-1)).
			Scan(&prevAsset, &prevPriority, &prevTo)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			// A repaired/imported ACK state may lack the predecessor commitment. Keep
			// the conservative Unix lower bound rather than inventing a precise span.
		case err != nil:
			return postgresGapCoverage{}, false, fmt.Errorf("read telemetry gap predecessor commitment: %w", err)
		case prevAsset == nextAsset && prevPriority == nextPriority:
			coverage.fromAt = prevTo.UTC()
		}
	}
	if coverage.fromAt.After(coverage.toAt) {
		coverage.fromAt, coverage.toAt = coverage.toAt, coverage.fromAt
	}
	return coverage, true, nil
}

func reconcileTransportGaps(ctx context.Context, tx pgx.Tx, tenant shared.ID, state ports.TelemetryStreamState) error {
	wanted := map[[2]uint64]ports.TelemetryGap{}
	for _, g := range state.GapsFrom() {
		g.DetectedAt = state.UpdatedAt.UTC()
		wanted[[2]uint64{g.FromSequence, g.ToSequence}] = g
	}
	rows, err := tx.Query(ctx, `SELECT from_sequence,to_sequence FROM telemetry_transport_gaps
		WHERE tenant_id=$1 AND agent_id=$2 AND stream_id=$3 AND epoch=$4 AND resolved_at IS NULL`,
		tenant.String(), state.AgentID.String(), state.StreamID.String(), int64(state.Epoch))
	if err != nil {
		return fmt.Errorf("list open telemetry gaps: %w", err)
	}
	var open [][2]uint64
	for rows.Next() {
		var from, to int64
		if err := rows.Scan(&from, &to); err != nil {
			rows.Close()
			return fmt.Errorf("scan open telemetry gap: %w", err)
		}
		open = append(open, [2]uint64{uint64(from), uint64(to)})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	for _, key := range open {
		gap, stillOpen := wanted[key]
		if !stillOpen {
			if _, err := tx.Exec(ctx, `UPDATE telemetry_transport_gaps SET resolved_at=$1
				WHERE tenant_id=$2 AND agent_id=$3 AND stream_id=$4 AND epoch=$5
				  AND from_sequence=$6 AND to_sequence=$7 AND resolved_at IS NULL`,
				state.UpdatedAt.UTC(), tenant.String(), state.AgentID.String(), state.StreamID.String(), int64(state.Epoch), int64(key[0]), int64(key[1])); err != nil {
				return fmt.Errorf("resolve telemetry gap: %w", err)
			}
			continue
		}

		coverage, ok, err := postgresGapCoverageFor(ctx, tx, tenant, state, gap)
		if err != nil {
			return err
		}
		if ok {
			if _, err := tx.Exec(ctx, `UPDATE telemetry_transport_gaps
				SET asset_id=$1,priority=$2,from_at=$3,to_at=$4
				WHERE tenant_id=$5 AND agent_id=$6 AND stream_id=$7 AND epoch=$8
				  AND from_sequence=$9 AND to_sequence=$10 AND resolved_at IS NULL`,
				coverage.assetID.String(), int(coverage.priority), coverage.fromAt, coverage.toAt,
				tenant.String(), state.AgentID.String(), state.StreamID.String(), int64(state.Epoch), int64(key[0]), int64(key[1])); err != nil {
				return fmt.Errorf("enrich telemetry gap coverage: %w", err)
			}
		}
		delete(wanted, key)
	}

	for _, gap := range wanted {
		coverage, ok, err := postgresGapCoverageFor(ctx, tx, tenant, state, gap)
		if err != nil {
			return err
		}
		if ok {
			if _, err := tx.Exec(ctx, `INSERT INTO telemetry_transport_gaps
				(tenant_id,agent_id,asset_id,stream_id,priority,epoch,from_sequence,to_sequence,from_at,to_at,detected_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING`,
				tenant.String(), state.AgentID.String(), coverage.assetID.String(), state.StreamID.String(), int(coverage.priority),
				int64(state.Epoch), int64(gap.FromSequence), int64(gap.ToSequence), coverage.fromAt, coverage.toAt, state.UpdatedAt.UTC()); err != nil {
				return fmt.Errorf("materialize telemetry gap coverage: %w", err)
			}
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO telemetry_transport_gaps
			(tenant_id,agent_id,stream_id,epoch,from_sequence,to_sequence,detected_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
			tenant.String(), state.AgentID.String(), state.StreamID.String(), int64(state.Epoch),
			int64(gap.FromSequence), int64(gap.ToSequence), state.UpdatedAt.UTC()); err != nil {
			return fmt.Errorf("materialize sequence-only telemetry gap: %w", err)
		}
	}
	return nil
}

func (r *TelemetryTransportRepository) MaxEpoch(ctx context.Context, agentID, streamID shared.ID) (uint64, error) {
	if err := requireTransportTenant(ctx); err != nil {
		return 0, err
	}
	var highest uint64
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		var maxEpoch *int64
		tenant, _ := shared.TenantFrom(ctx)
		if err := tx.QueryRow(ctx, `SELECT max(epoch) FROM telemetry_stream_positions
			WHERE tenant_id=$1 AND agent_id=$2 AND stream_id=$3`, tenant.String(), agentID.String(), streamID.String()).Scan(&maxEpoch); err != nil {
			return fmt.Errorf("read stream max epoch: %w", err)
		}
		if maxEpoch != nil {
			highest = uint64(*maxEpoch)
		}
		return nil
	})
	return highest, err
}

func scanPostgresTelemetryGap(rows pgx.Rows, fallbackAgent, fallbackStream shared.ID) (ports.TelemetryGap, error) {
	var (
		agentID, streamID               string
		assetID                         pgtype.Text
		priority                        pgtype.Int4
		epoch, fromSequence, toSequence int64
		fromAt, toAt                    pgtype.Timestamptz
		detectedAt                      time.Time
	)
	if err := rows.Scan(&agentID, &assetID, &streamID, &priority, &epoch, &fromSequence, &toSequence, &fromAt, &toAt, &detectedAt); err != nil {
		return ports.TelemetryGap{}, err
	}
	gap := ports.TelemetryGap{
		AgentID: shared.ID(agentID), StreamID: shared.ID(streamID), Epoch: uint64(epoch),
		FromSequence: uint64(fromSequence), ToSequence: uint64(toSequence), DetectedAt: detectedAt.UTC(),
	}
	if gap.AgentID.IsZero() {
		gap.AgentID = fallbackAgent
	}
	if gap.StreamID.IsZero() {
		gap.StreamID = fallbackStream
	}
	if assetID.Valid {
		gap.AssetID = shared.ID(assetID.String)
	}
	if priority.Valid {
		gap.Priority = fleetagent.DeliveryPriority(priority.Int32)
	}
	if fromAt.Valid {
		gap.FromAt = fromAt.Time.UTC()
	}
	if toAt.Valid {
		gap.ToAt = toAt.Time.UTC()
	}
	return gap, nil
}

func (r *TelemetryTransportRepository) ListGaps(ctx context.Context, agentID, streamID shared.ID) ([]ports.TelemetryGap, error) {
	if err := requireTransportTenant(ctx); err != nil {
		return nil, err
	}
	var gaps []ports.TelemetryGap
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		rows, err := tx.Query(ctx, `SELECT agent_id,asset_id,stream_id,priority,epoch,from_sequence,to_sequence,from_at,to_at,detected_at
			FROM telemetry_transport_gaps
			WHERE tenant_id=$1 AND agent_id=$2 AND stream_id=$3 AND resolved_at IS NULL
			ORDER BY epoch,from_sequence`, tenant.String(), agentID.String(), streamID.String())
		if err != nil {
			return fmt.Errorf("list telemetry gaps: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			gap, err := scanPostgresTelemetryGap(rows, agentID, streamID)
			if err != nil {
				return fmt.Errorf("scan telemetry gap: %w", err)
			}
			gaps = append(gaps, gap)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(gaps, func(i, j int) bool {
		if gaps[i].Epoch != gaps[j].Epoch {
			return gaps[i].Epoch < gaps[j].Epoch
		}
		return gaps[i].FromSequence < gaps[j].FromSequence
	})
	return gaps, nil
}

func (r *TelemetryTransportRepository) QueryDeliveryGaps(ctx context.Context, q ports.TelemetryGapQuery) ([]ports.TelemetryGap, error) {
	if err := requireTransportTenant(ctx); err != nil {
		return nil, err
	}
	if q.Priority != nil && !q.Priority.Valid() {
		return nil, fmt.Errorf("%w: telemetry gap query has invalid priority %d", shared.ErrValidation, int(*q.Priority))
	}
	if !q.Since.IsZero() && !q.Until.IsZero() && q.Until.Before(q.Since) {
		return nil, fmt.Errorf("%w: telemetry gap query until precedes since", shared.ErrValidation)
	}
	var gaps []ports.TelemetryGap
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		args := []any{tenant.String()}
		conds := []string{"tenant_id=$1", "resolved_at IS NULL", "asset_id IS NOT NULL", "priority IS NOT NULL", "from_at IS NOT NULL", "to_at IS NOT NULL"}
		add := func(format string, value any) {
			args = append(args, value)
			conds = append(conds, fmt.Sprintf(format, len(args)))
		}
		if !q.AgentID.IsZero() {
			add("agent_id=$%d", q.AgentID.String())
		}
		if !q.AssetID.IsZero() {
			add("asset_id=$%d", q.AssetID.String())
		}
		if q.Priority != nil {
			add("priority=$%d", int(*q.Priority))
		}
		if !q.Since.IsZero() {
			add("to_at >= $%d", q.Since.UTC())
		}
		if !q.Until.IsZero() {
			add("from_at <= $%d", q.Until.UTC())
		}
		rows, err := tx.Query(ctx, `SELECT agent_id,asset_id,stream_id,priority,epoch,from_sequence,to_sequence,from_at,to_at,detected_at
			FROM telemetry_transport_gaps WHERE `+strings.Join(conds, " AND ")+` ORDER BY from_at,epoch,from_sequence`, args...)
		if err != nil {
			return fmt.Errorf("query telemetry delivery gaps: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			gap, err := scanPostgresTelemetryGap(rows, q.AgentID, "")
			if err != nil {
				return fmt.Errorf("scan telemetry delivery gap: %w", err)
			}
			gaps = append(gaps, gap)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	agentGaps, err := r.QueryAgentGaps(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query durable telemetry agent gaps: %w", err)
	}
	gaps = append(gaps, agentGaps...)
	sort.Slice(gaps, func(i, j int) bool {
		if gaps[i].FromAt.Equal(gaps[j].FromAt) {
			if gaps[i].Epoch != gaps[j].Epoch {
				return gaps[i].Epoch < gaps[j].Epoch
			}
			return gaps[i].FromSequence < gaps[j].FromSequence
		}
		return gaps[i].FromAt.Before(gaps[j].FromAt)
	})
	return gaps, nil
}

func (r *TelemetryTransportRepository) IngestBatchEvents(ctx context.Context, batch ports.TelemetryEventBatch) (int, error) {
	if err := batch.Validate(); err != nil {
		return 0, err
	}
	if err := requireTransportTenant(ctx); err != nil {
		return 0, err
	}
	stored := 0
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		for _, e := range batch.Events {
			tag, err := tx.Exec(ctx, `INSERT INTO telemetry_batch_events
				(tenant_id,agent_id,stream_id,asset_id,epoch,sequence,event_id,class,digest,schema_version,payload,observed_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
				ON CONFLICT (tenant_id,agent_id,stream_id,epoch,sequence,event_id) DO NOTHING`,
				tenant.String(), batch.AgentID.String(), batch.StreamID.String(), batch.AssetID.String(), int64(batch.Epoch), int64(batch.Sequence),
				e.EventID.String(), string(e.Class), e.Digest, batch.SchemaVersion, e.Payload, e.ObservedAt.UTC())
			if err != nil {
				return fmt.Errorf("insert batch event: %w", err)
			}
			if tag.RowsAffected() == 1 {
				stored++
				continue
			}
			var assetID, class, digest string
			var schemaVersion int
			var payload []byte
			if err := tx.QueryRow(ctx, `SELECT asset_id,class,digest,schema_version,payload FROM telemetry_batch_events
				WHERE tenant_id=$1 AND agent_id=$2 AND stream_id=$3 AND epoch=$4 AND sequence=$5 AND event_id=$6`,
				tenant.String(), batch.AgentID.String(), batch.StreamID.String(), int64(batch.Epoch), int64(batch.Sequence), e.EventID.String()).Scan(&assetID, &class, &digest, &schemaVersion, &payload); err != nil {
				return fmt.Errorf("read batch event collision: %w", err)
			}
			if assetID != batch.AssetID.String() || class != string(e.Class) || digest != e.Digest || schemaVersion != batch.SchemaVersion || !bytes.Equal(payload, e.Payload) {
				return fmt.Errorf("%w: telemetry event coordinate is already committed to different content", shared.ErrConflict)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return stored, nil
}

func (r *TelemetryTransportRepository) CountBatchEvents(ctx context.Context, agentID, streamID shared.ID, epoch, sequence uint64) (int, error) {
	if err := requireTransportTenant(ctx); err != nil {
		return 0, err
	}
	var n int
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		return tx.QueryRow(ctx, `SELECT count(*) FROM telemetry_batch_events
			WHERE tenant_id=$1 AND agent_id=$2 AND stream_id=$3 AND epoch=$4 AND sequence=$5`,
			tenant.String(), agentID.String(), streamID.String(), int64(epoch), int64(sequence)).Scan(&n)
	})
	return n, err
}

func (r *TelemetryTransportRepository) BindTelemetryAsset(ctx context.Context, binding ports.TelemetryAssetBinding) error {
	if err := binding.Validate(); err != nil {
		return err
	}
	if err := requireTransportTenant(ctx); err != nil {
		return err
	}
	tenant, _ := shared.TenantFrom(ctx)
	if tenant != binding.TenantID {
		return fmt.Errorf("%w: telemetry asset binding tenant disagrees with context", shared.ErrForbidden)
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO telemetry_asset_bindings (tenant_id,agent_id,asset_id,updated_at)
			VALUES ($1,$2,$3,$4)
			ON CONFLICT (tenant_id,agent_id) DO UPDATE SET asset_id=EXCLUDED.asset_id,updated_at=EXCLUDED.updated_at
			WHERE telemetry_asset_bindings.updated_at <= EXCLUDED.updated_at`,
			binding.TenantID.String(), binding.AgentID.String(), binding.AssetID.String(), binding.UpdatedAt.UTC())
		if err != nil {
			return fmt.Errorf("bind telemetry asset: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: stale telemetry asset binding update", shared.ErrConflict)
		}
		return nil
	})
}

func (r *TelemetryTransportRepository) ResolveTelemetryAsset(ctx context.Context, agentID shared.ID) (shared.ID, error) {
	if agentID.IsZero() {
		return "", fmt.Errorf("%w: telemetry asset resolution requires agent id", shared.ErrValidation)
	}
	if err := requireTransportTenant(ctx); err != nil {
		return "", err
	}
	var asset shared.ID
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		var value string
		err := tx.QueryRow(ctx, `SELECT asset_id FROM telemetry_asset_bindings WHERE tenant_id=$1 AND agent_id=$2`, tenant.String(), agentID.String()).Scan(&value)
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("resolve telemetry asset: %w", err)
		}
		asset = shared.ID(value)
		return nil
	})
	return asset, err
}
