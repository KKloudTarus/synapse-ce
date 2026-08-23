package postgres

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TelemetryTransportRepository is the Postgres tier for the A3 telemetry transport state (per-stream ACK
// snapshots + durable raw batch events). Every method runs under the authenticated ctx tenant via
// WithContextTenant, so RLS binds the partition — the wire never picks it. State is keyed by the
// authenticated agent id in addition to the stream id, so an agent-chosen StreamID can never address a
// sibling agent's stream space within the tenant. Reads also carry an explicit tenant_id predicate as
// defense-in-depth for a role that could bypass RLS. Transport gaps are DERIVED from the ACK snapshot on
// read, never a separate stored table.
type TelemetryTransportRepository struct {
	pool *pgxpool.Pool
}

var _ ports.TelemetryTransportStore = (*TelemetryTransportRepository)(nil)

// NewTelemetryTransportRepository constructs the transport store over a pgx pool.
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
			return nil // zero state (Version 0)
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
		// Optimistic concurrency: the write lands only if the stored version still equals the one the caller
		// read (state.Version); otherwise a concurrent batch advanced the stream and we return ErrConflict so
		// the usecase retries from a fresh read.
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
				return shared.ErrConflict // a row already exists — someone else created it first
			}
			return nil
		}
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
			return shared.ErrConflict // version moved under us
		}
		return nil
	})
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
			WHERE tenant_id=$1 AND agent_id=$2 AND stream_id=$3`,
			tenant.String(), agentID.String(), streamID.String()).Scan(&maxEpoch); err != nil {
			return fmt.Errorf("read stream max epoch: %w", err)
		}
		if maxEpoch != nil {
			highest = uint64(*maxEpoch)
		}
		return nil
	})
	return highest, err
}

func (r *TelemetryTransportRepository) ListGaps(ctx context.Context, agentID, streamID shared.ID) ([]ports.TelemetryGap, error) {
	if err := requireTransportTenant(ctx); err != nil {
		return nil, err
	}
	var gaps []ports.TelemetryGap
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		rows, err := tx.Query(ctx, `SELECT epoch, contiguous, pending FROM telemetry_stream_positions
			WHERE tenant_id=$1 AND agent_id=$2 AND stream_id=$3`, tenant.String(), agentID.String(), streamID.String())
		if err != nil {
			return fmt.Errorf("list stream positions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var epoch, contiguous int64
			var pending []int64
			if err := rows.Scan(&epoch, &contiguous, &pending); err != nil {
				return fmt.Errorf("scan stream position: %w", err)
			}
			st := ports.TelemetryStreamState{AgentID: agentID, StreamID: streamID, Epoch: uint64(epoch), Contiguous: uint64(contiguous)}
			st.Pending = make([]uint64, len(pending))
			for i, p := range pending {
				st.Pending[i] = uint64(p)
			}
			// Gaps are derived from the ACK snapshot — the single source of truth — so a filled gap is never
			// reported (no phantom gaps) and there is no separate log to grow unbounded.
			gaps = append(gaps, st.GapsFrom()...)
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
			tag, err := tx.Exec(ctx, `
				INSERT INTO telemetry_batch_events
				  (tenant_id, agent_id, stream_id, asset_id, epoch, sequence, event_id, class, digest, schema_version, payload, observed_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
				ON CONFLICT (tenant_id, agent_id, stream_id, epoch, sequence, event_id) DO NOTHING`,
				tenant.String(), batch.AgentID.String(), batch.StreamID.String(), batch.AssetID.String(),
				int64(batch.Epoch), int64(batch.Sequence), e.EventID.String(), string(e.Class), e.Digest,
				batch.SchemaVersion, e.Payload, e.ObservedAt.UTC())
			if err != nil {
				return fmt.Errorf("insert batch event: %w", err)
			}
			stored += int(tag.RowsAffected())
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
