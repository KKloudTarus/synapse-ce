package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TelemetryRepository is the CE columnar-tier store (migration 0075) behind ports.TelemetryStore,
// tenant-scoped via WithTenant/RLS. It is reached only through the port and appears in no domain type.
type TelemetryRepository struct {
	pool *pgxpool.Pool
	hot  time.Duration
	warm time.Duration
}

var _ ports.TelemetryStore = (*TelemetryRepository)(nil)

// NewTelemetryRepository constructs the store with the hot/warm tier boundaries (ADR 0001 config).
func NewTelemetryRepository(pool *pgxpool.Pool, hot, warm time.Duration) *TelemetryRepository {
	return &TelemetryRepository{pool: pool, hot: hot, warm: warm}
}

// Ingest bulk-inserts the batch's events, idempotent on (tenant, host, class, seq, idx).
func (r *TelemetryRepository) Ingest(ctx context.Context, batch ports.TelemetryBatch) error {
	if len(batch.Events) == 0 {
		return nil
	}
	// Write under the AUTHENTICATED ctx tenant (not the wire batch's self-declared tenant); the usecase
	// has already asserted they match, and RLS WITH CHECK rejects a row whose tenant_id differs from the
	// GUC — so a forged batch tenant cannot land in another partition.
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		for i, ev := range batch.Events {
			payload, err := json.Marshal(ev)
			if err != nil {
				return fmt.Errorf("marshal telemetry event: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO telemetry_events
				  (tenant_id, host_id, asset_id, agent_id, class, seq, idx, sample_rate, event, observed_at, tier)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'hot')
				ON CONFLICT (tenant_id, host_id, class, seq, idx) DO NOTHING`,
				batch.TenantID.String(), batch.HostID.String(), batch.AssetID.String(), batch.AgentID.String(),
				string(batch.Class), int64(batch.Sequence), i, batch.SampleRate, payload, ev.At.UTC()); err != nil {
				return fmt.Errorf("insert telemetry event: %w", err)
			}
		}
		return nil
	})
}

// LastSequence returns the highest stored seq for a (host, class) in the ctx tenant.
func (r *TelemetryRepository) LastSequence(ctx context.Context, hostID shared.ID, class detection.Class) (uint64, error) {
	var last int64
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COALESCE(max(seq),0) FROM telemetry_events WHERE host_id=$1 AND class=$2`,
			hostID.String(), string(class)).Scan(&last)
	})
	if err != nil {
		return 0, err
	}
	return uint64(last), nil
}

// RecordLoss persists a Truncated/Dropped loss record for the ctx tenant, idempotent on
// (host, class, seq, disposition) via the primary key, so a re-ingest records one loss.
func (r *TelemetryRepository) RecordLoss(ctx context.Context, loss ports.TelemetryLoss) error {
	if err := loss.Validate(); err != nil {
		return err
	}
	if _, ok := shared.TenantFrom(ctx); !ok {
		return fmt.Errorf("%w: telemetry loss requires a tenant in context", shared.ErrValidation)
	}
	loss.FromAt = loss.FromAt.UTC().Truncate(time.Microsecond)
	loss.ToAt = loss.ToAt.UTC().Truncate(time.Microsecond)
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		tag, err := tx.Exec(ctx, `
			INSERT INTO telemetry_losses
			  (tenant_id, host_id, asset_id, class, seq, disposition, observed_count, kept_count, dropped_count, reason, from_at, to_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			ON CONFLICT (tenant_id, host_id, class, seq, disposition) DO NOTHING`,
			tenant.String(), loss.HostID.String(), loss.AssetID.String(), string(loss.Class), int64(loss.Sequence), string(loss.Disposition),
			loss.ObservedCount, loss.KeptCount, loss.DroppedCount, loss.Reason, loss.FromAt, loss.ToAt)
		if err != nil {
			return fmt.Errorf("insert telemetry loss: %w", err)
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var existing ports.TelemetryLoss
		var sequence int64
		if err := tx.QueryRow(ctx, `
			SELECT host_id, asset_id, class, seq, disposition,
			       observed_count, kept_count, dropped_count, reason, from_at, to_at
			FROM telemetry_losses
			WHERE tenant_id=$1 AND host_id=$2 AND class=$3 AND seq=$4 AND disposition=$5`,
			tenant.String(), loss.HostID.String(), string(loss.Class), int64(loss.Sequence), string(loss.Disposition)).Scan(
			&existing.HostID, &existing.AssetID, &existing.Class, &sequence, &existing.Disposition,
			&existing.ObservedCount, &existing.KeptCount, &existing.DroppedCount, &existing.Reason,
			&existing.FromAt, &existing.ToAt,
		); err != nil {
			return fmt.Errorf("read telemetry loss collision: %w", err)
		}
		if sequence < 0 {
			return fmt.Errorf("%w: persisted telemetry loss has a negative sequence", shared.ErrConflict)
		}
		existing.Sequence = uint64(sequence)
		existing.FromAt = existing.FromAt.UTC().Truncate(time.Microsecond)
		existing.ToAt = existing.ToAt.UTC().Truncate(time.Microsecond)
		if existing != loss {
			return fmt.Errorf("%w: telemetry loss identity is already committed to different immutable facts", shared.ErrConflict)
		}
		return nil
	})
}

// defaultHuntCap bounds how many event rows a single hunt loads into memory when the caller sets no
// Limit — a store defined by its volume must never let one query pull the whole window into RAM. The
// completeness metadata (sampled / sequence gaps) is still computed over the FULL window (cheap
// aggregate + distinct-seq queries), so a capped result is still honestly reported as incomplete.
const defaultHuntCap = 50000

// Query runs a retro-hunt over a window and reports completeness honestly (sampled + sequence gaps).
func (r *TelemetryRepository) Query(ctx context.Context, q ports.HuntQuery) (ports.HuntResult, error) {
	// Build a SARGABLE WHERE: only the set fields become predicates, so the (tenant, host, class, seq) and
	// (tenant, asset, observed_at) btrees are usable rather than defeated by `($1='' OR col=$1)`.
	conds := []string{"TRUE"}
	args := []any{}
	add := func(cond string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if q.HostID != "" {
		add("host_id = $%d", q.HostID.String())
	}
	if q.AssetID != "" {
		add("asset_id = $%d", q.AssetID.String())
	}
	if q.Class != "" {
		add("class = $%d", string(q.Class))
	}
	if !q.Since.IsZero() {
		add("observed_at >= $%d", q.Since.UTC())
	}
	if !q.Until.IsZero() {
		add("observed_at <= $%d", q.Until.UTC())
	}
	where := strings.Join(conds, " AND ")
	rowCap := q.Limit
	if rowCap <= 0 || rowCap > defaultHuntCap {
		rowCap = defaultHuntCap
	}

	res := ports.HuntResult{MaxSampleRate: 1}
	seqsByHostClass := map[telemetryKey][]uint64{}
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		// 1. The (bounded) event rows.
		rows, err := tx.Query(ctx, `SELECT event FROM telemetry_events WHERE `+where+` ORDER BY observed_at ASC LIMIT `+fmt.Sprint(rowCap), args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var payload []byte
			if err := rows.Scan(&payload); err != nil {
				return err
			}
			var ev detection.Event
			if err := json.Unmarshal(payload, &ev); err != nil {
				return fmt.Errorf("unmarshal telemetry event: %w", err)
			}
			res.Events = append(res.Events, ev)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		// 2. Completeness over the FULL window (not just the capped rows): max sample rate + distinct seqs.
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(sample_rate),1) FROM telemetry_events WHERE `+where, args...).Scan(&res.MaxSampleRate); err != nil {
			return err
		}
		seqRows, err := tx.Query(ctx, `SELECT host_id, class, seq FROM telemetry_events WHERE `+where+` GROUP BY host_id, class, seq ORDER BY host_id, class, seq`, args...)
		if err != nil {
			return err
		}
		defer seqRows.Close()
		for seqRows.Next() {
			var host, class string
			var seq int64
			if err := seqRows.Scan(&host, &class, &seq); err != nil {
				return err
			}
			k := telemetryKey{host: shared.ID(host), class: detection.Class(class)}
			seqsByHostClass[k] = append(seqsByHostClass[k], uint64(seq))
		}
		if err := seqRows.Err(); err != nil {
			return err
		}
		// 3. First-class losses intersecting the window, windowed by the SAME host/asset/class/time
		// dimensions as the events — so an asset-pivot hunt surfaces losses and a truncated/dropped window
		// is never presented as complete on an asset pivot (losses carry an asset_id for this).
		lossConds := []string{"TRUE"}
		lossArgs := []any{}
		laddc := func(cond string, val any) {
			lossArgs = append(lossArgs, val)
			lossConds = append(lossConds, fmt.Sprintf(cond, len(lossArgs)))
		}
		if q.HostID != "" {
			laddc("host_id = $%d", q.HostID.String())
		}
		if q.AssetID != "" {
			laddc("asset_id = $%d", q.AssetID.String())
		}
		if q.Class != "" {
			laddc("class = $%d", string(q.Class))
		}
		// Overlap, not point containment: to_at >= since AND from_at <= until.
		if !q.Since.IsZero() {
			laddc("to_at >= $%d", q.Since.UTC())
		}
		if !q.Until.IsZero() {
			laddc("from_at <= $%d", q.Until.UTC())
		}
		lossRows, err := tx.Query(ctx, `
			SELECT host_id, asset_id, class, seq, disposition, observed_count, kept_count, dropped_count, reason, from_at, to_at
			FROM telemetry_losses WHERE `+strings.Join(lossConds, " AND ")+` ORDER BY from_at ASC`, lossArgs...)
		if err != nil {
			return err
		}
		defer lossRows.Close()
		for lossRows.Next() {
			var (
				l                        ports.TelemetryLoss
				host, asset, class, disp string
				seq                      int64
			)
			if err := lossRows.Scan(&host, &asset, &class, &seq, &disp, &l.ObservedCount, &l.KeptCount, &l.DroppedCount, &l.Reason, &l.FromAt, &l.ToAt); err != nil {
				return err
			}
			l.HostID, l.AssetID, l.Class, l.Sequence, l.Disposition = shared.ID(host), shared.ID(asset), detection.Class(class), uint64(seq), telemetry.LossDisposition(disp)
			res.Losses = append(res.Losses, l)
		}
		return lossRows.Err()
	})
	if err != nil {
		return ports.HuntResult{}, fmt.Errorf("telemetry query: %w", err)
	}
	res.Sampled = res.MaxSampleRate > 1
	res.SequenceGaps = telemetryGaps(seqsByHostClass)
	res.Complete = !res.Sampled && len(res.SequenceGaps) == 0 && len(res.Losses) == 0
	res.RowsScanned = len(res.Events)
	return res, nil
}

// RetentionSweep down-samples the warm window (drops 1-in-2 by idx for reduced resolution) and expires
// the past-warm window, for the ctx tenant. Returns the counts so the caller can audit the expiry.
func (r *TelemetryRepository) RetentionSweep(ctx context.Context, now time.Time) (ports.SweepReport, error) {
	rep := ports.SweepReport{At: now}
	hotCut := now.Add(-r.hot).UTC()
	warmCut := now.Add(-r.warm).UTC()
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		// Expire past-warm rows.
		ct, err := tx.Exec(ctx, `DELETE FROM telemetry_events WHERE observed_at <= $1`, warmCut)
		if err != nil {
			return fmt.Errorf("expire telemetry: %w", err)
		}
		rep.Expired = ct.RowsAffected()
		// Down-sample the warm window: drop odd-idx hot rows entering warm (reduced resolution)...
		ct, err = tx.Exec(ctx, `DELETE FROM telemetry_events
			WHERE observed_at <= $1 AND observed_at > $2 AND tier='hot' AND (idx % 2) = 1`, hotCut, warmCut)
		if err != nil {
			return fmt.Errorf("downsample telemetry: %w", err)
		}
		rep.WarmDownsampled = ct.RowsAffected()
		// ...and mark the survivors warm.
		if _, err := tx.Exec(ctx, `UPDATE telemetry_events SET tier='warm'
			WHERE observed_at <= $1 AND observed_at > $2 AND tier='hot'`, hotCut, warmCut); err != nil {
			return fmt.Errorf("mark warm: %w", err)
		}
		return nil
	})
	if err != nil {
		return ports.SweepReport{}, err
	}
	return rep, nil
}

// Footprint reports the GLOBAL store size — an operator spend metric across all tenants, not a
// per-tenant figure. Both numbers are global and coherent: an estimated row count from the planner
// statistics (pg_class.reltuples) paired with the real on-disk size (pg_total_relation_size). These are
// catalog reads, unaffected by RLS, and carry only counts/bytes — never tenant data — so a global scope
// leaks nothing. reltuples is an estimate (refreshed by ANALYZE/autovacuum), which is the right shape for
// "predict spend, don't discover it".
func (r *TelemetryRepository) Footprint(ctx context.Context) (ports.TelemetryFootprint, error) {
	var fp ports.TelemetryFootprint
	if err := r.pool.QueryRow(ctx, `SELECT GREATEST(reltuples, 0)::bigint FROM pg_class WHERE relname = 'telemetry_events'`).Scan(&fp.Rows); err != nil {
		return ports.TelemetryFootprint{}, fmt.Errorf("telemetry footprint rows: %w", err)
	}
	if err := r.pool.QueryRow(ctx, `SELECT pg_total_relation_size('telemetry_events')`).Scan(&fp.Bytes); err != nil {
		return ports.TelemetryFootprint{}, fmt.Errorf("telemetry footprint bytes: %w", err)
	}
	return fp, nil
}

// telemetryKey uniquely identifies a (host, class) stream for grouping sequences in hunt queries.
type telemetryKey struct {
	host  shared.ID
	class detection.Class
}

func telemetryGaps(seqsByHostClass map[telemetryKey][]uint64) []ports.TelemetrySequenceGap {
	var gaps []ports.TelemetrySequenceGap
	for k, seqs := range seqsByHostClass {
		uniq := dedupSorted(seqs)
		for i := 1; i < len(uniq); i++ {
			if uniq[i] > uniq[i-1]+1 {
				gaps = append(gaps, ports.TelemetrySequenceGap{
					HostID: k.host, Class: k.class, Missing: uniq[i] - uniq[i-1] - 1, LastSeen: uniq[i-1], Incoming: uniq[i],
				})
			}
		}
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i].LastSeen < gaps[j].LastSeen })
	return gaps
}

func dedupSorted(in []uint64) []uint64 {
	if len(in) == 0 {
		return in
	}
	sort.Slice(in, func(i, j int) bool { return in[i] < in[j] })
	out := in[:1]
	for _, v := range in[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}
