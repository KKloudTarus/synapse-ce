package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
)

// SIEMRepository persists sinks, leases, batches, and incident capture.
type SIEMRepository struct{ pool *pgxpool.Pool }

// NewSIEMRepository returns a store scoped by the tenant on ctx.
// TenantIDs is the exception: it lists tenant ids and no sink secrets.
func NewSIEMRepository(pool *pgxpool.Pool) *SIEMRepository {
	return &SIEMRepository{pool: pool}
}

func (r *SIEMRepository) CreateSink(ctx context.Context, sink siem.Sink, sealed string) error {
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		if sink.TenantID != tenant {
			return fmt.Errorf("%w: sink tenant mismatch", shared.ErrValidation)
		}
		if err := lockSIEMRetention(ctx, tx, sink.TenantID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO siem_sinks (
				tenant_id, id, name, provider, origin, target, data_class, ack_mode, indexer_ack,
				allow_hosts, paused, enabled, generation, secret_version, version, channel,
				blocked_reason, created_at, updated_at
			) VALUES (
				$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19
			)`,
			sink.TenantID.String(), sink.ID.String(), sink.Name, string(sink.Provider), sink.Origin, sink.Target,
			string(sink.DataClass), string(sink.AckMode), sink.IndexerAckSupported, nonNilHosts(sink.AllowHosts), sink.Paused,
			sink.Enabled, sink.Generation, sink.SecretVersion, sink.Version, sink.Channel, sink.BlockedReason,
			sink.CreatedAt, sink.UpdatedAt)
		if err != nil {
			return siemWriteErr("insert sink", err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO siem_sink_secrets (tenant_id, sink_id, version, ciphertext, created_at) VALUES ($1,$2,$3,$4,$5)`,
			sink.TenantID.String(), sink.ID.String(), sink.SecretVersion, sealed, sink.CreatedAt)
		if err != nil {
			return siemWriteErr("insert secret", err)
		}
		for _, partition := range []struct {
			source siem.Source
			phase  siem.Phase
		}{{siem.SourceIncidentLive, siem.PhaseLive}, {siem.SourceIncidentHistorical, siem.PhaseHistorical}} {
			var seq int64
			var incidentID string
			var eventSeq int
			err := tx.QueryRow(ctx, `SELECT stream_seq, incident_id, event_seq
				FROM siem_incident_capture WHERE tenant_id=$1 AND phase=$2
				ORDER BY stream_seq ASC LIMIT 1`, sink.TenantID.String(), string(partition.phase)).Scan(&seq, &incidentID, &eventSeq)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			if seq <= 1 {
				continue
			}
			position, err := json.Marshal(siem.Position{Source: partition.source, Phase: partition.phase,
				StreamSeq: seq, IncidentID: incidentID, EventSeq: eventSeq})
			if err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `INSERT INTO siem_checkpoints
				(tenant_id, sink_id, source, generation, position, updated_at)
				VALUES ($1,$2,$3,$4,$5,$6)`, sink.TenantID.String(), sink.ID.String(),
				string(partition.source), sink.Generation, position, sink.CreatedAt)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *SIEMRepository) UpdateSink(ctx context.Context, sink siem.Sink, expected int64) error {
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		if sink.TenantID != tenant {
			return fmt.Errorf("%w: sink tenant mismatch", shared.ErrValidation)
		}
		tag, err := tx.Exec(ctx, `
			UPDATE siem_sinks SET
				name=$3, origin=$4, target=$5, data_class=$6, ack_mode=$7, indexer_ack=$8, allow_hosts=$9,
				paused=$10, enabled=$11, generation=$12, secret_version=$13, version=$14, channel=$15,
				blocked_reason=$16, updated_at=$17
			WHERE tenant_id=$1 AND id=$2 AND version=$18`,
			sink.TenantID.String(), sink.ID.String(), sink.Name, sink.Origin, sink.Target, string(sink.DataClass),
			string(sink.AckMode), sink.IndexerAckSupported, nonNilHosts(sink.AllowHosts), sink.Paused, sink.Enabled,
			sink.Generation, sink.SecretVersion, sink.Version, sink.Channel, sink.BlockedReason, sink.UpdatedAt, expected)
		if err != nil {
			return siemWriteErr("update sink", err)
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: sink version", shared.ErrConflict)
		}
		return nil
	})
}

func (r *SIEMRepository) GetSink(ctx context.Context, id shared.ID) (siem.Sink, error) {
	var sink siem.Sink
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, sinkSelect+` WHERE tenant_id=current_setting('app.current_tenant', true) AND id=$1`, id.String())
		var err error
		sink, err = scanSink(row)
		return err
	})
	return sink, err
}

func (r *SIEMRepository) ListSinks(ctx context.Context) ([]siem.Sink, error) {
	var out []siem.Sink
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sinkSelect+` WHERE tenant_id=current_setting('app.current_tenant', true) ORDER BY name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			sink, err := scanSink(rows)
			if err != nil {
				return err
			}
			out = append(out, sink)
		}
		return rows.Err()
	})
	return out, err
}

func (r *SIEMRepository) PutSecret(ctx context.Context, sinkID shared.ID, version int64, sealed string) error {
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		_, err := tx.Exec(ctx, `INSERT INTO siem_sink_secrets (tenant_id, sink_id, version, ciphertext, created_at) VALUES ($1,$2,$3,$4,$5)`,
			tenant.String(), sinkID.String(), version, sealed, time.Now().UTC())
		return siemWriteErr("insert secret", err)
	})
}

func (r *SIEMRepository) LatestSecret(ctx context.Context, sinkID shared.ID) (int64, string, error) {
	var version int64
	var sealed string
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT version, ciphertext FROM siem_sink_secrets WHERE tenant_id=current_setting('app.current_tenant', true) AND sink_id=$1 ORDER BY version DESC LIMIT 1`, sinkID.String()).Scan(&version, &sealed)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: siem secret", shared.ErrNotFound)
		}
		return err
	})
	return version, sealed, err
}

func (r *SIEMRepository) GetSecret(ctx context.Context, sinkID shared.ID, version int64) (string, error) {
	var sealed string
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		err := tx.QueryRow(ctx, `SELECT ciphertext FROM siem_sink_secrets
			WHERE tenant_id=$1 AND sink_id=$2 AND version=$3`, tenant.String(), sinkID.String(), version).Scan(&sealed)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: siem secret", shared.ErrNotFound)
		}
		return err
	})
	return sealed, err
}

func (r *SIEMRepository) Claim(ctx context.Context, owner string, sink siem.Sink, source siem.Source, now time.Time, ttl time.Duration) (siem.Lease, error) {
	var lease siem.Lease
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		if sink.TenantID != tenant {
			return fmt.Errorf("%w: lease tenant mismatch", shared.ErrValidation)
		}
		lease = siem.Lease{SinkID: sink.ID, TenantID: tenant, Source: source, Owner: owner, Generation: sink.Generation, ExpiresAt: now.Add(ttl)}
		err := tx.QueryRow(ctx, `
			UPDATE siem_leases SET expires_at=$5
			WHERE tenant_id=current_setting('app.current_tenant', true) AND sink_id=$1 AND source=$2 AND owner=$3 AND generation=$4 AND expires_at > $6
			RETURNING token`, sink.ID.String(), string(source), owner, sink.Generation, lease.ExpiresAt, now).Scan(&lease.Token)
		if err == nil {
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		err = tx.QueryRow(ctx, `
			INSERT INTO siem_leases (tenant_id, sink_id, source, owner, token, generation, expires_at)
			VALUES ($1,$2,$3,$4,1,$5,$6)
			ON CONFLICT (tenant_id, sink_id, source) DO UPDATE
			SET owner=EXCLUDED.owner, token=siem_leases.token+1, generation=EXCLUDED.generation, expires_at=EXCLUDED.expires_at
			WHERE siem_leases.expires_at <= $7
			RETURNING token, expires_at`,
			tenant.String(), sink.ID.String(), string(source), owner, sink.Generation, lease.ExpiresAt, now).Scan(&lease.Token, &lease.ExpiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return siem.ErrStaleLease
		}
		if err != nil {
			return err
		}
		// An expired owner may have left a prepared batch. Adopt it under
		// this lease before any sender can read or mutate its items.
		_, err = tx.Exec(ctx, `UPDATE siem_batches SET lease_token=$4
			WHERE tenant_id=$1 AND sink_id=$2 AND source=$3 AND generation=$5
			AND state IN ('prepared','sending','partial','awaiting_ack','blocked')`,
			tenant.String(), sink.ID.String(), string(source), lease.Token, sink.Generation)
		return err
	})
	return lease, err
}

func (r *SIEMRepository) Release(ctx context.Context, lease siem.Lease) error {
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		// Preserve the token as a fencing sequence across clean releases.
		_, err := tx.Exec(ctx, `UPDATE siem_leases SET expires_at=now()
			WHERE tenant_id=$1 AND sink_id=$2 AND source=$3 AND owner=$4 AND token=$5`,
			lease.TenantID.String(), lease.SinkID.String(), string(lease.Source), lease.Owner, lease.Token)
		return err
	})
}

func (r *SIEMRepository) SaveBatch(ctx context.Context, batch siem.Batch, sealed []string) error {
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		if batch.TenantID != tenant {
			return fmt.Errorf("%w: batch tenant mismatch", shared.ErrValidation)
		}
		var token, generation int64
		err := tx.QueryRow(ctx, `SELECT l.token, s.generation FROM siem_leases l
			JOIN siem_sinks s ON s.tenant_id=l.tenant_id AND s.id=l.sink_id
			WHERE l.tenant_id=$1 AND l.sink_id=$2 AND l.source=$3 FOR UPDATE OF l`,
			batch.TenantID.String(), batch.SinkID.String(), string(batch.Source)).Scan(&token, &generation)
		if errors.Is(err, pgx.ErrNoRows) || token != batch.LeaseToken || generation != batch.Generation {
			return siem.ErrStaleLease
		}
		if err != nil {
			return err
		}
		var existing string
		err = tx.QueryRow(ctx, `SELECT state FROM siem_batches WHERE tenant_id=$1 AND id=$2`,
			batch.TenantID.String(), batch.ID.String()).Scan(&existing)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil && !siem.BatchState(existing).Open() {
			return siem.ErrStaleLease
		}
		return upsertBatch(ctx, tx, batch, sealed)
	})
}

func (r *SIEMRepository) OpenBatch(ctx context.Context, sinkID shared.ID, source siem.Source) (siem.Batch, []string, bool, error) {
	var batch siem.Batch
	var sealed []string
	found := false
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		var id string
		err := tx.QueryRow(ctx, `SELECT id FROM siem_batches WHERE tenant_id=current_setting('app.current_tenant', true) AND sink_id=$1 AND source=$2 AND state IN ('prepared','sending','partial','awaiting_ack','blocked')`, sinkID.String(), string(source)).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		batch, sealed, err = loadBatch(ctx, tx, id)
		found = err == nil
		return err
	})
	return batch, sealed, found, err
}

func (r *SIEMRepository) Checkpoint(ctx context.Context, sinkID shared.ID, source siem.Source) (siem.Checkpoint, bool, error) {
	var cp siem.Checkpoint
	found := false
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT generation, position, chain_head, updated_at FROM siem_checkpoints WHERE tenant_id=current_setting('app.current_tenant', true) AND sink_id=$1 AND source=$2`, sinkID.String(), string(source)).Scan(&cp.Generation, &raw, &cp.ChainHead, &cp.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		tenant, _ := shared.TenantFrom(ctx)
		cp.TenantID = tenant
		cp.SinkID = sinkID
		cp.Source = source
		cp.Position, err = decodePosition(raw)
		found = err == nil
		return err
	})
	return cp, found, err
}

func (r *SIEMRepository) Commit(ctx context.Context, lease siem.Lease, batch siem.Batch, checkpoint siem.Checkpoint, now time.Time) error {
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		if lease.TenantID != tenant || batch.TenantID != tenant || checkpoint.TenantID != tenant {
			return fmt.Errorf("%w: commit tenant mismatch", shared.ErrValidation)
		}
		var owner string
		var token, generation int64
		var expires time.Time
		err := tx.QueryRow(ctx, `SELECT owner, token, generation, expires_at FROM siem_leases WHERE tenant_id=current_setting('app.current_tenant', true) AND sink_id=$1 AND source=$2 FOR UPDATE`, lease.SinkID.String(), string(lease.Source)).Scan(&owner, &token, &generation, &expires)
		if errors.Is(err, pgx.ErrNoRows) {
			return siem.ErrStaleLease
		}
		if err != nil {
			return err
		}
		held := siem.Lease{SinkID: lease.SinkID, TenantID: lease.TenantID, Source: lease.Source, Owner: owner, Token: token, Generation: generation, ExpiresAt: expires}
		if err := held.Holds(lease.Owner, lease.Token, lease.Generation, now); err != nil {
			return err
		}
		if batch.LeaseToken != token || batch.Generation != generation {
			return siem.ErrStaleLease
		}
		var sinkGeneration int64
		if err := tx.QueryRow(ctx, `SELECT generation FROM siem_sinks WHERE tenant_id=$1 AND id=$2 FOR UPDATE`,
			lease.TenantID.String(), lease.SinkID.String()).Scan(&sinkGeneration); err != nil {
			return err
		}
		if sinkGeneration != generation || checkpoint.Generation != generation {
			return siem.ErrStaleLease
		}
		var currentGeneration int64
		var currentRaw []byte
		err = tx.QueryRow(ctx, `SELECT generation, position FROM siem_checkpoints
			WHERE tenant_id=$1 AND sink_id=$2 AND source=$3 FOR UPDATE`,
			lease.TenantID.String(), lease.SinkID.String(), string(lease.Source)).Scan(&currentGeneration, &currentRaw)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil {
			currentPosition, err := decodePosition(currentRaw)
			if err != nil {
				return err
			}
			if currentGeneration != generation || siemPositionRegresses(checkpoint.Position, currentPosition) {
				return siem.ErrStaleLease
			}
		}
		if err := upsertBatch(ctx, tx, batch, nil); err != nil {
			return err
		}
		raw, err := json.Marshal(checkpoint.Position)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO siem_checkpoints (tenant_id, sink_id, source, generation, position, chain_head, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (tenant_id, sink_id, source) DO UPDATE
			SET generation=EXCLUDED.generation, position=EXCLUDED.position, chain_head=EXCLUDED.chain_head, updated_at=EXCLUDED.updated_at`,
			tenant.String(), checkpoint.SinkID.String(), string(checkpoint.Source), checkpoint.Generation, raw, checkpoint.ChainHead, checkpoint.UpdatedAt)
		return err
	})
}

func siemPositionRegresses(next, current siem.Position) bool {
	if current.Source == siem.SourceAudit {
		return next.AuditID < current.AuditID
	}
	return next.StreamSeq < current.StreamSeq
}

func (r *SIEMRepository) ResetPartition(ctx context.Context, sink siem.Sink, source siem.Source, checkpoint siem.Checkpoint) error {
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		if sink.TenantID != tenant || checkpoint.TenantID != tenant {
			return fmt.Errorf("%w: reset tenant mismatch", shared.ErrValidation)
		}
		if err := lockSIEMRetention(ctx, tx, tenant); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE siem_leases SET token=token+1, expires_at=now()
			WHERE tenant_id=$1 AND sink_id=$2 AND source=$3`, sink.TenantID.String(), sink.ID.String(), string(source)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE siem_batch_items SET sealed_payload='' WHERE tenant_id=current_setting('app.current_tenant', true) AND batch_id IN (SELECT id FROM siem_batches WHERE tenant_id=current_setting('app.current_tenant', true) AND sink_id=$1 AND source=$2 AND state IN ('prepared','sending','partial','awaiting_ack','blocked'))`, sink.ID.String(), string(source)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE siem_batches SET state='invalidated', updated_at=$3 WHERE tenant_id=current_setting('app.current_tenant', true) AND sink_id=$1 AND source=$2 AND state IN ('prepared','sending','partial','awaiting_ack','blocked')`, sink.ID.String(), string(source), time.Now().UTC()); err != nil {
			return err
		}
		raw, err := json.Marshal(checkpoint.Position)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO siem_checkpoints (tenant_id, sink_id, source, generation, position, chain_head, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (tenant_id, sink_id, source) DO UPDATE
			SET generation=EXCLUDED.generation, position=EXCLUDED.position, chain_head=EXCLUDED.chain_head, updated_at=EXCLUDED.updated_at`,
			tenant.String(), sink.ID.String(), string(source), checkpoint.Generation, raw, checkpoint.ChainHead, checkpoint.UpdatedAt)
		return err
	})
}

func (r *SIEMRepository) Prune(ctx context.Context, before time.Time) error {
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		if err := lockSIEMRetention(ctx, tx, tenant); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			WITH expired AS (
				SELECT i.tenant_id, i.batch_id, i.ordinal
				FROM siem_batch_items i JOIN siem_batches b
				  ON b.tenant_id=i.tenant_id AND b.id=i.batch_id
				WHERE b.state='acked' AND b.updated_at < $1 AND i.sealed_payload <> ''
				LIMIT 1000
			)
			UPDATE siem_batch_items i SET sealed_payload=''
			FROM expired e WHERE i.tenant_id=e.tenant_id AND i.batch_id=e.batch_id AND i.ordinal=e.ordinal`, before)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `WITH expired AS (
			SELECT s.tenant_id, s.sink_id, s.version
			FROM siem_sink_secrets s JOIN siem_sinks k
			  ON k.tenant_id=s.tenant_id AND k.id=s.sink_id
			WHERE s.version < k.secret_version AND s.created_at < $1
			LIMIT 100
		)
		DELETE FROM siem_sink_secrets s USING expired e
		WHERE s.tenant_id=e.tenant_id AND s.sink_id=e.sink_id AND s.version=e.version`, before)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id FROM siem_batches WHERE tenant_id=$1
			AND state IN ('acked','invalidated') AND updated_at < $2
			ORDER BY updated_at LIMIT 100 FOR UPDATE SKIP LOCKED`, tenant.String(), before)
		if err != nil {
			return err
		}
		var expiredBatches []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			expiredBatches = append(expiredBatches, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(expiredBatches) > 0 {
			if _, err := tx.Exec(ctx, `DELETE FROM siem_batch_items WHERE tenant_id=$1 AND batch_id=ANY($2)`, tenant.String(), expiredBatches); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM siem_batches WHERE tenant_id=$1 AND id=ANY($2)`, tenant.String(), expiredBatches); err != nil {
				return err
			}
		}
		for _, partition := range []struct {
			source siem.Source
			phase  siem.Phase
		}{{siem.SourceIncidentLive, siem.PhaseLive}, {siem.SourceIncidentHistorical, siem.PhaseHistorical}} {
			var floor *int64
			err := tx.QueryRow(ctx, `SELECT min(COALESCE((c.position->>'StreamSeq')::bigint, 0))
				FROM siem_sinks s LEFT JOIN siem_checkpoints c
				ON c.tenant_id=s.tenant_id AND c.sink_id=s.id AND c.source=$2
				WHERE s.tenant_id=$1`, tenant.String(), string(partition.source)).Scan(&floor)
			if err != nil {
				return err
			}
			if floor == nil || *floor <= 1 {
				continue
			}
			// Keep the floor row as an anchor for future sinks; their first
			// checkpoint is seeded from it in CreateSink. Tombstones stop
			// historical backfill from assigning a new sequence to a pruned identity.
			_, err = tx.Exec(ctx, `WITH doomed AS (
				SELECT tenant_id, incident_id, event_seq, phase, stream_seq
				FROM siem_incident_capture
				WHERE tenant_id=$1 AND phase=$2 AND stream_seq < $3 AND occurred_at < $4
				ORDER BY stream_seq
				LIMIT 1000
			), marked AS (
				INSERT INTO siem_incident_pruned (tenant_id, incident_id, event_seq, pruned_at)
				SELECT tenant_id, incident_id, event_seq, $4 FROM doomed
				ON CONFLICT (tenant_id, incident_id, event_seq) DO NOTHING
			)
			DELETE FROM siem_incident_capture c
			USING doomed d
			WHERE c.tenant_id=d.tenant_id AND c.phase=d.phase AND c.stream_seq=d.stream_seq`,
				tenant.String(), string(partition.phase), *floor, before)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *SIEMRepository) AggregateBacklog(ctx context.Context) (map[siem.Source]siem.BacklogAggregate, error) {
	result := map[siem.Source]siem.BacklogAggregate{}
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		for _, source := range []siem.Source{siem.SourceAudit, siem.SourceIncidentLive, siem.SourceIncidentHistorical} {
			var records int64
			var oldest *time.Time
			var err error
			if source == siem.SourceAudit {
				err = tx.QueryRow(ctx, `SELECT COALESCE(sum(lag.n),0)::bigint, min(lag.oldest)
					FROM siem_sinks s LEFT JOIN siem_checkpoints c
					  ON c.tenant_id=s.tenant_id AND c.sink_id=s.id AND c.source=$2
					CROSS JOIN LATERAL (
					  SELECT count(*) n, min(a.created_at) oldest FROM audit_log a
					  WHERE a.tenant_id=s.tenant_id AND a.hash_version=2 AND a.hash IS NOT NULL
					    AND a.id > COALESCE((c.position->>'AuditID')::bigint,0)
					) lag WHERE s.tenant_id=$1 AND s.enabled`, tenant.String(), string(source)).Scan(&records, &oldest)
			} else {
				phase := siem.PhaseLive
				if source == siem.SourceIncidentHistorical {
					phase = siem.PhaseHistorical
				}
				err = tx.QueryRow(ctx, `SELECT COALESCE(sum(lag.n),0)::bigint, min(lag.oldest)
					FROM siem_sinks s LEFT JOIN siem_checkpoints c
					  ON c.tenant_id=s.tenant_id AND c.sink_id=s.id AND c.source=$2
					CROSS JOIN LATERAL (
					  SELECT count(*) n, min(i.occurred_at) oldest FROM siem_incident_capture i
					  WHERE i.tenant_id=s.tenant_id AND i.phase=$3
					    AND i.stream_seq > COALESCE((c.position->>'StreamSeq')::bigint,0)
					) lag WHERE s.tenant_id=$1 AND s.enabled`, tenant.String(), string(source), string(phase)).Scan(&records, &oldest)
			}
			if err != nil {
				return err
			}
			value := siem.BacklogAggregate{Records: int(records)}
			if oldest != nil {
				value.OldestUnixMicro = oldest.UTC().UnixMicro()
			}
			result[source] = value
		}
		return nil
	})
	return result, err
}

func (r *SIEMRepository) ReadAudit(ctx context.Context, afterID int64, limit int) ([]siem.AuditFact, []map[string]string, siem.AuditAnchor, error) {
	if limit <= 0 || limit > siem.MaxBatchRecords {
		limit = siem.MaxBatchRecords
	}
	var facts []siem.AuditFact
	var metas []map[string]string
	var anchor siem.AuditAnchor
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		if afterID > 0 {
			var hash string
			err := tx.QueryRow(ctx, `SELECT hash FROM audit_log WHERE tenant_id=current_setting('app.current_tenant', true) AND id=$1 AND hash_version=2 AND hash IS NOT NULL`, afterID).Scan(&hash)
			if err == nil {
				anchor.CursorFound = true
				anchor.CursorID = afterID
				anchor.CursorHash = hash
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		err := tx.QueryRow(ctx, `SELECT id, hash FROM audit_log WHERE tenant_id=current_setting('app.current_tenant', true) AND hash_version=2 AND hash IS NOT NULL ORDER BY id DESC LIMIT 1`).Scan(&anchor.HeadID, &anchor.HeadHash)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT id, actor, action, target, metadata, created_at, hash, previous_hash, hash_version
			FROM audit_log
			WHERE tenant_id=current_setting('app.current_tenant', true) AND hash_version=2 AND hash IS NOT NULL AND id > $1
			ORDER BY id ASC LIMIT $2`, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var fact siem.AuditFact
			var metaRaw []byte
			var at time.Time
			var prev *string
			if err := rows.Scan(&fact.ID, &fact.Actor, &fact.Action, &fact.Target, &metaRaw, &at, &fact.Hash, &prev, &fact.HashVersion); err != nil {
				return err
			}
			if prev != nil {
				fact.PreviousHash = *prev
			}
			fact.AtUnixMicro = at.UTC().Truncate(time.Microsecond).UnixMicro()
			meta := map[string]string{}
			if len(metaRaw) > 0 {
				if err := json.Unmarshal(metaRaw, &meta); err != nil {
					return err
				}
			}
			fact = siem.AuditWithMetadata(fact, meta)
			facts = append(facts, fact)
			metas = append(metas, meta)
		}
		return rows.Err()
	})
	return facts, metas, anchor, err
}

func (r *SIEMRepository) CountAudit(ctx context.Context, afterID int64) (int, int64, error) {
	var count int
	var oldest *time.Time
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*), min(created_at) FROM audit_log WHERE tenant_id=current_setting('app.current_tenant', true) AND hash_version=2 AND hash IS NOT NULL AND id > $1`, afterID).Scan(&count, &oldest)
	})
	if oldest == nil {
		return count, 0, err
	}
	return count, oldest.UTC().UnixMicro(), err
}

func (r *SIEMRepository) ReadIncident(ctx context.Context, phase siem.Phase, afterSeq int64, limit int) ([]siem.IncidentFact, error) {
	if limit <= 0 || limit > siem.MaxBatchRecords {
		limit = siem.MaxBatchRecords
	}
	var out []siem.IncidentFact
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT c.stream_seq, c.phase, c.incident_id, c.event_seq, e.kind, e.occurred_at, e.actor, e.asset_id, e.payload
			FROM siem_incident_capture c
			JOIN incident_events e ON e.tenant_id = c.tenant_id AND e.incident_id = c.incident_id AND e.seq = c.event_seq
			WHERE c.tenant_id=current_setting('app.current_tenant', true) AND c.phase=$1 AND c.stream_seq > $2
			ORDER BY c.stream_seq ASC LIMIT $3`, string(phase), afterSeq, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var fact siem.IncidentFact
			var at time.Time
			var payload []byte
			var phaseText string
			if err := rows.Scan(&fact.StreamSeq, &phaseText, &fact.IncidentID, &fact.EventSeq, &fact.Kind, &at, &fact.Actor, &fact.AssetID, &payload); err != nil {
				return err
			}
			fact.Phase = siem.Phase(phaseText)
			fact.AtUnixMicro = at.UTC().UnixMicro()
			var event incident.IncidentEvent
			if json.Unmarshal(payload, &event) == nil {
				fact.Title = event.Title
				fact.Severity = string(event.Severity)
				fact.ToStatus = string(event.To)
				fact.Owner = event.Owner
				fact.Comment = event.Comment
				fact.EngagementID = event.EngagementID.String()
				fact.DetectionID = event.DetectionID.String()
			}
			out = append(out, fact)
		}
		return rows.Err()
	})
	return out, err
}

func (r *SIEMRepository) HeadIncident(ctx context.Context, phase siem.Phase) (siem.IncidentFact, bool, error) {
	var fact siem.IncidentFact
	found := false
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		err := tx.QueryRow(ctx, `SELECT stream_seq, incident_id, event_seq FROM siem_incident_capture
			WHERE tenant_id=$1 AND phase=$2 ORDER BY stream_seq DESC LIMIT 1`, tenant.String(), string(phase)).Scan(
			&fact.StreamSeq, &fact.IncidentID, &fact.EventSeq)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err == nil {
			fact.Phase = phase
			found = true
		}
		return err
	})
	return fact, found, err
}

func (r *SIEMRepository) CountIncident(ctx context.Context, phase siem.Phase, afterSeq int64) (int, int64, error) {
	var count int
	var oldest *time.Time
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*), min(occurred_at) FROM siem_incident_capture WHERE tenant_id=current_setting('app.current_tenant', true) AND phase=$1 AND stream_seq > $2`, string(phase), afterSeq).Scan(&count, &oldest)
	})
	if oldest == nil {
		return count, 0, err
	}
	return count, oldest.UTC().UnixMicro(), err
}

func (r *SIEMRepository) BackfillIncidents(ctx context.Context, limit int) (int, error) {
	if limit <= 0 || limit > siem.MaxBatchRecords {
		limit = siem.MaxBatchRecords
	}
	written := 0
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		if err := lockSIEMRetention(ctx, tx, tenant); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT e.incident_id, e.seq, e.occurred_at
			FROM incident_events e
			WHERE e.tenant_id=current_setting('app.current_tenant', true)
			  AND NOT EXISTS (
				SELECT 1 FROM siem_incident_capture c
				WHERE c.tenant_id = e.tenant_id AND c.incident_id = e.incident_id AND c.event_seq = e.seq
			  )
			  AND NOT EXISTS (
				SELECT 1 FROM siem_incident_pruned p
				WHERE p.tenant_id = e.tenant_id AND p.incident_id = e.incident_id AND p.event_seq = e.seq
			  )
			ORDER BY e.incident_id COLLATE "C", e.seq
			LIMIT $1`, limit)
		if err != nil {
			return err
		}
		type missing struct {
			id   string
			seq  int
			when time.Time
		}
		var page []missing
		for rows.Next() {
			var row missing
			if err := rows.Scan(&row.id, &row.seq, &row.when); err != nil {
				rows.Close()
				return err
			}
			page = append(page, row)
		}
		rows.Close()
		if err := rows.Err(); err != nil || len(page) == 0 {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO siem_incident_counters (tenant_id) VALUES ($1) ON CONFLICT (tenant_id) DO NOTHING`, tenant.String()); err != nil {
			return err
		}
		var next int64
		if err := tx.QueryRow(ctx, `SELECT hist_next FROM siem_incident_counters WHERE tenant_id=$1 FOR UPDATE`, tenant.String()).Scan(&next); err != nil {
			return err
		}
		for _, row := range page {
			tag, err := tx.Exec(ctx, `
				INSERT INTO siem_incident_capture (tenant_id, phase, stream_seq, incident_id, event_seq, occurred_at)
				VALUES ($1,'historical',$2,$3,$4,$5)
				ON CONFLICT (tenant_id, incident_id, event_seq) DO NOTHING`,
				tenant.String(), next, row.id, row.seq, row.when)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 1 {
				next++
				written++
			}
		}
		_, err = tx.Exec(ctx, `UPDATE siem_incident_counters SET hist_next=$2 WHERE tenant_id=$1`, tenant.String(), next)
		return err
	})
	return written, err
}

func (r *SIEMRepository) TenantIDs(ctx context.Context) ([]shared.ID, error) {
	// Migration 0002 seeded a tenants row with an empty id for the original single-tenant mode and
	// every install still carries it. Nothing can be exported for it: WithTenant maps an empty id to
	// NULL, which RLS denies. Returned here it would cost the SIEM tick an RLS-denied round trip per
	// pass, which is the reconciler noise 0129 and the other seven listings already removed.
	rows, err := r.pool.Query(ctx, `SELECT id FROM tenants WHERE id <> '' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, shared.ID(id))
	}
	return out, rows.Err()
}

const sinkSelect = `
	SELECT tenant_id, id, name, provider, origin, target, data_class, ack_mode, indexer_ack, allow_hosts,
		paused, enabled, generation, secret_version, version, channel, blocked_reason, created_at, updated_at
	FROM siem_sinks`

type sinkScanner interface {
	Scan(dest ...any) error
}

func scanSink(row sinkScanner) (siem.Sink, error) {
	var sink siem.Sink
	var tenant, id, provider, class, ack string
	err := row.Scan(&tenant, &id, &sink.Name, &provider, &sink.Origin, &sink.Target, &class, &ack, &sink.IndexerAckSupported,
		&sink.AllowHosts, &sink.Paused, &sink.Enabled, &sink.Generation, &sink.SecretVersion, &sink.Version, &sink.Channel,
		&sink.BlockedReason, &sink.CreatedAt, &sink.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return siem.Sink{}, fmt.Errorf("%w: siem sink", shared.ErrNotFound)
	}
	if err != nil {
		return siem.Sink{}, err
	}
	sink.TenantID = shared.ID(tenant)
	sink.ID = shared.ID(id)
	sink.Provider = siem.Provider(provider)
	sink.DataClass = siem.DataClass(class)
	sink.AckMode = siem.AckMode(ack)
	return sink, nil
}

func upsertBatch(ctx context.Context, tx pgx.Tx, batch siem.Batch, sealed []string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO siem_batches (
			tenant_id, id, sink_id, source, generation, lease_token, state, policy_version, mapping_version,
			chain_head, diagnostic, attempt, next_attempt_at, indexer_ack_id, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (tenant_id, id) DO UPDATE SET
			state=EXCLUDED.state, lease_token=EXCLUDED.lease_token, chain_head=EXCLUDED.chain_head,
			diagnostic=EXCLUDED.diagnostic, attempt=EXCLUDED.attempt, next_attempt_at=EXCLUDED.next_attempt_at,
			indexer_ack_id=EXCLUDED.indexer_ack_id,
			updated_at=EXCLUDED.updated_at`,
		batch.TenantID.String(), batch.ID.String(), batch.SinkID.String(), string(batch.Source), batch.Generation,
		batch.LeaseToken, string(batch.State), batch.PolicyVersion, batch.MappingVersion, batch.ChainHead,
		batch.Diagnostic, batch.Attempt, nullTime(batch.NextAttemptAt), batch.IndexerAckID, batch.CreatedAt, batch.UpdatedAt)
	if err != nil {
		return siemWriteErr("save batch", err)
	}
	if sealed == nil {
		rows, err := tx.Query(ctx, `SELECT ordinal, sealed_payload FROM siem_batch_items WHERE tenant_id=current_setting('app.current_tenant', true) AND batch_id=$1 ORDER BY ordinal`, batch.ID.String())
		if err != nil {
			return err
		}
		kept := map[int]string{}
		for rows.Next() {
			var ordinal int
			var payload string
			if err := rows.Scan(&ordinal, &payload); err != nil {
				rows.Close()
				return err
			}
			kept[ordinal] = payload
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		sealed = make([]string, len(batch.Items))
		for i, item := range batch.Items {
			sealed[i] = kept[item.Ordinal]
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM siem_batch_items WHERE tenant_id=current_setting('app.current_tenant', true) AND batch_id=$1`, batch.ID.String()); err != nil {
		return err
	}
	for i, item := range batch.Items {
		raw, err := json.Marshal(item.Position)
		if err != nil {
			return err
		}
		payload := ""
		if i < len(sealed) {
			payload = sealed[i]
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO siem_batch_items (
				tenant_id, batch_id, ordinal, record_id, position, disposition, payload_digest, mapping,
				data_class, engagement_id, safe_reason, sealed_payload
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			batch.TenantID.String(), batch.ID.String(), item.Ordinal, item.RecordID, raw, string(item.Disposition),
			item.PayloadDigest, item.Mapping, string(item.DataClass), item.EngagementID, item.SafeReason, payload); err != nil {
			return err
		}
	}
	return nil
}

func loadBatch(ctx context.Context, tx pgx.Tx, id string) (siem.Batch, []string, error) {
	var batch siem.Batch
	var tenant, sink, source, state string
	var next *time.Time
	err := tx.QueryRow(ctx, `
		SELECT tenant_id, id, sink_id, source, generation, lease_token, state, policy_version, mapping_version,
			chain_head, diagnostic, attempt, next_attempt_at, indexer_ack_id, created_at, updated_at
		FROM siem_batches WHERE tenant_id=current_setting('app.current_tenant', true) AND id=$1`, id).Scan(&tenant, &batch.ID, &sink, &source, &batch.Generation, &batch.LeaseToken,
		&state, &batch.PolicyVersion, &batch.MappingVersion, &batch.ChainHead, &batch.Diagnostic, &batch.Attempt, &next, &batch.IndexerAckID,
		&batch.CreatedAt, &batch.UpdatedAt)
	if err != nil {
		return siem.Batch{}, nil, err
	}
	batch.TenantID = shared.ID(tenant)
	batch.SinkID = shared.ID(sink)
	batch.Source = siem.Source(source)
	batch.State = siem.BatchState(state)
	if next != nil {
		batch.NextAttemptAt = *next
	}
	rows, err := tx.Query(ctx, `
		SELECT ordinal, record_id, position, disposition, payload_digest, mapping, data_class, engagement_id, safe_reason, sealed_payload
		FROM siem_batch_items WHERE tenant_id=current_setting('app.current_tenant', true) AND batch_id=$1 ORDER BY ordinal`, id)
	if err != nil {
		return siem.Batch{}, nil, err
	}
	defer rows.Close()
	var sealed []string
	for rows.Next() {
		var item siem.BatchItem
		var raw []byte
		var disposition, class, payload string
		if err := rows.Scan(&item.Ordinal, &item.RecordID, &raw, &disposition, &item.PayloadDigest, &item.Mapping, &class, &item.EngagementID, &item.SafeReason, &payload); err != nil {
			return siem.Batch{}, nil, err
		}
		item.Disposition = siem.ItemDisposition(disposition)
		item.DataClass = siem.DataClass(class)
		item.Position, err = decodePosition(raw)
		if err != nil {
			return siem.Batch{}, nil, err
		}
		batch.Items = append(batch.Items, item)
		sealed = append(sealed, payload)
	}
	return batch, sealed, rows.Err()
}

func decodePosition(raw []byte) (siem.Position, error) {
	var position siem.Position
	if len(raw) == 0 {
		return position, nil
	}
	err := json.Unmarshal(raw, &position)
	return position, err
}

func nullTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func nonNilHosts(hosts []string) []string {
	if hosts == nil {
		return []string{}
	}
	return hosts
}

func lockSIEMRetention(ctx context.Context, tx pgx.Tx, tenant shared.ID) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1484, hashtext($1))`, tenant.String())
	return err
}

func siemWriteErr(action string, err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return fmt.Errorf("%w: %s", shared.ErrConflict, action)
	}
	return fmt.Errorf("%s: %w", action, err)
}
