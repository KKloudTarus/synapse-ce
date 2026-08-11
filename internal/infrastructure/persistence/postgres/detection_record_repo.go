package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// DetectionRecordRepository persists the detection-ledger projection (migration 0074), tenant-scoped via
// WithTenant so RLS isolates one tenant's detections from another's. The evidence-chain link each row
// references is the permanent ledger; these rows are the queryable, retention-bounded projection.
type DetectionRecordRepository struct{ pool *pgxpool.Pool }

var _ ports.DetectionRecordStore = (*DetectionRecordRepository)(nil)

// NewDetectionRecordRepository constructs the repository.
func NewDetectionRecordRepository(pool *pgxpool.Pool) *DetectionRecordRepository {
	return &DetectionRecordRepository{pool: pool}
}

// AppendDetection stores one projection row, idempotent on (tenant_id, id): a row is immutable once
// written (provenance), so a re-delivery of the same detection does not overwrite it.
func (r *DetectionRecordRepository) AppendDetection(ctx context.Context, rec detection.Record) error {
	if err := rec.Validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(rec.Detection)
	if err != nil {
		return fmt.Errorf("marshal detection %s: %w", rec.ID, err)
	}
	var expires *time.Time
	if !rec.ExpiresAt.IsZero() {
		e := rec.ExpiresAt.UTC()
		expires = &e
	}
	return WithTenant(ctx, r.pool, rec.TenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO detections
			  (tenant_id, id, engagement_id, asset_id, agent_id, rule_id, rule_version, class, severity,
			   host_id, observed_at, evidence_id, batch_seq, detection, recorded_at, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
			ON CONFLICT (tenant_id, id) DO NOTHING`,
			rec.TenantID.String(), rec.ID.String(), rec.EngagementID.String(), rec.AssetID.String(),
			rec.AgentID.String(), rec.Detection.RuleID, rec.Detection.RuleVersion, string(rec.Detection.Class),
			string(rec.Detection.Severity), rec.Detection.HostID.String(), rec.Detection.Observed.UTC(),
			rec.EvidenceID.String(), int64(rec.BatchSeq), payload, rec.RecordedAt.UTC(), expires)
		if err != nil {
			return fmt.Errorf("insert detection %s: %w", rec.ID, err)
		}
		return nil
	})
}

// ListDetections returns the non-expired records for an engagement, oldest first, tenant-scoped by RLS.
func (r *DetectionRecordRepository) ListDetections(ctx context.Context, engagementID shared.ID) ([]detection.Record, error) {
	var out []detection.Record
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT tenant_id, id, engagement_id, asset_id, agent_id, evidence_id, batch_seq, detection,
			       recorded_at, expires_at
			FROM detections
			WHERE engagement_id = $1 AND (expires_at IS NULL OR expires_at > now())
			ORDER BY recorded_at ASC, id ASC`, engagementID.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				rec      detection.Record
				tenant   string
				id       string
				eng      string
				asset    string
				agent    string
				evID     string
				batchSeq int64
				payload  []byte
				recorded time.Time
				expires  *time.Time
			)
			if err := rows.Scan(&tenant, &id, &eng, &asset, &agent, &evID, &batchSeq, &payload, &recorded, &expires); err != nil {
				return err
			}
			var d detection.Detection
			if err := json.Unmarshal(payload, &d); err != nil {
				return fmt.Errorf("unmarshal detection %s: %w", id, err)
			}
			rec = detection.Record{
				ID: shared.ID(id), TenantID: shared.ID(tenant), EngagementID: shared.ID(eng),
				AssetID: shared.ID(asset), AgentID: shared.ID(agent), Detection: d, EvidenceID: shared.ID(evID),
				BatchSeq: uint64(batchSeq), RecordedAt: recorded,
			}
			if expires != nil {
				rec.ExpiresAt = *expires
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}

// HasDetection reports whether a record with this id already exists in the ctx tenant.
func (r *DetectionRecordRepository) HasDetection(ctx context.Context, id shared.ID) (bool, error) {
	var exists bool
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM detections WHERE id = $1)`, id.String()).Scan(&exists)
	})
	return exists, err
}

// LastBatchSequence returns the highest batch sequence for an agent in the ctx tenant (0 = none yet).
func (r *DetectionRecordRepository) LastBatchSequence(ctx context.Context, agentID shared.ID) (uint64, error) {
	var last int64
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COALESCE(max(batch_seq), 0) FROM detections WHERE agent_id = $1`, agentID.String()).Scan(&last)
	})
	if err != nil {
		return 0, err
	}
	return uint64(last), nil
}

// ExpireDetections deletes the engagement's records whose expiry has elapsed at cutoff and returns their
// ids for auditing. Rows with a NULL expires_at are never removed. Deleting a projection row leaves its
// evidence-chain link intact — the ledger is permanent, only the queryable projection ages out.
func (r *DetectionRecordRepository) ExpireDetections(ctx context.Context, engagementID shared.ID, cutoff time.Time) ([]shared.ID, error) {
	var ids []shared.ID
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			DELETE FROM detections
			WHERE engagement_id = $1 AND expires_at IS NOT NULL AND expires_at <= $2
			RETURNING id`, engagementID.String(), cutoff.UTC())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, shared.ID(id))
		}
		return rows.Err()
	})
	return ids, err
}
