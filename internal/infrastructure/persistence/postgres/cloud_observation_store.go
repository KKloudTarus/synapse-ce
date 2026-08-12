package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// CloudObservationStore atomically replaces producer ownership only after a complete target snapshot.
type CloudObservationStore struct{ pool *pgxpool.Pool }

var _ ports.CloudObservationStore = (*CloudObservationStore)(nil)

func NewCloudObservationStore(pool *pgxpool.Pool) *CloudObservationStore {
	return &CloudObservationStore{pool: pool}
}

func idsToStrings(ids []shared.ID) []string {
	out := make([]string, len(ids))
	for i := range ids {
		out[i] = ids[i].String()
	}
	return out
}

func (s *CloudObservationStore) ReconcileCloudObservations(ctx context.Context, tenantID, engagementID shared.ID, producer string, evidenceID shared.ID, assets, findings []shared.ID, edges []string, complete bool) error {
	return WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		if complete {
			if _, err := tx.Exec(ctx, `UPDATE cspm_observations SET active=false WHERE tenant_id=$1 AND engagement_id=$2 AND producer=$3`, tenantID.String(), engagementID.String(), producer); err != nil {
				return err
			}
		}
		for _, pair := range []struct {
			kind string
			ids  []string
		}{{"asset", idsToStrings(assets)}, {"finding", idsToStrings(findings)}, {"edge", edges}} {
			for _, id := range pair.ids {
				if _, err := tx.Exec(ctx, `INSERT INTO cspm_observations (tenant_id,engagement_id,producer,observation_kind,object_id,evidence_id,active,last_seen_at)
					VALUES ($1,$2,$3,$4,$5,$6,true,now())
					ON CONFLICT (tenant_id,engagement_id,producer,observation_kind,object_id)
					DO UPDATE SET evidence_id=EXCLUDED.evidence_id,active=true,last_seen_at=now()`, tenantID.String(), engagementID.String(), producer, pair.kind, id, evidenceID.String()); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
