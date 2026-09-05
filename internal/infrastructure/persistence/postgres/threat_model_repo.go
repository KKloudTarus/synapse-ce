package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/threatmodel"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ThreatModelRepository persists the architecture-input threat model per engagement to
// PostgreSQL: one row per engagement, the validated domain model stored as a JSONB blob.
// threat_models is RLS-protected (migration 0129): both statements run inside a WithTenant
// transaction and carry their own tenant_id predicate, so a read can no longer reach another
// tenant's engagement id even if the upstream route gate is bypassed.
type ThreatModelRepository struct{ pool *pgxpool.Pool }

// NewThreatModelRepository returns a repository backed by the given pool.
func NewThreatModelRepository(pool *pgxpool.Pool) *ThreatModelRepository {
	return &ThreatModelRepository{pool: pool}
}

var _ ports.ThreatModelStore = (*ThreatModelRepository)(nil)

// Save upserts the engagement's model (the usecase has already bounded size + validated it), bumping version
// on each re-ingest. The model round-trips through the JSONB `data` blob.
func (r *ThreatModelRepository) Save(ctx context.Context, engagementID, tenantID shared.ID, m threatmodel.Model) error {
	blob, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal threat model: %w", err)
	}
	return requireTenant(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		// engagement_id is globally unique, so an ON CONFLICT that lands on a row owned by another
		// tenant is a cross-tenant write attempt. The guarded WHERE turns it into zero rows, which
		// is reported as a conflict rather than silently swallowed.
		tag, err := tx.Exec(ctx,
			`INSERT INTO threat_models (engagement_id, tenant_id, data, version, created_at, updated_at)
			 VALUES ($1, $2, $3, 1, now(), now())
			 ON CONFLICT (engagement_id) DO UPDATE SET data = EXCLUDED.data, version = threat_models.version + 1, updated_at = now()
			 WHERE threat_models.tenant_id = $2`,
			engagementID.String(), tenantID.String(), blob)
		if err != nil {
			return fmt.Errorf("save threat model: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("threat model for engagement %s belongs to another tenant: %w", engagementID, shared.ErrConflict)
		}
		return nil
	})
}

// Get decodes the engagement's model from its JSONB blob; ok=false when none has been ingested.
// The port carries no tenant argument, so the read runs under the ambient tenant bound to ctx;
// a context without one is a validation error, never a cross-tenant read.
func (r *ThreatModelRepository) Get(ctx context.Context, engagementID shared.ID) (threatmodel.Model, bool, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return threatmodel.Model{}, false, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	var m threatmodel.Model
	found := false
	err := requireTenant(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		var blob []byte
		err := tx.QueryRow(ctx, `SELECT data FROM threat_models WHERE tenant_id = $1 AND engagement_id = $2`, tenantID.String(), engagementID.String()).Scan(&blob)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("get threat model: %w", err)
		}
		if err := json.Unmarshal(blob, &m); err != nil {
			return fmt.Errorf("decode threat model: %w", err)
		}
		found = true
		return nil
	})
	if err != nil {
		return threatmodel.Model{}, false, err
	}
	return m, found, nil
}
