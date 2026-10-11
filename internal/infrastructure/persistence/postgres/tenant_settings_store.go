package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
)

// TenantSettingsStore is the PostgreSQL ports.TenantSettingsStore over tenant_settings (0191). Every
// statement runs inside WithTenant, so forced RLS confines it to the caller's tenant row.
type TenantSettingsStore struct{ pool *pgxpool.Pool }

// NewTenantSettingsStore returns a store over pool.
func NewTenantSettingsStore(pool *pgxpool.Pool) *TenantSettingsStore {
	return &TenantSettingsStore{pool: pool}
}

func (s *TenantSettingsStore) GetTenantSettings(ctx context.Context, tenant shared.ID) (tenancy.Settings, bool, error) {
	out := tenancy.Settings{TenantID: tenant}
	found := false
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		var locale string
		err := tx.QueryRow(ctx, `SELECT default_locale, time_zone, revision, updated_at, updated_by
			FROM tenant_settings WHERE tenant_id=$1`, tenant).
			Scan(&locale, &out.TimeZone, &out.Revision, &out.UpdatedAt, &out.UpdatedBy)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out.DefaultLocale = tenancy.Locale(locale)
		found = true
		return nil
	})
	if err != nil {
		return tenancy.Settings{}, false, fmt.Errorf("read tenant settings: %w", err)
	}
	if !found {
		return tenancy.Settings{}, false, nil
	}
	return out, true, nil
}

func (s *TenantSettingsStore) SaveTenantSettings(ctx context.Context, next tenancy.Settings, expectedRevision int) (tenancy.Settings, error) {
	err := WithTenant(ctx, s.pool, next.TenantID.String(), func(tx pgx.Tx) error {
		var err error
		if expectedRevision == 0 {
			err = tx.QueryRow(ctx, `INSERT INTO tenant_settings(tenant_id, default_locale, time_zone, revision, updated_at, updated_by)
				VALUES($1, $2, $3, 1, $4, $5) ON CONFLICT (tenant_id) DO NOTHING RETURNING revision`,
				next.TenantID, string(next.DefaultLocale), next.TimeZone, next.UpdatedAt, next.UpdatedBy).Scan(&next.Revision)
		} else {
			err = tx.QueryRow(ctx, `UPDATE tenant_settings
				SET default_locale=$2, time_zone=$3, revision=revision+1, updated_at=$4, updated_by=$5
				WHERE tenant_id=$1 AND revision=$6 RETURNING revision`,
				next.TenantID, string(next.DefaultLocale), next.TimeZone, next.UpdatedAt, next.UpdatedBy, expectedRevision).Scan(&next.Revision)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: tenant settings revision is stale", shared.ErrConflict)
		}
		return err
	})
	if err != nil {
		return tenancy.Settings{}, err
	}
	return next, nil
}
