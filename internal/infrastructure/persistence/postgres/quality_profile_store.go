package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/qualityprofile"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// QualityProfileStore persists tenant-scoped custom quality profiles. Built-in profiles are generated
// from the rule catalog and never stored here.
type QualityProfileStore struct{ pool *pgxpool.Pool }

func NewQualityProfileStore(pool *pgxpool.Pool) *QualityProfileStore {
	return &QualityProfileStore{pool: pool}
}

var _ ports.QualityProfileStore = (*QualityProfileStore)(nil)

func (s *QualityProfileStore) Create(ctx context.Context, tenantID shared.ID, profile qualityprofile.Profile) error {
	activated, err := json.Marshal(profile.ActivatedRules)
	if err != nil {
		return fmt.Errorf("marshal profile rules: %w", err)
	}
	err = WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO quality_profiles (tenant_id, key, name, language, parent, activated_rules) VALUES ($1,$2,$3,$4,$5,$6)`,
			tenantID.String(), profile.Key, profile.Name, profile.Language, profile.Parent, activated)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return shared.ErrConflict
			}
			return fmt.Errorf("insert quality profile: %w", err)
		}
		return nil
	})
	return err
}

func (s *QualityProfileStore) List(ctx context.Context, tenantID shared.ID) (out []qualityprofile.Profile, err error) {
	err = WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT key, name, language, parent, activated_rules FROM quality_profiles WHERE tenant_id=$1 ORDER BY key`, tenantID.String())
		if err != nil {
			return fmt.Errorf("list quality profiles: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			profile, err := scanQualityProfile(rows)
			if err != nil {
				return err
			}
			out = append(out, profile)
		}
		return rows.Err()
	})
	return out, err
}

func (s *QualityProfileStore) Get(ctx context.Context, tenantID shared.ID, key string) (out qualityprofile.Profile, err error) {
	err = WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		profile, err := scanQualityProfile(tx.QueryRow(ctx, `SELECT key, name, language, parent, activated_rules FROM quality_profiles WHERE tenant_id=$1 AND key=$2`, tenantID.String(), key))
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select quality profile: %w", err)
		}
		out = profile
		return nil
	})
	return out, err
}

func (s *QualityProfileStore) Update(ctx context.Context, tenantID shared.ID, profile qualityprofile.Profile) error {
	activated, err := json.Marshal(profile.ActivatedRules)
	if err != nil {
		return fmt.Errorf("marshal profile rules: %w", err)
	}
	err = WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE quality_profiles SET name=$3, language=$4, parent=$5, activated_rules=$6, updated_at=now() WHERE tenant_id=$1 AND key=$2`,
			tenantID.String(), profile.Key, profile.Name, profile.Language, profile.Parent, activated)
		if err != nil {
			return fmt.Errorf("update quality profile: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return shared.ErrNotFound
		}
		return nil
	})
	return err
}

func (s *QualityProfileStore) Delete(ctx context.Context, tenantID shared.ID, key string) error {
	return WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM quality_profiles WHERE tenant_id=$1 AND key=$2`, tenantID.String(), key)
		if err != nil {
			return fmt.Errorf("delete quality profile: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return shared.ErrNotFound
		}
		return nil
	})
}

func scanQualityProfile(row rowScanner) (qualityprofile.Profile, error) {
	var p qualityprofile.Profile
	var activated []byte
	if err := row.Scan(&p.Key, &p.Name, &p.Language, &p.Parent, &activated); err != nil {
		return qualityprofile.Profile{}, err
	}
	p.ActivatedRules = map[string]qualityprofile.RuleActivation{}
	if len(activated) > 0 {
		if err := json.Unmarshal(activated, &p.ActivatedRules); err != nil {
			return qualityprofile.Profile{}, fmt.Errorf("unmarshal profile rules: %w", err)
		}
	}
	return p, nil
}
