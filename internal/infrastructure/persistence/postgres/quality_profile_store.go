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
	_, err = s.pool.Exec(ctx, `INSERT INTO quality_profiles (tenant_id, key, name, language, parent, activated_rules) VALUES ($1,$2,$3,$4,$5,$6)`,
		tenantID.String(), profile.Key, profile.Name, profile.Language, profile.Parent, activated)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return shared.ErrConflict
		}
		return fmt.Errorf("insert quality profile: %w", err)
	}
	return nil
}

func (s *QualityProfileStore) List(ctx context.Context, tenantID shared.ID) ([]qualityprofile.Profile, error) {
	rows, err := s.pool.Query(ctx, `SELECT key, name, language, parent, activated_rules FROM quality_profiles WHERE tenant_id=$1 ORDER BY key`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list quality profiles: %w", err)
	}
	defer rows.Close()
	out := make([]qualityprofile.Profile, 0)
	for rows.Next() {
		profile, err := scanQualityProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, profile)
	}
	return out, rows.Err()
}

func (s *QualityProfileStore) Get(ctx context.Context, tenantID shared.ID, key string) (qualityprofile.Profile, error) {
	profile, err := scanQualityProfile(s.pool.QueryRow(ctx, `SELECT key, name, language, parent, activated_rules FROM quality_profiles WHERE tenant_id=$1 AND key=$2`, tenantID.String(), key))
	if errors.Is(err, pgx.ErrNoRows) {
		return qualityprofile.Profile{}, shared.ErrNotFound
	}
	if err != nil {
		return qualityprofile.Profile{}, fmt.Errorf("select quality profile: %w", err)
	}
	return profile, nil
}

func (s *QualityProfileStore) Update(ctx context.Context, tenantID shared.ID, profile qualityprofile.Profile) error {
	activated, err := json.Marshal(profile.ActivatedRules)
	if err != nil {
		return fmt.Errorf("marshal profile rules: %w", err)
	}
	ct, err := s.pool.Exec(ctx, `UPDATE quality_profiles SET name=$3, language=$4, parent=$5, activated_rules=$6, updated_at=now() WHERE tenant_id=$1 AND key=$2`,
		tenantID.String(), profile.Key, profile.Name, profile.Language, profile.Parent, activated)
	if err != nil {
		return fmt.Errorf("update quality profile: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return shared.ErrNotFound
	}
	return nil
}

func (s *QualityProfileStore) Delete(ctx context.Context, tenantID shared.ID, key string) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM quality_profiles WHERE tenant_id=$1 AND key=$2`, tenantID.String(), key)
	if err != nil {
		return fmt.Errorf("delete quality profile: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return shared.ErrNotFound
	}
	return nil
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
