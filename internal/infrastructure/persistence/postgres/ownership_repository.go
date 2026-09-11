package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type OwnershipRepository struct{ pool *pgxpool.Pool }

func NewOwnershipRepository(pool *pgxpool.Pool) (*OwnershipRepository, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: ownership requires PostgreSQL", shared.ErrValidation)
	}
	return &OwnershipRepository{pool: pool}, nil
}

var _ ports.OwnershipRepository = (*OwnershipRepository)(nil)

func (r *OwnershipRepository) within(ctx context.Context, fn func(pgx.Tx, shared.ID) error) error {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() {
		return fmt.Errorf("%w: ownership tenant context required", shared.ErrValidation)
	}
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error { return fn(tx, tenant) })
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("ownership resource: %w", shared.ErrNotFound)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return fmt.Errorf("ownership uniqueness conflict: %w", shared.ErrConflict)
		case "23503":
			return fmt.Errorf("ownership reference: %w", shared.ErrNotFound)
		case "23514", "23502", "22001":
			return fmt.Errorf("ownership constraint: %w", shared.ErrValidation)
		}
	}
	return err
}

func ownershipLimit(n int) int {
	if n <= 0 {
		return 100
	}
	if n > 200 {
		return 200
	}
	return n
}
func ownershipCAS(tag pgconn.CommandTag, err error) error {
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return shared.ErrConflict
	}
	return nil
}

func (r *OwnershipRepository) CreateTeam(ctx context.Context, t ownership.Team) (ownership.Team, error) {
	if err := t.Validate(); err != nil {
		return t, err
	}
	if t.Revision != 1 {
		return t, shared.ErrValidation
	}
	err := r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		if tenant != t.TenantID {
			return shared.ErrValidation
		}
		_, err := tx.Exec(ctx, `INSERT INTO ownership_teams(tenant_id,id,slug,name,archived,revision,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, tenant, t.ID, t.Slug, t.Name, t.Archived, t.Revision, t.CreatedAt, t.UpdatedAt)
		return err
	})
	return t, err
}

func (r *OwnershipRepository) UpdateTeam(ctx context.Context, t ownership.Team, expected int) (ownership.Team, error) {
	if err := t.Validate(); err != nil {
		return t, err
	}
	if expected < 1 || t.Revision != expected+1 {
		return t, shared.ErrValidation
	}
	err := r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		if tenant != t.TenantID {
			return shared.ErrValidation
		}
		return ownershipCAS(tx.Exec(ctx, `UPDATE ownership_teams SET slug=$3,name=$4,archived=$5,revision=$6,updated_at=$7 WHERE tenant_id=$1 AND id=$2 AND revision=$8 AND created_at=$9`, tenant, t.ID, t.Slug, t.Name, t.Archived, t.Revision, t.UpdatedAt, expected, t.CreatedAt))
	})
	return t, err
}

const ownershipTeamSelect = `SELECT tenant_id,id,slug,name,archived,revision,created_at,updated_at FROM ownership_teams`

func scanOwnershipTeam(row rowScanner) (t ownership.Team, err error) {
	err = row.Scan(&t.TenantID, &t.ID, &t.Slug, &t.Name, &t.Archived, &t.Revision, &t.CreatedAt, &t.UpdatedAt)
	return
}
func (r *OwnershipRepository) GetTeam(ctx context.Context, id shared.ID) (t ownership.Team, err error) {
	err = r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		var e error
		t, e = scanOwnershipTeam(tx.QueryRow(ctx, ownershipTeamSelect+` WHERE tenant_id=$1 AND id=$2`, tenant, id))
		return e
	})
	return
}
func (r *OwnershipRepository) ListTeams(ctx context.Context, after shared.ID, limit int) (out []ownership.Team, err error) {
	out = []ownership.Team{}
	err = r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		rows, e := tx.Query(ctx, ownershipTeamSelect+` WHERE tenant_id=$1 AND id>$2 ORDER BY id LIMIT $3`, tenant, after, ownershipLimit(limit))
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			t, e := scanOwnershipTeam(rows)
			if e != nil {
				return e
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	return
}

func ownershipActiveTeam(ctx context.Context, tx pgx.Tx, tenant, id shared.ID) error {
	var archived bool
	if err := tx.QueryRow(ctx, `SELECT archived FROM ownership_teams WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&archived); err != nil {
		return err
	}
	if archived {
		return fmt.Errorf("%w: ownership team is archived", shared.ErrValidation)
	}
	return nil
}

func ownershipEligibleUser(ctx context.Context, tx pgx.Tx, tenant, id, team shared.ID, triage bool) error {
	var disabled bool
	var role user.Role
	if err := tx.QueryRow(ctx, `SELECT disabled,role FROM users WHERE ownership_tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&disabled, &role); err != nil {
		return err
	}
	if disabled || !role.Valid() || triage && !role.Can(user.PermTriage) {
		return fmt.Errorf("%w: ownership user is ineligible", shared.ErrForbidden)
	}
	if !team.IsZero() {
		var member string
		if err := tx.QueryRow(ctx, `SELECT user_id FROM ownership_memberships WHERE tenant_id=$1 AND team_id=$2 AND user_id=$3 FOR SHARE`, tenant, team, id).Scan(&member); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: user is not a team member", shared.ErrValidation)
			}
			return err
		}
	}
	return nil
}

func (r *OwnershipRepository) AddMember(ctx context.Context, team, id shared.ID, at time.Time) error {
	if team.IsZero() || id.IsZero() || at.IsZero() {
		return shared.ErrValidation
	}
	return r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		if err := ownershipActiveTeam(ctx, tx, tenant, team); err != nil {
			return err
		}
		if err := ownershipEligibleUser(ctx, tx, tenant, id, "", false); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO ownership_memberships(tenant_id,team_id,user_id,created_at) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, tenant, team, id, at)
		return err
	})
}
func (r *OwnershipRepository) RemoveMember(ctx context.Context, team, id shared.ID) error {
	return r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		tag, err := tx.Exec(ctx, `DELETE FROM ownership_memberships WHERE tenant_id=$1 AND team_id=$2 AND user_id=$3`, tenant, team, id)
		if err == nil && tag.RowsAffected() == 0 {
			return shared.ErrNotFound
		}
		return err
	})
}
func (r *OwnershipRepository) ListMembers(ctx context.Context, team, after shared.ID, limit int) (out []ownership.Membership, err error) {
	out = []ownership.Membership{}
	err = r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		rows, e := tx.Query(ctx, `SELECT tenant_id,team_id,user_id,created_at FROM ownership_memberships WHERE tenant_id=$1 AND team_id=$2 AND user_id>$3 ORDER BY user_id LIMIT $4`, tenant, team, after, ownershipLimit(limit))
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var m ownership.Membership
			if e := rows.Scan(&m.TenantID, &m.TeamID, &m.UserID, &m.CreatedAt); e != nil {
				return e
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return
}

func (r *OwnershipRepository) SaveMapping(ctx context.Context, eng shared.ID, record ports.OwnershipMapping) error {
	m := record.Mapping
	if err := m.Validate(); err != nil {
		return err
	}
	if eng.IsZero() || record.Revision < 1 {
		return shared.ErrValidation
	}
	return r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		if err := ownershipActiveTeam(ctx, tx, tenant, m.TeamID); err != nil {
			return err
		}
		if !m.SuggestedUserID.IsZero() {
			if err := ownershipEligibleUser(ctx, tx, tenant, m.SuggestedUserID, m.TeamID, true); err != nil {
				return err
			}
		}
		if record.Revision == 1 {
			_, err := tx.Exec(ctx, `INSERT INTO ownership_mappings(tenant_id,engagement_id,repository,owner_token,team_id,suggested_user_id,revision) VALUES($1,$2,$3,$4,$5,$6,1)`, tenant, eng, m.Repository, m.Owner, m.TeamID, nullableID(m.SuggestedUserID))
			return err
		}
		return ownershipCAS(tx.Exec(ctx, `UPDATE ownership_mappings SET team_id=$5,suggested_user_id=$6,revision=$7 WHERE tenant_id=$1 AND engagement_id=$2 AND repository=$3 AND owner_token=$4 AND revision=$8`, tenant, eng, m.Repository, m.Owner, m.TeamID, nullableID(m.SuggestedUserID), record.Revision, record.Revision-1))
	})
}
func (r *OwnershipRepository) DeleteMapping(ctx context.Context, eng shared.ID, repo, owner string, revision int) error {
	return r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		return ownershipCAS(tx.Exec(ctx, `DELETE FROM ownership_mappings WHERE tenant_id=$1 AND engagement_id=$2 AND repository=$3 AND owner_token=$4 AND revision=$5`, tenant, eng, repo, owner, revision))
	})
}
func (r *OwnershipRepository) ListMappings(ctx context.Context, eng shared.ID, repo, after string, limit int) (out []ports.OwnershipMapping, err error) {
	out = []ports.OwnershipMapping{}
	err = r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		rows, e := tx.Query(ctx, `SELECT repository,owner_token,team_id,COALESCE(suggested_user_id,''),revision FROM ownership_mappings WHERE tenant_id=$1 AND engagement_id=$2 AND repository=$3 AND owner_token>$4 ORDER BY owner_token LIMIT $5`, tenant, eng, repo, after, ownershipLimit(limit))
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var m ports.OwnershipMapping
			if e := rows.Scan(&m.Mapping.Repository, &m.Mapping.Owner, &m.Mapping.TeamID, &m.Mapping.SuggestedUserID, &m.Revision); e != nil {
				return e
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return
}
func (r *OwnershipRepository) SaveAssetMapping(ctx context.Context, m ports.OwnershipAssetMapping) error {
	if m.Mapping.AssetID.IsZero() || m.Mapping.TeamID.IsZero() || m.Revision < 1 {
		return shared.ErrValidation
	}
	return r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		if err := ownershipActiveTeam(ctx, tx, tenant, m.Mapping.TeamID); err != nil {
			return err
		}
		if m.Revision == 1 {
			_, err := tx.Exec(ctx, `INSERT INTO ownership_asset_mappings(tenant_id,asset_id,team_id,revision) VALUES($1,$2,$3,1)`, tenant, m.Mapping.AssetID, m.Mapping.TeamID)
			return err
		}
		return ownershipCAS(tx.Exec(ctx, `UPDATE ownership_asset_mappings SET team_id=$3,revision=$4 WHERE tenant_id=$1 AND asset_id=$2 AND revision=$5`, tenant, m.Mapping.AssetID, m.Mapping.TeamID, m.Revision, m.Revision-1))
	})
}
func (r *OwnershipRepository) DeleteAssetMapping(ctx context.Context, asset shared.ID, revision int) error {
	return r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		return ownershipCAS(tx.Exec(ctx, `DELETE FROM ownership_asset_mappings WHERE tenant_id=$1 AND asset_id=$2 AND revision=$3`, tenant, asset, revision))
	})
}
func (r *OwnershipRepository) ListAssetMappings(ctx context.Context, after shared.ID, limit int) (out []ports.OwnershipAssetMapping, err error) {
	out = []ports.OwnershipAssetMapping{}
	err = r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		rows, e := tx.Query(ctx, `SELECT asset_id,team_id,revision FROM ownership_asset_mappings WHERE tenant_id=$1 AND asset_id>$2 ORDER BY asset_id LIMIT $3`, tenant, after, ownershipLimit(limit))
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var m ports.OwnershipAssetMapping
			if e := rows.Scan(&m.Mapping.AssetID, &m.Mapping.TeamID, &m.Revision); e != nil {
				return e
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return
}
