package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// FleetAgentRepository is the Postgres-backed fleet agent identity store. Every method runs through
// WithTenant so Row Level Security (migration 0060 via the 0057 procedure) isolates by tenant. The
// auth lookup is tenant-scoped because the agent credential carries a non-secret tenant prefix.
type FleetAgentRepository struct{ pool *pgxpool.Pool }

// NewFleetAgentRepository constructs the Postgres fleet agent repository.
func NewFleetAgentRepository(pool *pgxpool.Pool) *FleetAgentRepository {
	return &FleetAgentRepository{pool: pool}
}

var _ ports.FleetAgentStore = (*FleetAgentRepository)(nil)

const fleetAgentCols = `id, tenant_id, name, platform, os_version, agent_version, capabilities, token_hash, state, created_at, updated_at, last_seen_at, fingerprint, revoked_at, revoked_by, revoke_reason`

func (r *FleetAgentRepository) CreateEnrolToken(ctx context.Context, t *fleetagent.EnrolToken) error {
	return WithTenant(ctx, r.pool, t.TenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO fleet_enrol_tokens (tenant_id, hash, issued_by, expires_at, created_at)
			VALUES ($1,$2,$3,$4,$5)`,
			t.TenantID.String(), t.Hash, t.IssuedBy, t.ExpiresAt, t.CreatedAt)
		return err
	})
}

// ConsumeEnrolToken atomically marks a usable token used and returns it; shared.ErrNotFound if no
// unused, unexpired token with that hash exists for the tenant.
func (r *FleetAgentRepository) ConsumeEnrolToken(ctx context.Context, tenantID shared.ID, hash string, now time.Time) (*fleetagent.EnrolToken, error) {
	var out *fleetagent.EnrolToken
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			UPDATE fleet_enrol_tokens SET used_at=$3
			WHERE tenant_id=$1 AND hash=$2 AND used_at IS NULL AND expires_at > $3
			RETURNING tenant_id, hash, issued_by, expires_at, used_at, created_at`,
			tenantID.String(), hash, now)
		t, e := scanEnrolToken(row)
		if e != nil {
			return e
		}
		out = t
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *FleetAgentRepository) CreateAgent(ctx context.Context, a *fleetagent.Agent) error {
	caps, err := json.Marshal(a.Capabilities)
	if err != nil {
		return err
	}
	return WithTenant(ctx, r.pool, a.TenantID.String(), func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `
			INSERT INTO fleet_agents (`+fleetAgentCols+`)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
			a.ID.String(), a.TenantID.String(), a.Name, a.Platform, a.OSVersion, a.AgentVersion,
			caps, a.TokenHash, string(a.State), a.Audit.CreatedAt, a.Audit.UpdatedAt, a.LastSeenAt,
			a.Fingerprint, a.RevokedAt, a.RevokedBy.String(), a.RevokeReason)
		return e
	})
}

func (r *FleetAgentRepository) GetAgent(ctx context.Context, tenantID, id shared.ID) (*fleetagent.Agent, error) {
	var out *fleetagent.Agent
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		a, e := scanAgent(tx.QueryRow(ctx, `SELECT `+fleetAgentCols+` FROM fleet_agents WHERE tenant_id=$1 AND id=$2`,
			tenantID.String(), id.String()))
		if e != nil {
			return e
		}
		out = a
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *FleetAgentRepository) Heartbeat(ctx context.Context, tenantID, id shared.ID, platform, osVersion, agentVersion string, capabilities []string, now time.Time) error {
	var caps []byte
	if capabilities != nil {
		b, err := json.Marshal(capabilities)
		if err != nil {
			return err
		}
		caps = b
	}
	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `
			UPDATE fleet_agents SET
				platform = COALESCE(NULLIF($3,''), platform),
				os_version = COALESCE(NULLIF($4,''), os_version),
				agent_version = COALESCE(NULLIF($5,''), agent_version),
				capabilities = COALESCE($6, capabilities),
				last_seen_at = $7,
				updated_at = $7
			WHERE tenant_id=$1 AND id=$2`,
			tenantID.String(), id.String(), platform, osVersion, agentVersion, caps, now)
		if e != nil {
			return e
		}
		if tag.RowsAffected() == 0 {
			return shared.ErrNotFound
		}
		return nil
	})
}

func (r *FleetAgentRepository) SetFingerprint(ctx context.Context, tenantID, id shared.ID, fingerprint string, now time.Time) error {
	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `UPDATE fleet_agents SET fingerprint=$3, updated_at=$4 WHERE tenant_id=$1 AND id=$2`,
			tenantID.String(), id.String(), fingerprint, now)
		if e != nil {
			return e
		}
		if tag.RowsAffected() == 0 {
			return shared.ErrNotFound
		}
		return nil
	})
}

func (r *FleetAgentRepository) Revoke(ctx context.Context, tenantID, id, by shared.ID, reason string, now time.Time) error {
	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `UPDATE fleet_agents
			SET state='revoked', revoked_at=$3, revoked_by=$4, revoke_reason=$5, updated_at=$3
			WHERE tenant_id=$1 AND id=$2`,
			tenantID.String(), id.String(), now, by.String(), reason)
		if e != nil {
			return e
		}
		if tag.RowsAffected() == 0 {
			return shared.ErrNotFound
		}
		return nil
	})
}

func (r *FleetAgentRepository) ListAgents(ctx context.Context, tenantID shared.ID) ([]*fleetagent.Agent, error) {
	var out []*fleetagent.Agent
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT `+fleetAgentCols+` FROM fleet_agents WHERE tenant_id=$1 ORDER BY name, id`, tenantID.String())
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			a, e := scanAgent(rows)
			if e != nil {
				return e
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func scanAgent(row rowScanner) (*fleetagent.Agent, error) {
	var (
		id, tid, name, platform, osv, ver, hash, state string
		fingerprint, revokedBy, revokeReason           string
		revokedAt                                      *time.Time
		caps                                           []byte
		a                                              fleetagent.Agent
	)
	if err := row.Scan(&id, &tid, &name, &platform, &osv, &ver, &caps, &hash, &state,
		&a.Audit.CreatedAt, &a.Audit.UpdatedAt, &a.LastSeenAt,
		&fingerprint, &revokedAt, &revokedBy, &revokeReason); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, err
	}
	a.ID = shared.ID(id)
	a.TenantID = shared.ID(tid)
	a.Name = name
	a.Platform = platform
	a.OSVersion = osv
	a.AgentVersion = ver
	a.TokenHash = hash
	a.State = fleetagent.State(state)
	a.Fingerprint = fingerprint
	a.RevokedAt = revokedAt
	a.RevokedBy = shared.ID(revokedBy)
	a.RevokeReason = revokeReason
	if len(caps) > 0 {
		if err := json.Unmarshal(caps, &a.Capabilities); err != nil {
			return nil, err
		}
	}
	return &a, nil
}

func scanEnrolToken(row rowScanner) (*fleetagent.EnrolToken, error) {
	var (
		tid, hash, issuedBy string
		usedAt              *time.Time
		t                   fleetagent.EnrolToken
	)
	if err := row.Scan(&tid, &hash, &issuedBy, &t.ExpiresAt, &usedAt, &t.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, err
	}
	t.TenantID = shared.ID(tid)
	t.Hash = hash
	t.IssuedBy = issuedBy
	if usedAt != nil {
		t.UsedAt = *usedAt
	}
	return &t, nil
}
