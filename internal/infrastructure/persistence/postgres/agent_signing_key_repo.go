package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AgentSigningKeyRepository is the Postgres-backed agent content-signing key registry (#607, A0.2). Every
// method runs through WithContextTenant so Row Level Security (migration 0105 via the 0057 procedure)
// isolates one tenant's keys from another's. A key's public half and window are immutable once written;
// revocation is monotonic. The primary key (tenant_id, agent_id, key_id) makes registration idempotent
// on identity and blocks re-pointing a KeyID at another key (anti-rollback).
type AgentSigningKeyRepository struct{ pool *pgxpool.Pool }

var _ ports.AgentSigningKeyStore = (*AgentSigningKeyRepository)(nil)

// NewAgentSigningKeyRepository constructs the repository.
func NewAgentSigningKeyRepository(pool *pgxpool.Pool) *AgentSigningKeyRepository {
	return &AgentSigningKeyRepository{pool: pool}
}

const agentSigningKeyCols = `agent_id, key_id, algorithm, purpose, public_key, not_before, not_after, revoked_at, replaced_by`

// Register stores a signing key, idempotent on identity and anti-rollback on KeyID.
func (r *AgentSigningKeyRepository) Register(ctx context.Context, key fleetagent.AgentSigningKey) error {
	if err := key.Validate(); err != nil {
		return err
	}
	tenant, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("%w: signing-key registration requires a tenant in context", shared.ErrValidation)
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			INSERT INTO agent_signing_keys
			  (tenant_id, agent_id, key_id, algorithm, purpose, public_key, not_before, not_after, revoked_at, replaced_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (tenant_id, agent_id, key_id) DO NOTHING`,
			tenant.String(), key.AgentID.String(), key.KeyID, key.Algorithm, string(key.Purpose),
			[]byte(key.PublicKey), key.NotBefore.UTC(), key.NotAfter.UTC(), nullableTime(key.RevokedAt), key.ReplacedBy)
		if err != nil {
			return fmt.Errorf("insert signing key %s: %w", key.KeyID, err)
		}
		if ct.RowsAffected() == 1 {
			return nil // freshly inserted
		}
		// Conflict on (tenant, agent, key_id): a row already exists. An identical re-registration is a
		// no-op (at-least-once safe); a differing one is refused (a KeyID cannot be re-pointed).
		existing, err := scanSigningKey(tx.QueryRow(ctx, `
			SELECT `+agentSigningKeyCols+` FROM agent_signing_keys
			WHERE agent_id = $1 AND key_id = $2`, key.AgentID.String(), key.KeyID))
		if err != nil {
			return err
		}
		if existing.SameIdentity(key) {
			return nil
		}
		return fmt.Errorf("%w: signing key %s already registered with different attributes", shared.ErrConflict, key.KeyID)
	})
}

// ResolveSigningKey returns the (agent, keyID) key under the ctx tenant, or shared.ErrNotFound.
func (r *AgentSigningKeyRepository) ResolveSigningKey(ctx context.Context, agentID shared.ID, keyID string) (fleetagent.AgentSigningKey, error) {
	var out fleetagent.AgentSigningKey
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		k, e := scanSigningKey(tx.QueryRow(ctx, `
			SELECT `+agentSigningKeyCols+` FROM agent_signing_keys
			WHERE agent_id = $1 AND key_id = $2`, agentID.String(), keyID))
		if errors.Is(e, pgx.ErrNoRows) {
			return fmt.Errorf("%w: signing key %s for agent %s", shared.ErrNotFound, keyID, agentID)
		}
		if e != nil {
			return e
		}
		out = k
		return nil
	})
	return out, err
}

// ListByAgent returns every key for an agent under the ctx tenant, newest NotBefore first.
func (r *AgentSigningKeyRepository) ListByAgent(ctx context.Context, agentID shared.ID) ([]fleetagent.AgentSigningKey, error) {
	var out []fleetagent.AgentSigningKey
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+agentSigningKeyCols+` FROM agent_signing_keys
			WHERE agent_id = $1
			ORDER BY not_before DESC, key_id ASC`, agentID.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			k, e := scanSigningKey(rows)
			if e != nil {
				return e
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	return out, err
}

// Revoke marks (agentID, keyID) revoked at `at`, monotonic (an already-revoked key keeps its first
// RevokedAt), tenant-scoped. shared.ErrNotFound if the key is unknown.
func (r *AgentSigningKeyRepository) Revoke(ctx context.Context, agentID shared.ID, keyID string, at time.Time) error {
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE agent_signing_keys SET revoked_at = $3
			WHERE agent_id = $1 AND key_id = $2 AND revoked_at IS NULL`,
			agentID.String(), keyID, at.UTC())
		if err != nil {
			return fmt.Errorf("revoke signing key %s: %w", keyID, err)
		}
		if ct.RowsAffected() == 1 {
			return nil // revoked now
		}
		// No row updated: either the key does not exist, or it is already revoked (monotonic no-op).
		var exists bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS(SELECT 1 FROM agent_signing_keys WHERE agent_id = $1 AND key_id = $2)`,
			agentID.String(), keyID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("%w: signing key %s for agent %s", shared.ErrNotFound, keyID, agentID)
		}
		return nil
	})
}

// scanSigningKey materializes one row into a domain key and re-validates it, so a corrupted row is
// refused rather than trusted. rowScanner is satisfied by both pgx.Row and pgx.Rows.
func scanSigningKey(row rowScanner) (fleetagent.AgentSigningKey, error) {
	var (
		agentID   string
		keyID     string
		algorithm string
		purpose   string
		pub       []byte
		notBefore time.Time
		notAfter  time.Time
		revokedAt *time.Time
		replaced  string
	)
	if err := row.Scan(&agentID, &keyID, &algorithm, &purpose, &pub, &notBefore, &notAfter, &revokedAt, &replaced); err != nil {
		return fleetagent.AgentSigningKey{}, err
	}
	k := fleetagent.AgentSigningKey{
		KeyID:      keyID,
		AgentID:    shared.ID(agentID),
		Algorithm:  algorithm,
		Purpose:    fleetagent.SigningPurpose(purpose),
		PublicKey:  append([]byte(nil), pub...),
		NotBefore:  notBefore.UTC(),
		NotAfter:   notAfter.UTC(),
		ReplacedBy: replaced,
	}
	if revokedAt != nil {
		k.RevokedAt = revokedAt.UTC()
	}
	if err := k.Validate(); err != nil {
		return fleetagent.AgentSigningKey{}, fmt.Errorf("stored signing key %s is corrupt: %w", keyID, err)
	}
	return k, nil
}

// nullableTime maps a zero time to a SQL NULL so revoked_at is NULL for an un-revoked key.
func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}
