package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.IdentityAuthorizationStore = (*IdentityFoundationStore)(nil)

// CreateIdentityAuthorization records a short lived callback binding. Only digests and sealed
// values cross this persistence boundary; callers retain state, nonce, and verifier plaintext.
func (s *IdentityFoundationStore) CreateIdentityAuthorization(ctx context.Context, v ports.IdentityAuthorizationTransaction) error {
	if v.ID.IsZero() || v.TenantID.IsZero() || !v.Purpose.Valid() || v.ConnectionID.IsZero() || v.ConnectionRevision < 1 ||
		!identityDigestPattern.MatchString(v.StateDigest) || !identityDigestPattern.MatchString(v.NonceDigest) ||
		!identityDigestPattern.MatchString(v.CallerNonceDigest) ||
		strings.TrimSpace(v.PKCEVerifierSealed) == "" || v.ExpiresAt.IsZero() || v.CreatedAt.IsZero() || !v.ExpiresAt.After(v.CreatedAt) {
		return fmt.Errorf("%w: invalid identity authorization transaction", shared.ErrValidation)
	}
	return s.withIdentityTenant(ctx, v.TenantID, func(tx pgx.Tx) error {
		if s.authorizationCapacity <= 0 {
			return shared.ErrSaturated
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('identity-authorization:'||$1,0))`, v.TenantID.String()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `WITH expired AS MATERIALIZED (SELECT id FROM identity_transactions WHERE tenant_id=$1 AND (expires_at<=$2 OR consumed_at IS NOT NULL) ORDER BY expires_at,id LIMIT 100 FOR UPDATE SKIP LOCKED)
 DELETE FROM identity_transactions target USING expired WHERE target.tenant_id=$1 AND target.id=expired.id`, v.TenantID.String(), v.CreatedAt); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT 1 FROM identity_transactions WHERE tenant_id=$1 AND consumed_at IS NULL AND expires_at>$2 LIMIT $3) live`, v.TenantID.String(), v.CreatedAt, s.authorizationCapacity).Scan(&count); err != nil {
			return err
		}
		if count >= s.authorizationCapacity {
			return shared.ErrSaturated
		}
		_, err := tx.Exec(ctx, `INSERT INTO identity_transactions
 (tenant_id,id,purpose,connection_id,connection_revision,state_digest,nonce_digest,caller_nonce_digest,pkce_verifier_sealed,context_sealed,session_id,expires_at,created_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULLIF($11,''),$12,$13)`,
			v.TenantID.String(), v.ID.String(), v.Purpose, v.ConnectionID.String(), v.ConnectionRevision,
			v.StateDigest, v.NonceDigest, v.CallerNonceDigest, v.PKCEVerifierSealed, v.ContextSealed, v.SessionID.String(), v.ExpiresAt.UTC(), v.CreatedAt.UTC())
		return err
	})
}

// ConsumeIdentityAuthorization burns an eligible state before any token exchange is attempted.
// SELECT FOR UPDATE serializes replay attempts; an expired or already consumed state is neutral.
func (s *IdentityFoundationStore) ConsumeIdentityAuthorization(ctx context.Context, tenantID shared.ID, stateDigest, callerNonceDigest string, now time.Time) (out ports.IdentityAuthorizationTransaction, err error) {
	if tenantID.IsZero() || !identityDigestPattern.MatchString(stateDigest) || !identityDigestPattern.MatchString(callerNonceDigest) || now.IsZero() {
		return out, fmt.Errorf("%w: identity authorization state is invalid", shared.ErrNotFound)
	}
	err = s.withIdentityTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var purpose, id, connection, session string
		var consumed *time.Time
		err := tx.QueryRow(ctx, `SELECT id,purpose,connection_id,connection_revision,state_digest,nonce_digest,caller_nonce_digest,pkce_verifier_sealed,context_sealed,
 COALESCE(session_id,''),expires_at,consumed_at,created_at FROM identity_transactions
 WHERE tenant_id=$1 AND state_digest=$2 FOR UPDATE`, tenantID.String(), stateDigest).Scan(
			&id, &purpose, &connection, &out.ConnectionRevision, &out.StateDigest, &out.NonceDigest, &out.CallerNonceDigest,
			&out.PKCEVerifierSealed, &out.ContextSealed, &session, &out.ExpiresAt, &consumed, &out.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return err
		}
		if consumed != nil || !out.ExpiresAt.After(now.UTC()) || out.CallerNonceDigest != callerNonceDigest {
			return shared.ErrNotFound
		}
		out.ID, out.TenantID, out.Purpose, out.ConnectionID, out.SessionID = shared.ID(id), tenantID, ports.IdentityAuthorizationPurpose(purpose), shared.ID(connection), shared.ID(session)
		// The durable burn happens before returning verifier/context. A failed exchange cannot be retried.
		if _, err = tx.Exec(ctx, `UPDATE identity_transactions SET consumed_at=$3 WHERE tenant_id=$1 AND id=$2 AND consumed_at IS NULL`, tenantID.String(), id, now.UTC()); err != nil {
			return err
		}
		out.ConsumedAt = ptrTime(now.UTC())
		return nil
	})
	return out, err
}

// CleanupIdentityAuthorizations uses SKIP LOCKED so independently scheduled workers clean bounded
// batches without blocking callback transactions or each other.
func (s *IdentityFoundationStore) CleanupIdentityAuthorizations(ctx context.Context, tenantID shared.ID, now time.Time, limit int) (count int, err error) {
	if tenantID.IsZero() || now.IsZero() || limit < 1 || limit > 1000 {
		return 0, fmt.Errorf("%w: authorization cleanup limit must be 1..1000", shared.ErrValidation)
	}
	err = s.withIdentityTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('identity-authorization:'||$1,0))`, tenantID.String()); e != nil {
			return e
		}
		ct, err := tx.Exec(ctx, `WITH expired AS MATERIALIZED (
 SELECT id FROM identity_transactions WHERE tenant_id=$1 AND (expires_at <= $2 OR consumed_at IS NOT NULL)
 ORDER BY expires_at,id LIMIT $3 FOR UPDATE SKIP LOCKED)
 DELETE FROM identity_transactions target USING expired WHERE target.tenant_id=$1 AND target.id=expired.id`, tenantID.String(), now.UTC(), limit)
		count = int(ct.RowsAffected())
		return err
	})
	return count, err
}

func ptrTime(v time.Time) *time.Time { return &v }
