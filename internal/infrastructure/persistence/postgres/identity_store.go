package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// IdentityStore persists OIDC identity/session records under the tenant RLS boundary.
type IdentityStore struct{ pool *pgxpool.Pool }

// NewIdentityStore returns a PostgreSQL-backed OIDC identity/session store.
func NewIdentityStore(pool *pgxpool.Pool) (*IdentityStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: identity store requires pool", shared.ErrValidation)
	}
	return &IdentityStore{pool: pool}, nil
}

var _ ports.IdentityStore = (*IdentityStore)(nil)

func (s *IdentityStore) CreateExternalIdentity(ctx context.Context, external identity.ExternalIdentity) error {
	return WithTenant(ctx, s.pool, external.TenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO oidc_external_identities
			(id, tenant_id, user_id, issuer, subject, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, external.ID.String(), external.TenantID.String(), external.UserID.String(), external.Issuer, external.Subject, external.CreatedAt, external.UpdatedAt)
		if err == nil {
			return nil
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "23505":
				return fmt.Errorf("OIDC issuer/subject already linked: %w", shared.ErrConflict)
			case "23503":
				return fmt.Errorf("OIDC identity user tenant link is invalid: %w", shared.ErrForbidden)
			}
		}
		return fmt.Errorf("create OIDC external identity: %w", err)
	})
}

func (s *IdentityStore) GetExternalIdentity(ctx context.Context, issuer, subject string) (external identity.ExternalIdentity, err error) {
	err = WithContextTenant(ctx, s.pool, func(tx pgx.Tx) error {
		external, err = scanExternalIdentity(tx.QueryRow(ctx, `SELECT id, tenant_id, user_id, issuer, subject, created_at, updated_at
			FROM oidc_external_identities WHERE issuer=$1 AND subject=$2`, issuer, subject))
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get OIDC external identity: %w", err)
		}
		return nil
	})
	return external, err
}

func (s *IdentityStore) CreateAuthorizationTransaction(ctx context.Context, transaction identity.AuthorizationTransaction) error {
	return WithTenant(ctx, s.pool, transaction.TenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO oidc_authorization_transactions
			(id, tenant_id, state_hash, nonce_hash, pkce_verifier_ciphertext, created_at, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, transaction.ID.String(), transaction.TenantID.String(), transaction.StateHash, transaction.NonceHash, transaction.PKCEVerifierCiphertext, transaction.CreatedAt, transaction.ExpiresAt)
		if err == nil {
			return nil
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("OIDC authorization state already exists: %w", shared.ErrConflict)
		}
		return fmt.Errorf("create OIDC authorization transaction: %w", err)
	})
}

// ConsumeAuthorizationTransaction atomically deletes and returns an unexpired transaction, making
// the state unusable by every concurrent request and every API replica after the first succeeds.
func (s *IdentityStore) ConsumeAuthorizationTransaction(ctx context.Context, tenantID shared.ID, stateHash string, now time.Time) (transaction identity.AuthorizationTransaction, err error) {
	if tenantID.IsZero() {
		return identity.AuthorizationTransaction{}, fmt.Errorf("%w: authorization transaction tenant is required", shared.ErrValidation)
	}
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		if _, purgeErr := tx.Exec(ctx, `DELETE FROM oidc_authorization_transactions WHERE tenant_id=$1 AND expires_at <= $2`, tenantID.String(), now.UTC()); purgeErr != nil {
			return fmt.Errorf("purge expired OIDC authorization transactions: %w", purgeErr)
		}
		transaction, err = scanAuthorizationTransaction(tx.QueryRow(ctx, `DELETE FROM oidc_authorization_transactions
			WHERE tenant_id=$1 AND state_hash=$2 AND expires_at > $3
			RETURNING id, tenant_id, state_hash, nonce_hash, pkce_verifier_ciphertext, created_at, expires_at`, tenantID.String(), stateHash, now.UTC()))
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("consume OIDC authorization transaction: %w", err)
		}
		return nil
	})
	return transaction, err
}

func (s *IdentityStore) CreateSession(ctx context.Context, session identity.Session) error {
	metadata, err := json.Marshal(session.Metadata)
	if err != nil {
		return fmt.Errorf("marshal session metadata: %w", err)
	}
	return WithTenant(ctx, s.pool, session.TenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO oidc_sessions
			(id, tenant_id, user_id, token_hash, csrf_token_hash, metadata, created_at, updated_at, expires_at, revoked_at, origin_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, session.ID.String(), session.TenantID.String(), session.UserID.String(), session.TokenHash, session.CSRFTokenHash, metadata, session.CreatedAt, session.UpdatedAt, session.ExpiresAt, session.RevokedAt, session.OriginAt)
		if err == nil {
			return nil
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "23505":
				return fmt.Errorf("OIDC session already exists: %w", shared.ErrConflict)
			case "23503":
				return fmt.Errorf("OIDC session user tenant link is invalid: %w", shared.ErrForbidden)
			}
		}
		return fmt.Errorf("create OIDC session: %w", err)
	})
}

// RotateSession creates replacement and revokes the active previous session in one transaction.
func (s *IdentityStore) RotateSession(ctx context.Context, previousSessionID shared.ID, replacement identity.Session, now time.Time) error {
	metadata, err := json.Marshal(replacement.Metadata)
	if err != nil {
		return fmt.Errorf("marshal replacement session metadata: %w", err)
	}
	return WithTenant(ctx, s.pool, replacement.TenantID.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO oidc_sessions
			(id, tenant_id, user_id, token_hash, csrf_token_hash, metadata, created_at, updated_at, expires_at, revoked_at, origin_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, replacement.ID.String(), replacement.TenantID.String(), replacement.UserID.String(), replacement.TokenHash, replacement.CSRFTokenHash, metadata, replacement.CreatedAt, replacement.UpdatedAt, replacement.ExpiresAt, replacement.RevokedAt, replacement.OriginAt); err != nil {
			return fmt.Errorf("create replacement OIDC session: %w", err)
		}
		tag, err := tx.Exec(ctx, `UPDATE oidc_sessions SET revoked_at=$4, updated_at=$4
			WHERE id=$1 AND tenant_id=$2 AND user_id=$3 AND revoked_at IS NULL AND expires_at > $4`, previousSessionID.String(), replacement.TenantID.String(), replacement.UserID.String(), now.UTC())
		if err != nil {
			return fmt.Errorf("revoke previous OIDC session: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("previous OIDC session is not active: %w", shared.ErrConflict)
		}
		return nil
	})
}

func (s *IdentityStore) GetSessionByTokenHash(ctx context.Context, tokenHash string) (session identity.Session, err error) {
	err = WithContextTenant(ctx, s.pool, func(tx pgx.Tx) error {
		session, err = scanSession(tx.QueryRow(ctx, `SELECT id, tenant_id, user_id, token_hash, csrf_token_hash, metadata, created_at, updated_at, expires_at, revoked_at, origin_at
			FROM oidc_sessions WHERE token_hash=$1`, tokenHash))
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get OIDC session: %w", err)
		}
		return nil
	})
	return session, err
}

func (s *IdentityStore) RevokeSession(ctx context.Context, tenantID, sessionID shared.ID, now time.Time) error {
	return WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE oidc_sessions SET revoked_at=$3, updated_at=$3
			WHERE id=$1 AND tenant_id=$2 AND revoked_at IS NULL`, sessionID.String(), tenantID.String(), now.UTC())
		if err != nil {
			return fmt.Errorf("revoke OIDC session: %w", err)
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM oidc_sessions WHERE id=$1 AND tenant_id=$2)`, sessionID.String(), tenantID.String()).Scan(&exists); err != nil {
			return fmt.Errorf("check OIDC session: %w", err)
		}
		if exists {
			return fmt.Errorf("OIDC session already revoked: %w", shared.ErrConflict)
		}
		return shared.ErrNotFound
	})
}

func scanExternalIdentity(row rowScanner) (identity.ExternalIdentity, error) {
	var external identity.ExternalIdentity
	var id, tenantID, userID string
	if err := row.Scan(&id, &tenantID, &userID, &external.Issuer, &external.Subject, &external.CreatedAt, &external.UpdatedAt); err != nil {
		return identity.ExternalIdentity{}, err
	}
	external.ID, external.TenantID, external.UserID = shared.ID(id), shared.ID(tenantID), shared.ID(userID)
	return external, nil
}

func scanAuthorizationTransaction(row rowScanner) (identity.AuthorizationTransaction, error) {
	var transaction identity.AuthorizationTransaction
	var id, tenantID string
	if err := row.Scan(&id, &tenantID, &transaction.StateHash, &transaction.NonceHash, &transaction.PKCEVerifierCiphertext, &transaction.CreatedAt, &transaction.ExpiresAt); err != nil {
		return identity.AuthorizationTransaction{}, err
	}
	transaction.ID, transaction.TenantID = shared.ID(id), shared.ID(tenantID)
	return transaction, nil
}

func scanSession(row rowScanner) (identity.Session, error) {
	var session identity.Session
	var id, tenantID, userID string
	var metadata []byte
	if err := row.Scan(&id, &tenantID, &userID, &session.TokenHash, &session.CSRFTokenHash, &metadata, &session.CreatedAt, &session.UpdatedAt, &session.ExpiresAt, &session.RevokedAt, &session.OriginAt); err != nil {
		return identity.Session{}, err
	}
	if err := json.Unmarshal(metadata, &session.Metadata); err != nil {
		return identity.Session{}, fmt.Errorf("decode session metadata: %w", err)
	}
	session.ID, session.TenantID, session.UserID = shared.ID(id), shared.ID(tenantID), shared.ID(userID)
	return session, nil
}
