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

var (
	_ ports.IdentityStore                 = (*IdentityStore)(nil)
	_ ports.ExternalIdentitySessionIssuer = (*IdentityStore)(nil)
)

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

// DeleteExternalIdentity removes one approved link of a user, joining the tenant transaction bound
// to ctx. The tenant and user predicates confine it on top of RLS.
func (s *IdentityStore) DeleteExternalIdentity(ctx context.Context, tenantID, userID, linkID shared.ID) (external identity.ExternalIdentity, err error) {
	if tenantID.IsZero() || userID.IsZero() || linkID.IsZero() {
		return identity.ExternalIdentity{}, fmt.Errorf("%w: identity link tenant, user and id are required", shared.ErrValidation)
	}
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		if err := lockIdentityUser(ctx, tx, tenantID, userID); err != nil {
			return err
		}
		external, err = scanExternalIdentity(tx.QueryRow(ctx, `DELETE FROM oidc_external_identities
			WHERE id=$1 AND tenant_id=$2 AND user_id=$3
			RETURNING id, tenant_id, user_id, issuer, subject, created_at, updated_at`, linkID.String(), tenantID.String(), userID.String()))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("OIDC external identity %s: %w", linkID, shared.ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("delete OIDC external identity: %w", err)
		}
		return nil
	})
	return external, err
}

// ListExternalIdentities returns one user's approved issuer/subject links, oldest first.
func (s *IdentityStore) ListExternalIdentities(ctx context.Context, tenantID, userID shared.ID) ([]identity.ExternalIdentity, error) {
	if tenantID.IsZero() || userID.IsZero() {
		return nil, fmt.Errorf("%w: identity link tenant and user are required", shared.ErrValidation)
	}
	var out []identity.ExternalIdentity
	err := WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, tenant_id, user_id, issuer, subject, created_at, updated_at
			FROM oidc_external_identities WHERE tenant_id=$1 AND user_id=$2 ORDER BY created_at, id`, tenantID.String(), userID.String())
		if err != nil {
			return fmt.Errorf("list OIDC external identities: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			external, scanErr := scanExternalIdentity(rows)
			if scanErr != nil {
				return fmt.Errorf("scan OIDC external identity: %w", scanErr)
			}
			out = append(out, external)
		}
		return rows.Err()
	})
	return out, err
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
	return WithTenant(ctx, s.pool, session.TenantID.String(), func(tx pgx.Tx) error {
		return insertSession(ctx, tx, session)
	})
}

func (s *IdentityStore) CreateSessionForExternalIdentity(ctx context.Context, issuer, subject string, approvedUserUpdatedAt time.Time, session identity.Session) error {
	if session.TenantID.IsZero() || session.UserID.IsZero() || issuer == "" || subject == "" || approvedUserUpdatedAt.IsZero() {
		return fmt.Errorf("%w: OIDC session tenant, user, issuer, subject and approval version are required", shared.ErrValidation)
	}
	return WithTenant(ctx, s.pool, session.TenantID.String(), func(tx pgx.Tx) error {
		var enabled bool
		err := tx.QueryRow(ctx, `SELECT NOT u.disabled
			FROM users u
			WHERE u.tenant_id=$1 AND u.id=$2 AND u.id <> 'operator' AND u.updated_at=$5
				AND EXISTS (SELECT 1 FROM oidc_external_identities e
					WHERE e.tenant_id=u.tenant_id AND e.user_id=u.id AND e.issuer=$3 AND e.subject=$4)
			FOR UPDATE OF u`, session.TenantID, session.UserID, issuer, subject, approvedUserUpdatedAt).Scan(&enabled)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !enabled) {
			return shared.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("validate OIDC session subject and user: %w", err)
		}
		return insertSession(ctx, tx, session)
	})
}

func insertSession(ctx context.Context, tx pgx.Tx, session identity.Session) error {
	metadata, err := json.Marshal(session.Metadata)
	if err != nil {
		return fmt.Errorf("marshal session metadata: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO oidc_sessions
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

// RevokeUserSessions terminally revokes every unrevoked session of one user. Expired sessions
// are revoked too, so no row of the lineage can ever be reactivated by a later change.
func (s *IdentityStore) RevokeUserSessions(ctx context.Context, tenantID, userID shared.ID, now time.Time) (int, error) {
	if tenantID.IsZero() || userID.IsZero() {
		return 0, fmt.Errorf("%w: session revocation tenant and user are required", shared.ErrValidation)
	}
	var revoked int
	err := WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		if err := lockIdentityUser(ctx, tx, tenantID, userID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE oidc_sessions SET revoked_at=$3, updated_at=GREATEST(updated_at, $3)
			WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NULL`, tenantID.String(), userID.String(), now)
		if err != nil {
			return fmt.Errorf("revoke user OIDC sessions: %w", err)
		}
		revoked = int(tag.RowsAffected())
		return nil
	})
	return revoked, err
}

func lockIdentityUser(ctx context.Context, tx pgx.Tx, tenantID, userID shared.ID) error {
	var id string
	if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, userID).Scan(&id); errors.Is(err, pgx.ErrNoRows) {
		return shared.ErrNotFound
	} else if err != nil {
		return fmt.Errorf("lock OIDC session user: %w", err)
	}
	return nil
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
