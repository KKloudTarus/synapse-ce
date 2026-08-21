// Package identity defines persisted OIDC identities, authorization transactions, and sessions.
package identity

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	maxMetadataEntries  = 16
	maxMetadataKeyLen   = 64
	maxMetadataValueLen = 256
)

// ExternalIdentity links an immutable provider subject to one tenant-scoped user. Provider tokens
// are deliberately not part of this model.
type ExternalIdentity struct {
	ID        shared.ID
	TenantID  shared.ID
	UserID    shared.ID
	Issuer    string
	Subject   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewExternalIdentity constructs an identity whose issuer/subject tuple is globally unique in the
// store. The user relationship is additionally enforced by the persistence adapter.
func NewExternalIdentity(id, tenantID, userID shared.ID, issuer, subject string, now time.Time) (ExternalIdentity, error) {
	issuer, subject = strings.TrimSpace(issuer), strings.TrimSpace(subject)
	if id.IsZero() || tenantID.IsZero() || userID.IsZero() {
		return ExternalIdentity{}, fmt.Errorf("%w: identity id, tenant id, and user id are required", shared.ErrValidation)
	}
	if issuer == "" || subject == "" {
		return ExternalIdentity{}, fmt.Errorf("%w: issuer and subject are required", shared.ErrValidation)
	}
	return ExternalIdentity{ID: id, TenantID: tenantID, UserID: userID, Issuer: issuer, Subject: subject, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}, nil
}

// AuthorizationTransaction is a short-lived, single-use OIDC login transaction. StateHash and
// NonceHash are one-way hashes. PKCEVerifierCiphertext must be encrypted before it reaches this
// model because the verifier must later be recovered for the token exchange.
type AuthorizationTransaction struct {
	ID                     shared.ID
	TenantID               shared.ID
	StateHash              string
	NonceHash              string
	PKCEVerifierCiphertext string
	CreatedAt              time.Time
	ExpiresAt              time.Time
	ConsumedAt             *time.Time
}

// NewAuthorizationTransaction validates a transaction after state and nonce were hashed and the
// PKCE verifier was encrypted by the caller.
func NewAuthorizationTransaction(id, tenantID shared.ID, stateHash, nonceHash, pkceVerifierCiphertext string, expiresAt, now time.Time) (AuthorizationTransaction, error) {
	stateHash, nonceHash = strings.TrimSpace(stateHash), strings.TrimSpace(nonceHash)
	if id.IsZero() || tenantID.IsZero() {
		return AuthorizationTransaction{}, fmt.Errorf("%w: authorization transaction id and tenant id are required", shared.ErrValidation)
	}
	if stateHash == "" || nonceHash == "" || strings.TrimSpace(pkceVerifierCiphertext) == "" {
		return AuthorizationTransaction{}, fmt.Errorf("%w: state hash, nonce hash, and PKCE verifier ciphertext are required", shared.ErrValidation)
	}
	if !expiresAt.After(now) {
		return AuthorizationTransaction{}, fmt.Errorf("%w: authorization transaction expiry must be in the future", shared.ErrValidation)
	}
	return AuthorizationTransaction{ID: id, TenantID: tenantID, StateHash: stateHash, NonceHash: nonceHash, PKCEVerifierCiphertext: pkceVerifierCiphertext, CreatedAt: now.UTC(), ExpiresAt: expiresAt.UTC()}, nil
}

// Usable reports whether the transaction has neither been consumed nor expired.
func (t AuthorizationTransaction) Usable(now time.Time) bool {
	return t.ConsumedAt == nil && t.ExpiresAt.After(now)
}

// MaxSessionAge is the absolute lifetime of a browser session, independent of the sliding per-poll
// TTL. Rotation refreshes the sliding expiry but never extends OriginAt, so an actively-polled (or
// stolen-then-kept-alive) session cannot outlive this cap — past it the operator must re-authenticate
// through the OIDC provider.
const MaxSessionAge = 12 * time.Hour

// Session is an opaque browser session. Only token hashes are persisted; no provider credentials
// or raw session/CSRF tokens are retained.
type Session struct {
	ID            shared.ID
	TenantID      shared.ID
	UserID        shared.ID
	TokenHash     string
	CSRFTokenHash string
	Metadata      map[string]string
	// OriginAt is the immutable time the session lineage began at login. It is carried unchanged across
	// every rotation so the absolute-age cap (MaxSessionAge) is measured from first authentication.
	OriginAt  time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// NewSession constructs an opaque session record with bounded, non-secret metadata.
func NewSession(id, tenantID, userID shared.ID, tokenHash, csrfTokenHash string, metadata map[string]string, expiresAt, now time.Time) (Session, error) {
	if id.IsZero() || tenantID.IsZero() || userID.IsZero() {
		return Session{}, fmt.Errorf("%w: session id, tenant id, and user id are required", shared.ErrValidation)
	}
	if strings.TrimSpace(tokenHash) == "" || strings.TrimSpace(csrfTokenHash) == "" {
		return Session{}, fmt.Errorf("%w: session and CSRF token hashes are required", shared.ErrValidation)
	}
	if !expiresAt.After(now) {
		return Session{}, fmt.Errorf("%w: session expiry must be in the future", shared.ErrValidation)
	}
	metadata, err := validMetadata(metadata)
	if err != nil {
		return Session{}, err
	}
	return Session{ID: id, TenantID: tenantID, UserID: userID, TokenHash: tokenHash, CSRFTokenHash: csrfTokenHash, Metadata: metadata, OriginAt: now.UTC(), CreatedAt: now.UTC(), UpdatedAt: now.UTC(), ExpiresAt: expiresAt.UTC()}, nil
}

// Active reports whether a session remains unrevoked and unexpired.
func (s Session) Active(now time.Time) bool {
	return s.RevokedAt == nil && s.ExpiresAt.After(now)
}

// BeyondMaxAge reports whether the session has passed its absolute lifetime cap measured from
// OriginAt. A session that has must not be rotated — the browser is forced back through OIDC. A zero
// OriginAt is treated as beyond the cap (fail closed): a session lineage with no recorded origin
// cannot prove it is within the absolute window.
func (s Session) BeyondMaxAge(now time.Time) bool {
	if s.OriginAt.IsZero() {
		return true
	}
	return !now.Before(s.OriginAt.Add(MaxSessionAge))
}

// Revoke records the terminal revocation timestamp. It is intentionally idempotent on the entity;
// the store detects a concurrent duplicate revoke where callers need that distinction.
func (s *Session) Revoke(now time.Time) {
	if s.RevokedAt != nil {
		return
	}
	at := now.UTC()
	s.RevokedAt = &at
	s.UpdatedAt = at
}

func validMetadata(in map[string]string) (map[string]string, error) {
	if len(in) > maxMetadataEntries {
		return nil, fmt.Errorf("%w: session metadata exceeds %d entries", shared.ErrValidation, maxMetadataEntries)
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if key == "" || len(key) > maxMetadataKeyLen || len(value) > maxMetadataValueLen {
			return nil, fmt.Errorf("%w: invalid session metadata", shared.ErrValidation)
		}
		out[key] = value
	}
	return out, nil
}

// CopySession returns a defensive copy of a session and its mutable metadata.
func CopySession(s Session) Session {
	s.Metadata = copyMetadata(s.Metadata)
	if s.RevokedAt != nil {
		at := *s.RevokedAt
		s.RevokedAt = &at
	}
	return s
}

func copyMetadata(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
