// Package identitysessions issues and switches authoritative enterprise browser sessions.
package identitysessions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type Service struct {
	store     ports.IdentitySessionStore
	proofs    ports.IdentityDestinationProof
	protector ports.IdentitySecretProtector
	clock     ports.Clock
	ids       ports.IDGenerator
}

func NewService(store ports.IdentitySessionStore, proofs ports.IdentityDestinationProof, protector ports.IdentitySecretProtector, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if store == nil || proofs == nil || protector == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: identity sessions service is missing a dependency", shared.ErrValidation)
	}
	return &Service{store: store, proofs: proofs, protector: protector, clock: clock, ids: ids}, nil
}

type CreatedSession struct {
	Session   identity.EnterpriseSession
	Token     string
	CSRFToken string
}

// Authenticate delegates every durable authorization fence to the authoritative store. A CSRF
// mismatch is deliberately rejected after session lookup so it cannot become a credential oracle.
func (s *Service) Authenticate(ctx context.Context, token, csrf string, unsafe bool) (ports.IdentitySessionAuthentication, error) {
	if strings.TrimSpace(token) == "" {
		return ports.IdentitySessionAuthentication{}, invalidCredential("missing browser credential")
	}
	auth, err := s.store.AuthenticateEnterpriseSession(ctx, digest(token), s.clock.Now().UTC())
	if errors.Is(err, shared.ErrNotFound) || errors.Is(err, shared.ErrForbidden) || errors.Is(err, shared.ErrConflict) {
		return ports.IdentitySessionAuthentication{}, invalidCredential("enterprise session is not active")
	}
	if err != nil {
		return ports.IdentitySessionAuthentication{}, fmt.Errorf("authenticate enterprise session: %w: %w", authz.ErrAuthenticationUnavailable, err)
	}
	if unsafe && (strings.TrimSpace(csrf) == "" || subtle.ConstantTimeCompare([]byte(auth.Session.CSRFTokenHash), []byte(digest(csrf))) != 1) {
		return ports.IdentitySessionAuthentication{}, fmt.Errorf("CSRF token does not match: %w: %w", authz.ErrCSRFInvalid, shared.ErrForbidden)
	}
	return auth, nil
}

// Create issues a browser-session or distinct break-glass credential after the caller has
// completed its authentication policy. The store is still responsible for durable lifecycle and
// connection fences at commit time.
func (s *Service) Create(ctx context.Context, session identity.EnterpriseSession, actor string) (CreatedSession, error) {
	token, err := randomValue()
	if err != nil {
		return CreatedSession{}, err
	}
	csrf, err := randomValue()
	if err != nil {
		return CreatedSession{}, err
	}
	now := s.clock.Now().UTC()
	session.ID = s.ids.NewID()
	session.CredentialID = s.ids.NewID()
	if session.LineageID.IsZero() {
		session.LineageID = session.ID
	}
	session.CSRFTokenHash = digest(csrf)
	session.CreatedAt = now
	if session.Kind == identity.EnterpriseSessionKindBreakGlass {
		if session.AuthenticatedAt.IsZero() {
			session.AuthenticatedAt = now
		}
		if session.OriginAt.IsZero() {
			session.OriginAt = now
		}
	} else if session.AuthenticatedAt.IsZero() || session.OriginAt.IsZero() {
		return CreatedSession{}, fmt.Errorf("%w: browser session requires verified upstream authentication time and origin", shared.ErrValidation)
	}
	if err := session.Valid(); err != nil {
		return CreatedSession{}, err
	}
	if err := s.store.CreateEnterpriseSession(ctx, ports.IdentitySessionIssue{Session: session, CredentialDigest: digest(token)}, actor, now); err != nil {
		return CreatedSession{}, fmt.Errorf("create enterprise session: %w", err)
	}
	return CreatedSession{Session: session, Token: token, CSRFToken: csrf}, nil
}

func (s *Service) Logout(ctx context.Context, token, actor string) error {
	if strings.TrimSpace(token) == "" {
		return invalidCredential("missing browser credential")
	}
	if err := s.store.LogoutEnterpriseSession(ctx, digest(token), actor, s.clock.Now().UTC()); err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return invalidCredential("enterprise session is not active")
		}
		return fmt.Errorf("logout enterprise session: %w", err)
	}
	return nil
}

// Rotate replaces a current session while preserving its immutable lineage and upstream
// authentication time. It never treats rotation as a fresh SSO authentication.
func (s *Service) Rotate(ctx context.Context, sourceToken string, previous identity.EnterpriseSession, actor string, expiresAt time.Time) (CreatedSession, error) {
	if strings.TrimSpace(sourceToken) == "" || previous.BeyondMaxAge(s.clock.Now()) {
		return CreatedSession{}, invalidCredential("enterprise session is not eligible for rotation")
	}
	replacement := previous
	replacement.ID, replacement.CredentialID = s.ids.NewID(), s.ids.NewID()
	replacement.RotatedFromSessionID = previous.ID
	replacement.CreatedAt = s.clock.Now().UTC()
	replacement.ExpiresAt = expiresAt.UTC()
	token, err := randomValue()
	if err != nil {
		return CreatedSession{}, err
	}
	csrf, err := randomValue()
	if err != nil {
		return CreatedSession{}, err
	}
	replacement.CSRFTokenHash = digest(csrf)
	if err = replacement.Valid(); err != nil {
		return CreatedSession{}, err
	}
	if err = s.store.RotateEnterpriseSession(ctx, digest(sourceToken), ports.IdentitySessionIssue{Session: replacement, CredentialDigest: digest(token)}, actor, replacement.CreatedAt); err != nil {
		return CreatedSession{}, fmt.Errorf("rotate enterprise session: %w", err)
	}
	return CreatedSession{Session: replacement, Token: token, CSRFToken: csrf}, nil
}

// Picker projects only memberships of the person proven by the active source credential.
func (s *Service) Picker(ctx context.Context, token, csrf string, unsafe bool) ([]ports.IdentityMembershipChoice, error) {
	auth, err := s.Authenticate(ctx, token, csrf, unsafe)
	if err != nil {
		return nil, err
	}
	projection, ok := s.store.(ports.IdentityMembershipProjection)
	if !ok {
		return nil, fmt.Errorf("identity membership projection is unavailable: %w", authz.ErrAuthenticationUnavailable)
	}
	return projection.ActiveMembershipsForPerson(ctx, digest(token), auth.Session.PersonID)
}

type SwitchInput struct {
	SourceToken                string
	SourceCSRFToken            string
	DestinationTenantID        shared.ID
	DestinationMembershipID    shared.ID
	DestinationConnectionID    shared.ID
	DestinationSubject         string
	DestinationRevision        int
	DestinationAuthenticatedAt time.Time
	PersonID                   shared.ID
	Kind                       string
	ExpiresAt                  time.Time
	PersonEpoch                int64
	MembershipEpoch            int64
	ConnectionEpoch            int64
	RetryKey                   string
	RetryPayload               string
}

type ReplayInput struct {
	SourceToken     string
	SourceCSRFToken string
	RetryKey        string
	RetryPayload    string
}

const (
	maxSwitchRetryKeyLength     = 256
	maxSwitchRetryPayloadLength = 16 * 1024
)

func (s *Service) Switch(ctx context.Context, in SwitchInput, actor string) (CreatedSession, error) {
	if strings.TrimSpace(in.SourceToken) == "" || in.DestinationTenantID.IsZero() || in.DestinationMembershipID.IsZero() || in.PersonID.IsZero() || (!in.DestinationConnectionID.IsZero() && (in.DestinationRevision < 1 || in.DestinationAuthenticatedAt.IsZero())) || (in.DestinationConnectionID.IsZero() && in.DestinationRevision != 0) || !validSwitchReplayInput(in.RetryKey, in.RetryPayload) {
		return CreatedSession{}, fmt.Errorf("%w: incomplete enterprise session switch", shared.ErrValidation)
	}
	now := s.clock.Now().UTC()
	// Network-backed proof is intentionally outside the store transaction. The command below
	// repeats all persistent predicates under its deterministic locks.
	if !in.DestinationConnectionID.IsZero() {
		if err := s.proofs.VerifyDestinationProof(ctx, in.DestinationTenantID, in.DestinationConnectionID, in.PersonID, in.DestinationSubject, in.DestinationRevision, now); err != nil {
			return CreatedSession{}, fmt.Errorf("destination reauthentication required: %w", err)
		}
	}
	token, err := randomValue()
	if err != nil {
		return CreatedSession{}, err
	}
	csrf, err := randomValue()
	if err != nil {
		return CreatedSession{}, err
	}
	authenticatedAt := in.DestinationAuthenticatedAt
	if authenticatedAt.IsZero() {
		source, err := s.Authenticate(ctx, in.SourceToken, "", false)
		if err != nil {
			return CreatedSession{}, err
		}
		authenticatedAt = source.Session.AuthenticatedAt
	}
	session := identity.EnterpriseSession{ID: s.ids.NewID(), TenantID: in.DestinationTenantID, CredentialID: s.ids.NewID(), MembershipID: in.DestinationMembershipID, PersonID: in.PersonID, ConnectionID: in.DestinationConnectionID, Kind: in.Kind, LineageID: s.ids.NewID(), AuthenticatedAt: authenticatedAt, OriginAt: now, ExpiresAt: in.ExpiresAt.UTC(), PersonEpoch: in.PersonEpoch, MembershipEpoch: in.MembershipEpoch, ConnectionEpoch: in.ConnectionEpoch, CSRFTokenHash: digest(csrf), CreatedAt: now}
	if err := session.Valid(); err != nil {
		return CreatedSession{}, err
	}
	plain := token + "\n" + csrf
	sourceDigest := digest(in.SourceToken)
	payloadHash := digest(in.RetryPayload)
	ciphertext, err := s.protector.Seal(ctx, []byte(plain), []byte(switchReplayAAD(sourceDigest, in.RetryKey, payloadHash)))
	if err != nil {
		return CreatedSession{}, fmt.Errorf("seal session switch response: %w", err)
	}
	result, err := s.store.SwitchEnterpriseSession(ctx, ports.IdentitySessionSwitch{SourceCredentialDigest: sourceDigest, SourceCSRFTokenHash: optionalDigest(in.SourceCSRFToken), DestinationTenantID: in.DestinationTenantID, DestinationMembershipID: in.DestinationMembershipID, DestinationConnectionID: in.DestinationConnectionID, DestinationSubject: in.DestinationSubject, DestinationRevision: in.DestinationRevision, DestinationAuthenticatedAt: in.DestinationAuthenticatedAt, Replacement: ports.IdentitySessionIssue{Session: session, CredentialDigest: digest(token)}, RetryKey: in.RetryKey, RetryPayloadHash: payloadHash, RetryCiphertext: ciphertext, Now: now}, actor)
	if err != nil {
		return CreatedSession{}, fmt.Errorf("switch enterprise session: %w", err)
	}
	if result.Replayed {
		opened, err := s.protector.Open(ctx, result.RetryCiphertext, []byte(switchReplayAAD(sourceDigest, in.RetryKey, payloadHash)))
		if err != nil {
			return CreatedSession{}, fmt.Errorf("open retained switch response: %w", err)
		}
		parts := strings.Split(string(opened), "\n")
		if len(parts) != 2 {
			return CreatedSession{}, fmt.Errorf("%w: retained switch response is malformed", shared.ErrValidation)
		}
		token, csrf = parts[0], parts[1]
	}
	return CreatedSession{Session: result.Session, Token: token, CSRFToken: csrf}, nil
}

// Replay returns the retained source-bound switch response without first authenticating the
// revoked source credential. The store verifies the source CSRF hash and every destination fence.
func (s *Service) Replay(ctx context.Context, in ReplayInput) (CreatedSession, error) {
	if strings.TrimSpace(in.SourceToken) == "" || strings.TrimSpace(in.SourceCSRFToken) == "" || !validSwitchReplayInput(in.RetryKey, in.RetryPayload) {
		return CreatedSession{}, fmt.Errorf("%w: incomplete enterprise session switch replay", shared.ErrValidation)
	}
	sourceDigest := digest(in.SourceToken)
	payloadHash := digest(in.RetryPayload)
	result, err := s.store.ReplayEnterpriseSessionSwitch(ctx, ports.IdentitySessionSwitchReplay{SourceCredentialDigest: sourceDigest, SourceCSRFTokenHash: digest(in.SourceCSRFToken), RetryKey: in.RetryKey, PayloadHash: payloadHash, Now: s.clock.Now().UTC()})
	if err != nil {
		return CreatedSession{}, fmt.Errorf("replay enterprise session switch: %w", err)
	}
	opened, err := s.protector.Open(ctx, result.RetryCiphertext, []byte(switchReplayAAD(sourceDigest, in.RetryKey, payloadHash)))
	if err != nil {
		return CreatedSession{}, fmt.Errorf("open retained switch response: %w", err)
	}
	parts := strings.Split(string(opened), "\n")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return CreatedSession{}, fmt.Errorf("%w: retained switch response is malformed", shared.ErrValidation)
	}
	return CreatedSession{Session: result.Session, Token: parts[0], CSRFToken: parts[1]}, nil
}

func validSwitchReplayInput(key, payload string) bool {
	return strings.TrimSpace(key) != "" && len(key) <= maxSwitchRetryKeyLength && strings.TrimSpace(payload) != "" && len(payload) <= maxSwitchRetryPayloadLength
}

func optionalDigest(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return digest(value)
}

func switchReplayAAD(sourceDigest, key, payloadHash string) string {
	return "identity-session-switch:" + sourceDigest + ":" + key + ":" + payloadHash
}

func invalidCredential(message string) error {
	return fmt.Errorf("%s: %w: %w", message, authz.ErrCredentialInvalid, shared.ErrForbidden)
}
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func randomValue() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate secure random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
