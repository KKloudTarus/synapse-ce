// Package identityenterprise coordinates immutable OIDC revisions with one-use protocol state.
package identityenterprise

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const authorizationLifetime = 10 * time.Minute

type Service struct {
	connections  ports.IdentityConnectionStore
	transactions ports.IdentityAuthorizationStore
	providers    ports.IdentityOIDCProviderFactory
	protector    ports.IdentitySecretProtector
	clock        ports.Clock
	ids          ports.IDGenerator
}

func NewService(connections ports.IdentityConnectionStore, transactions ports.IdentityAuthorizationStore, providers ports.IdentityOIDCProviderFactory, protector ports.IdentitySecretProtector, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if connections == nil || transactions == nil || providers == nil || protector == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: identity enterprise service is missing a dependency", shared.ErrValidation)
	}
	return &Service{connections: connections, transactions: transactions, providers: providers, protector: protector, clock: clock, ids: ids}, nil
}

type BeginInput struct {
	TenantID     shared.ID
	ConnectionID shared.ID
	Revision     int
	Purpose      ports.IdentityAuthorizationPurpose
	CallerNonce  string
	AdminProof   *ports.IdentityAdminProof
	// Context is authenticated and sealed, and may contain an initiating session identity. It is
	// never copied into state, callback URLs, or provider requests.
	Context []byte
}

type BeginResult struct {
	AuthorizationURL string
	TransactionID    shared.ID
	ExpiresAt        time.Time
}

func (s *Service) Begin(ctx context.Context, in BeginInput) (BeginResult, error) {
	if in.TenantID.IsZero() || in.ConnectionID.IsZero() || !in.Purpose.Valid() || (in.Revision < 0) || strings.TrimSpace(in.CallerNonce) == "" {
		return BeginResult{}, fmt.Errorf("%w: invalid authorization start", shared.ErrValidation)
	}
	if in.Purpose == ports.IdentityAuthorizationTest && in.AdminProof == nil {
		return BeginResult{}, fmt.Errorf("%w: connection test requires administrator proof", shared.ErrForbidden)
	}
	revision := in.Revision
	if revision == 0 {
		// Test uses the current draft revision; all other purposes require the activated revision.
		c, err := s.connections.GetIdentityConnection(ctx, in.TenantID, in.ConnectionID, 0)
		if err != nil {
			return BeginResult{}, err
		}
		if in.Purpose == ports.IdentityAuthorizationTest {
			revision = c.DraftRevision
		} else {
			revision = c.Revision
		}
	}
	c, err := s.connections.GetIdentityConnection(ctx, in.TenantID, in.ConnectionID, revision)
	if err != nil {
		return BeginResult{}, fmt.Errorf("load identity connection: %w", err)
	}
	if in.Purpose != ports.IdentityAuthorizationTest && (!c.Enabled || !c.TestPassed || c.Revision != revision) {
		return BeginResult{}, fmt.Errorf("%w: connection is not active and tested", shared.ErrForbidden)
	}
	p, err := s.providers.ProviderForConnection(ctx, c)
	if err != nil {
		return BeginResult{}, fmt.Errorf("identity provider unavailable: %w", err)
	}
	state, err := randomAuthorizationValue()
	if err != nil {
		return BeginResult{}, err
	}
	nonce, err := randomAuthorizationValue()
	if err != nil {
		return BeginResult{}, err
	}
	verifier := p.GenerateVerifier()
	if strings.TrimSpace(verifier) == "" {
		return BeginResult{}, fmt.Errorf("%w: provider returned no PKCE verifier", shared.ErrValidation)
	}
	now := s.clock.Now().UTC()
	txID := s.ids.NewID()
	sealedVerifier, err := s.protector.Seal(ctx, []byte(verifier), authorizationAAD(in.TenantID, txID, "pkce"))
	if err != nil {
		return BeginResult{}, fmt.Errorf("seal PKCE verifier: %w", err)
	}
	// Nonce is protocol secret material too: retain it only inside the authenticated context
	// envelope so the callback can provide it to signed-token verification.
	contextPayload, err := json.Marshal(sealedCallbackContext{Nonce: nonce, Context: base64.RawURLEncoding.EncodeToString(in.Context), AdminProof: in.AdminProof})
	if err != nil {
		return BeginResult{}, fmt.Errorf("encode authorization context: %w", err)
	}
	sealedContext, err := s.protector.Seal(ctx, contextPayload, authorizationAAD(in.TenantID, txID, "context"))
	if err != nil {
		return BeginResult{}, fmt.Errorf("seal authorization context: %w", err)
	}
	if err := s.transactions.CreateIdentityAuthorization(ctx, ports.IdentityAuthorizationTransaction{ID: txID, TenantID: in.TenantID, Purpose: in.Purpose, ConnectionID: c.ID, ConnectionRevision: revision, StateDigest: digestAuthorization(state), NonceDigest: digestAuthorization(nonce), CallerNonceDigest: digestAuthorization(in.CallerNonce), PKCEVerifierSealed: sealedVerifier, ContextSealed: sealedContext, ExpiresAt: now.Add(authorizationLifetime), CreatedAt: now}); err != nil {
		return BeginResult{}, fmt.Errorf("create authorization transaction: %w", err)
	}
	// OIDCAuthentication is required for all enterprise flows because max_age is part of the
	// sensitive proof contract. A legacy-only provider fails closed.
	sensitive, ok := p.(ports.OIDCAuthentication)
	if !ok {
		return BeginResult{}, fmt.Errorf("%w: provider lacks authenticated protocol flow", shared.ErrForbidden)
	}
	url, err := sensitive.AuthorizationURLWithMaxAge(ctx, state, nonce, verifier, 15*time.Minute)
	if err != nil {
		return BeginResult{}, fmt.Errorf("build authorization URL: %w", err)
	}
	return BeginResult{AuthorizationURL: url, TransactionID: txID, ExpiresAt: now.Add(authorizationLifetime)}, nil
}

type CallbackInput struct {
	TenantID    shared.ID
	State       string
	Code        string
	CallerNonce string
}
type CallbackResult struct {
	Purpose         ports.IdentityAuthorizationPurpose
	TransactionID   shared.ID
	ConnectionID    shared.ID
	Revision        int
	Subject         string
	Email           string
	Name            string
	EmailVerified   bool
	AuthenticatedAt time.Time
	Context         []byte
}
type sealedCallbackContext struct {
	Nonce      string                    `json:"nonce"`
	Context    string                    `json:"context"`
	AdminProof *ports.IdentityAdminProof `json:"admin_proof,omitempty"`
}

// Callback consumes before exchange. It returns neutral verified protocol evidence; admission
// policy and any session/membership mutation are intentionally performed by the caller's command.
func (s *Service) Callback(ctx context.Context, in CallbackInput) (CallbackResult, error) {
	if in.TenantID.IsZero() || strings.TrimSpace(in.State) == "" || strings.TrimSpace(in.Code) == "" || strings.TrimSpace(in.CallerNonce) == "" {
		return CallbackResult{}, fmt.Errorf("%w: invalid authorization callback", shared.ErrValidation)
	}
	now := s.clock.Now().UTC()
	tx, err := s.transactions.ConsumeIdentityAuthorization(ctx, in.TenantID, digestAuthorization(in.State), digestAuthorization(in.CallerNonce), now)
	if err != nil {
		return CallbackResult{}, fmt.Errorf("consume authorization state: %w", err)
	}
	c, err := s.connections.GetIdentityConnection(ctx, tx.TenantID, tx.ConnectionID, tx.ConnectionRevision)
	if err != nil {
		return CallbackResult{}, fmt.Errorf("load callback connection: %w", err)
	}
	if tx.Purpose != ports.IdentityAuthorizationTest && (!c.Enabled || c.Revision != tx.ConnectionRevision || !c.TestPassed) {
		return CallbackResult{}, fmt.Errorf("%w: connection is no longer eligible", shared.ErrForbidden)
	}
	p, err := s.providers.ProviderForConnection(ctx, c)
	if err != nil {
		return CallbackResult{}, fmt.Errorf("identity provider unavailable: %w", err)
	}
	sensitive, ok := p.(ports.OIDCAuthentication)
	if !ok {
		return CallbackResult{}, fmt.Errorf("%w: provider lacks authenticated protocol flow", shared.ErrForbidden)
	}
	verifier, err := s.protector.Open(ctx, tx.PKCEVerifierSealed, authorizationAAD(tx.TenantID, tx.ID, "pkce"))
	if err != nil {
		return CallbackResult{}, fmt.Errorf("open PKCE verifier: %w", err)
	}
	defer zero(verifier)
	payload, err := s.protector.Open(ctx, tx.ContextSealed, authorizationAAD(tx.TenantID, tx.ID, "context"))
	if err != nil {
		return CallbackResult{}, fmt.Errorf("open authorization context: %w", err)
	}
	defer zero(payload)
	var sealed sealedCallbackContext
	if err := json.Unmarshal(payload, &sealed); err != nil || digestAuthorization(sealed.Nonce) != tx.NonceDigest {
		return CallbackResult{}, fmt.Errorf("%w: authorization context is malformed", shared.ErrForbidden)
	}
	identity, err := sensitive.ExchangeAndVerifyWithMaxAge(ctx, in.Code, string(verifier), sealed.Nonce, 15*time.Minute)
	if err != nil {
		return CallbackResult{}, fmt.Errorf("exchange authorization code: %w", err)
	}
	if identity.Issuer != c.Issuer || strings.TrimSpace(identity.Subject) == "" || identity.AuthenticatedAt.IsZero() || identity.AuthenticatedAt.After(now) || !now.Before(identity.AuthenticatedAt.Add(15*time.Minute)) {
		return CallbackResult{}, fmt.Errorf("%w: upstream identity does not satisfy callback policy", shared.ErrForbidden)
	}
	plainContext, err := base64.RawURLEncoding.DecodeString(sealed.Context)
	if err != nil {
		return CallbackResult{}, fmt.Errorf("%w: authorization context encoding is invalid", shared.ErrValidation)
	}
	if tx.Purpose == ports.IdentityAuthorizationTest {
		if sealed.AdminProof == nil {
			return CallbackResult{}, fmt.Errorf("%w: missing connection test proof", shared.ErrForbidden)
		}
		sealed.AdminProof.At = now
		if err := s.connections.RecordIdentityConnectionTest(ctx, ports.IdentityConnectionTest{ID: s.ids.NewID(), TenantID: tx.TenantID, ConnectionID: tx.ConnectionID, Revision: tx.ConnectionRevision, Passed: true, At: now, ExpiresAt: now.Add(24 * time.Hour)}, *sealed.AdminProof); err != nil {
			return CallbackResult{}, fmt.Errorf("record connection test: %w", err)
		}
	}
	return CallbackResult{Purpose: tx.Purpose, TransactionID: tx.ID, ConnectionID: tx.ConnectionID, Revision: tx.ConnectionRevision, Subject: identity.Subject, Email: identity.Email, EmailVerified: identity.EmailVerified, Name: identity.Name, AuthenticatedAt: identity.AuthenticatedAt, Context: plainContext}, nil
}

func authorizationAAD(t, id shared.ID, field string) []byte {
	return []byte("identity-authorization:" + t.String() + ":" + id.String() + ":" + field)
}
func digestAuthorization(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])
}
func randomAuthorizationValue() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate authorization value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
