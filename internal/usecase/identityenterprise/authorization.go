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

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const authorizationLifetime = 10 * time.Minute

type Service struct {
	connections           ports.IdentityConnectionStore
	transactions          ports.IdentityAuthorizationStore
	providers             ports.IdentityOIDCProviderFactory
	protector             ports.IdentitySecretProtector
	clock                 ports.Clock
	ids                   ports.IDGenerator
	bootstrapCredentialID string
	provisioning          *Provisioning
}

func NewService(connections ports.IdentityConnectionStore, transactions ports.IdentityAuthorizationStore, providers ports.IdentityOIDCProviderFactory, protector ports.IdentitySecretProtector, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if connections == nil || transactions == nil || providers == nil || protector == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: identity enterprise service is missing a dependency", shared.ErrValidation)
	}
	return &Service{connections: connections, transactions: transactions, providers: providers, protector: protector, clock: clock, ids: ids}, nil
}

// SetBootstrapCredentialID binds bootstrap Test callbacks to this process's configured
// deployment credential. Composition calls it once before the service handles requests.
func (s *Service) SetBootstrapCredentialID(id string) error {
	if id == "" || strings.TrimSpace(id) != id || len(id) > 256 {
		return fmt.Errorf("%w: bootstrap credential binding is required", shared.ErrValidation)
	}
	if s.bootstrapCredentialID != "" && s.bootstrapCredentialID != id {
		return fmt.Errorf("%w: bootstrap credential binding is already configured", shared.ErrConflict)
	}
	s.bootstrapCredentialID = id
	return nil
}

func (s *Service) SetProvisioning(provisioning *Provisioning) error {
	if provisioning == nil || s.provisioning != nil || provisioning.cfg.BootstrapCredentialID != s.bootstrapCredentialID {
		return fmt.Errorf("%w: initial provisioning authority does not match this process", shared.ErrValidation)
	}
	s.provisioning = provisioning
	return nil
}

type BeginInput struct {
	TenantID          shared.ID
	ConnectionID      shared.ID
	Revision          int
	Purpose           ports.IdentityAuthorizationPurpose
	CallerNonce       string
	AdminProof        *ports.IdentityAdminProof
	ProvisioningToken string
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
	if in.ProvisioningToken != "" && (in.Purpose != ports.IdentityAuthorizationTest || in.AdminProof != nil || s.provisioning == nil) {
		return BeginResult{}, shared.ErrForbidden
	}
	if in.Purpose == ports.IdentityAuthorizationTest && in.AdminProof == nil && in.ProvisioningToken == "" {
		return BeginResult{}, fmt.Errorf("%w: connection test requires administrator proof", shared.ErrForbidden)
	}
	if in.ProvisioningToken != "" {
		proof, err := s.provisioning.Proof(ctx, in.ProvisioningToken)
		if err != nil || proof.TenantID != in.TenantID || proof.ConnectionID != in.ConnectionID {
			return BeginResult{}, shared.ErrForbidden
		}
		state, err := s.provisioning.store.ReadIdentityProvisioning(ctx, proof)
		if err != nil {
			return BeginResult{}, err
		}
		if !provisioningTestEligible(state) {
			return BeginResult{}, shared.ErrForbidden
		}
	} else if in.Purpose == ports.IdentityAuthorizationTest {
		if err := s.checkBootstrapTestProof(in.AdminProof, in.TenantID, s.clock.Now().UTC()); err != nil {
			return BeginResult{}, err
		}
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
	contextPayload, err := json.Marshal(sealedCallbackContext{Nonce: nonce, Context: base64.RawURLEncoding.EncodeToString(in.Context), AdminProof: in.AdminProof, ProvisioningToken: in.ProvisioningToken})
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
		return BeginResult{}, fmt.Errorf("build authorization URL: %w: %w", authz.ErrAuthenticationUnavailable, err)
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
	Purpose              ports.IdentityAuthorizationPurpose
	TransactionID        shared.ID
	ConnectionID         shared.ID
	Revision             int
	Subject              string
	Email                string
	Name                 string
	EmailVerified        bool
	AuthenticatedAt      time.Time
	Context              []byte
	ProvisioningTenantID shared.ID
}
type sealedCallbackContext struct {
	Nonce             string                    `json:"nonce"`
	Context           string                    `json:"context"`
	AdminProof        *ports.IdentityAdminProof `json:"admin_proof,omitempty"`
	ProvisioningToken string                    `json:"initial_provisioning,omitempty"`
}

// Callback consumes before exchange. It returns neutral verified protocol evidence; admission
// policy and any session/membership mutation are intentionally performed by the caller's command.
func (s *Service) Callback(ctx context.Context, in CallbackInput) (out CallbackResult, err error) {
	if in.TenantID.IsZero() || strings.TrimSpace(in.State) == "" || strings.TrimSpace(in.CallerNonce) == "" {
		return CallbackResult{}, fmt.Errorf("%w: invalid authorization callback", shared.ErrValidation)
	}
	now := s.clock.Now().UTC()
	tx, err := s.transactions.ConsumeIdentityAuthorization(ctx, in.TenantID, digestAuthorization(in.State), digestAuthorization(in.CallerNonce), now)
	if err != nil {
		return CallbackResult{}, fmt.Errorf("consume authorization state: %w", err)
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
	if sealed.ProvisioningToken != "" {
		if tx.Purpose != ports.IdentityAuthorizationTest || sealed.AdminProof != nil || s.provisioning == nil {
			return CallbackResult{}, shared.ErrForbidden
		}
		proof, proofErr := s.provisioning.Proof(ctx, sealed.ProvisioningToken)
		if proofErr != nil || proof.TenantID != tx.TenantID || proof.ConnectionID != tx.ConnectionID {
			return CallbackResult{}, shared.ErrForbidden
		}
		state, readErr := s.provisioning.store.ReadIdentityProvisioning(ctx, proof)
		if readErr != nil {
			err = readErr
			return CallbackResult{}, err
		}
		if !provisioningTestEligible(state) {
			return CallbackResult{}, shared.ErrForbidden
		}
		// Only trusted, current provisioning context may select the fixed setup return.
		// Errors before this point must stay on the ordinary fail-closed callback path.
		defer func() {
			if err != nil {
				err = &ProvisioningCallbackError{TenantID: tx.TenantID, Cause: err}
			}
		}()
	} else if tx.Purpose == ports.IdentityAuthorizationTest {
		if err := s.checkBootstrapTestProof(sealed.AdminProof, tx.TenantID, now); err != nil {
			return CallbackResult{}, err
		}
	}
	if strings.TrimSpace(in.Code) == "" {
		return CallbackResult{}, fmt.Errorf("%w: authorization callback did not include a code", shared.ErrValidation)
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
	identity, err := sensitive.ExchangeAndVerifyWithMaxAge(ctx, in.Code, string(verifier), sealed.Nonce, 15*time.Minute)
	if err != nil {
		return CallbackResult{}, fmt.Errorf("exchange authorization code: %w", err)
	}
	now = s.clock.Now().UTC()
	if identity.Issuer != c.Issuer || strings.TrimSpace(identity.Subject) == "" || identity.AuthenticatedAt.IsZero() || identity.AuthenticatedAt.After(now) || !now.Before(identity.AuthenticatedAt.Add(15*time.Minute)) {
		return CallbackResult{}, fmt.Errorf("%w: upstream identity does not satisfy callback policy", shared.ErrForbidden)
	}
	plainContext, err := base64.RawURLEncoding.DecodeString(sealed.Context)
	if err != nil {
		return CallbackResult{}, fmt.Errorf("%w: authorization context encoding is invalid", shared.ErrValidation)
	}
	if tx.Purpose == ports.IdentityAuthorizationTest {
		test := ports.IdentityConnectionTest{ID: s.ids.NewID(), TenantID: tx.TenantID, ConnectionID: tx.ConnectionID, Revision: tx.ConnectionRevision, Passed: true, At: now, ExpiresAt: now.Add(time.Hour)}
		if sealed.ProvisioningToken != "" {
			err = s.provisioning.RecordTest(ctx, sealed.ProvisioningToken, test)
		} else {
			if err := s.checkBootstrapTestProof(sealed.AdminProof, tx.TenantID, now); err != nil {
				return CallbackResult{}, err
			}
			sealed.AdminProof.At = now
			err = s.connections.RecordIdentityConnectionTest(ctx, test, *sealed.AdminProof)
		}
		if err != nil {
			return CallbackResult{}, fmt.Errorf("record connection test: %w", err)
		}
	}
	out = CallbackResult{Purpose: tx.Purpose, TransactionID: tx.ID, ConnectionID: tx.ConnectionID, Revision: tx.ConnectionRevision, Subject: identity.Subject, Email: identity.Email, EmailVerified: identity.EmailVerified, Name: identity.Name, AuthenticatedAt: identity.AuthenticatedAt, Context: plainContext}
	if sealed.ProvisioningToken != "" {
		out.ProvisioningTenantID = tx.TenantID
	}
	return out, nil
}

func (s *Service) checkBootstrapTestProof(proof *ports.IdentityAdminProof, tenant shared.ID, now time.Time) error {
	if proof == nil {
		return fmt.Errorf("%w: missing connection test proof", shared.ErrForbidden)
	}
	p := proof.Principal
	if !p.IsBootstrap() {
		return nil // Native administrator authority is revalidated by the transactional store.
	}
	if s.bootstrapCredentialID == "" || p.Credential != (authz.Credential{Kind: authz.KindBootstrap, ID: s.bootstrapCredentialID}) || p.TenantID != tenant.String() || proof.Bootstrap == nil || !proof.Bootstrap.Active(now) || proof.Bootstrap.Principal != p {
		return fmt.Errorf("%w: bootstrap connection test proof is no longer valid", shared.ErrForbidden)
	}
	return nil
}

// provisioningTestEligible is deliberately narrower than the states that can be
// read or resumed. A Test changes provisioning authority and is allowed only before
// activation, while the scoped operation is drafting or has an existing test.
func provisioningTestEligible(state ports.IdentityInitialProvisioning) bool {
	return state.State == "draft" || state.State == "tested"
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
