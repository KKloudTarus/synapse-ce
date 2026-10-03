package identityenterprise

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type authClock struct{ now time.Time }

func (c authClock) Now() time.Time { return c.now }

type authIDs struct{ n int }

func (i *authIDs) NewID() shared.ID { i.n++; return shared.ID(fmt.Sprintf("id-%d", i.n)) }

type authProtector struct{}

func (authProtector) Seal(_ context.Context, p, _ []byte) (string, error) { return string(p), nil }
func (authProtector) Open(_ context.Context, p string, _ []byte) ([]byte, error) {
	return []byte(p), nil
}

type authProvider struct{}

func (authProvider) GenerateVerifier() string                        { return "verifier" }
func (authProvider) AuthorizationURL(_, _, _ string) (string, error) { return "", nil }
func (authProvider) ExchangeAndVerify(context.Context, string, string, string) (ports.OIDCIdentity, error) {
	return ports.OIDCIdentity{}, nil
}
func (authProvider) AuthorizationURLWithMaxAge(_ context.Context, state, _, _ string, _ time.Duration) (string, error) {
	return "https://issuer.example/auth?state=" + state, nil
}
func (authProvider) ExchangeAndVerifyWithMaxAge(_ context.Context, code, verifier, nonce string, _ time.Duration) (ports.OIDCIdentity, error) {
	if code != "code" || verifier != "verifier" || nonce == "" {
		return ports.OIDCIdentity{}, fmt.Errorf("bad proof")
	}
	return ports.OIDCIdentity{Issuer: "https://issuer.example", Subject: "subject", AuthenticatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}, nil
}

type authFactory struct{}

func (authFactory) ProviderForConnection(context.Context, ports.IdentityConnection) (ports.OIDCProvider, error) {
	return authProvider{}, nil
}

type authConnections struct{}

func (authConnections) GetIdentityConnection(_ context.Context, t, id shared.ID, r int) (ports.IdentityConnection, error) {
	return ports.IdentityConnection{TenantID: t, ID: id, Issuer: "https://issuer.example", Enabled: true, Revision: r, DraftRevision: r, TestPassed: true}, nil
}
func (authConnections) ListIdentityConnections(context.Context, shared.ID, bool) ([]ports.IdentityConnection, error) {
	return nil, nil
}
func (authConnections) SaveIdentityConnectionDraft(context.Context, ports.IdentityConnectionDraft, ports.IdentityAdminProof) (ports.IdentityConnection, error) {
	return ports.IdentityConnection{}, nil
}
func (authConnections) RecordIdentityConnectionTest(context.Context, ports.IdentityConnectionTest, ports.IdentityAdminProof) error {
	return nil
}
func (authConnections) ActivateIdentityConnection(context.Context, shared.ID, shared.ID, int, int, ports.IdentityAdminProof) (ports.IdentityConnection, error) {
	return ports.IdentityConnection{}, nil
}
func (authConnections) DisableIdentityConnection(context.Context, shared.ID, shared.ID, int, ports.IdentityAdminProof) (ports.IdentityConnection, error) {
	return ports.IdentityConnection{}, nil
}

type authTransactions struct {
	v        ports.IdentityAuthorizationTransaction
	consumed bool
}

func (s *authTransactions) CreateIdentityAuthorization(_ context.Context, v ports.IdentityAuthorizationTransaction) error {
	s.v = v
	return nil
}
func (s *authTransactions) ConsumeIdentityAuthorization(_ context.Context, _ shared.ID, state, caller string, now time.Time) (ports.IdentityAuthorizationTransaction, error) {
	if s.consumed || state != s.v.StateDigest || caller != s.v.CallerNonceDigest {
		return ports.IdentityAuthorizationTransaction{}, shared.ErrNotFound
	}
	s.consumed = true
	s.v.ConsumedAt = &now
	return s.v, nil
}
func (*authTransactions) CleanupIdentityAuthorizations(context.Context, shared.ID, time.Time, int) (int, error) {
	return 0, nil
}

func TestCallback_BurnsStateAndReturnsVerifiedNeutralEvidence(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)
	tx := &authTransactions{}
	ids := &authIDs{}
	s, err := NewService(authConnections{}, tx, authFactory{}, authProtector{}, authClock{now}, ids)
	if err != nil {
		t.Fatal(err)
	}
	started, err := s.Begin(context.Background(), BeginInput{TenantID: "tenant", ConnectionID: "connection", Revision: 1, Purpose: ports.IdentityAuthorizationLogin, CallerNonce: "browser", Context: []byte("bound-session")})
	if err != nil {
		t.Fatal(err)
	}
	if started.AuthorizationURL == "" || tx.v.PKCEVerifierSealed == "" || tx.v.NonceDigest == "" {
		t.Fatal("transaction did not bind protocol secrets")
	}
	state := started.AuthorizationURL[len("https://issuer.example/auth?state="):]
	out, err := s.Callback(context.Background(), CallbackInput{TenantID: "tenant", State: state, Code: "code", CallerNonce: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Subject != "subject" || string(out.Context) != "bound-session" || !tx.consumed {
		t.Fatalf("unexpected callback result: %+v", out)
	}
	if _, err = s.Callback(context.Background(), CallbackInput{TenantID: "tenant", State: state, Code: "code", CallerNonce: "browser"}); err == nil {
		t.Fatal("replay was accepted")
	}
}
