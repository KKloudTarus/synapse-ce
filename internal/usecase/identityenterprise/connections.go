package identityenterprise

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Connections administers immutable tested OIDC revisions without manufacturing membership.
type Connections struct {
	store       ports.IdentityConnectionStore
	protector   ports.IdentitySecretProtector
	clock       ports.Clock
	ids         ports.IDGenerator
	callbackURL string
}

func NewConnections(store ports.IdentityConnectionStore, protector ports.IdentitySecretProtector, clock ports.Clock, ids ports.IDGenerator, callbackURL string) (*Connections, error) {
	u, err := url.Parse(callbackURL)
	if store == nil || protector == nil || clock == nil || ids == nil || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return nil, fmt.Errorf("%w: connection administration requires a fixed HTTPS callback and dependencies", shared.ErrValidation)
	}
	return &Connections{store: store, protector: protector, clock: clock, ids: ids, callbackURL: callbackURL}, nil
}

// BeginBootstrap requires the explicitly authenticated deployment principal. The sealed proof
// is returned once for initial provisioning and cannot authenticate an ordinary application route.
func (s *Connections) BeginBootstrap(ctx context.Context, p authz.Principal) (string, error) {
	if !p.IsBootstrap() || p.TenantID == "" {
		return "", shared.ErrForbidden
	}
	at := s.clock.Now().UTC()
	proof := authz.BootstrapEligibility{Principal: p, VerifiedAt: at, ExpiresAt: at.Add(15 * time.Minute)}
	plain, err := json.Marshal(proof)
	if err != nil {
		return "", err
	}
	return s.protector.Seal(ctx, plain, []byte("identity-bootstrap:"+p.TenantID+":"+p.Credential.ID))
}

func (s *Connections) AdminProof(ctx context.Context, p authz.Principal, bootstrapToken string) (ports.IdentityAdminProof, error) {
	proof := ports.IdentityAdminProof{Principal: p, At: s.clock.Now().UTC()}
	if p.IsBootstrap() {
		plain, err := s.protector.Open(ctx, bootstrapToken, []byte("identity-bootstrap:"+p.TenantID+":"+p.Credential.ID))
		if err != nil {
			return proof, shared.ErrForbidden
		}
		var eligibility authz.BootstrapEligibility
		if json.Unmarshal(plain, &eligibility) != nil || !eligibility.Active(proof.At) || eligibility.Principal.ActorID != p.ActorID || eligibility.Principal.TenantID != p.TenantID || eligibility.Principal.Credential != p.Credential {
			return proof, shared.ErrForbidden
		}
		proof.Bootstrap = &eligibility
	} else if p.Credential.Kind != authz.KindBrowserSession || p.Role != user.RoleAdmin || p.PersonID == "" || !authz.RecentlyAuthenticated(p, proof.At) {
		return proof, shared.ErrForbidden
	}
	return proof, nil
}

// RepairProof admits emergency proof only at the closed identity repair boundary.
func (s *Connections) RepairProof(ctx context.Context, p authz.Principal, bootstrapToken string) (ports.IdentityAdminProof, error) {
	if p.Credential.Kind == authz.KindBreakGlass && p.Role == user.RoleAdmin && p.PersonID != "" && p.MembershipID != "" {
		return ports.IdentityAdminProof{Principal: p, At: s.clock.Now().UTC(), Recovery: true}, nil
	}
	return s.AdminProof(ctx, p, bootstrapToken)
}

type ConnectionDraftInput struct {
	ID              shared.ID
	DisplayName     string
	Issuer          string
	ClientID        string
	ClientSecret    string
	ExpectedVersion int
}

func (s *Connections) SaveDraft(ctx context.Context, p authz.Principal, bootstrapToken string, in ConnectionDraftInput) (ports.IdentityConnection, error) {
	proof, err := s.RepairProof(ctx, p, bootstrapToken)
	if err != nil {
		return ports.IdentityConnection{}, err
	}
	u, err := url.Parse(in.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.TrimSpace(in.DisplayName) == "" || len(in.DisplayName) > 200 || strings.TrimSpace(in.ClientID) == "" || len(in.ClientID) > 512 || len(in.ClientSecret) > 4096 || in.ClientSecret == "" {
		return ports.IdentityConnection{}, shared.ErrValidation
	}
	if in.ID.IsZero() {
		in.ID = s.ids.NewID()
	}
	sealed, err := s.protector.Seal(ctx, []byte(in.ClientSecret), []byte("identity-connection:"+p.TenantID+":"+in.ID.String()))
	if err != nil {
		return ports.IdentityConnection{}, fmt.Errorf("seal connection client secret: %w", err)
	}
	return s.store.SaveIdentityConnectionDraft(ctx, ports.IdentityConnectionDraft{TenantID: shared.ID(p.TenantID), ID: in.ID, DisplayName: strings.TrimSpace(in.DisplayName), Issuer: strings.TrimRight(u.String(), "/"), Settings: ports.IdentityOIDCSettings{ClientID: in.ClientID, RedirectURL: s.callbackURL, SealedClientSecret: sealed}, ExpectedVersion: in.ExpectedVersion}, proof)
}

func (s *Connections) Activate(ctx context.Context, p authz.Principal, bootstrapToken string, id shared.ID, revision, version int) (ports.IdentityConnection, error) {
	proof, err := s.RepairProof(ctx, p, bootstrapToken)
	if err != nil {
		return ports.IdentityConnection{}, err
	}
	return s.store.ActivateIdentityConnection(ctx, shared.ID(p.TenantID), id, revision, version, proof)
}

func (s *Connections) Disable(ctx context.Context, p authz.Principal, bootstrapToken string, id shared.ID, version int) (ports.IdentityConnection, error) {
	proof, err := s.RepairProof(ctx, p, bootstrapToken)
	if err != nil {
		return ports.IdentityConnection{}, err
	}
	return s.store.DisableIdentityConnection(ctx, shared.ID(p.TenantID), id, version, proof)
}

func (s *Connections) TestResult(ctx context.Context, p authz.Principal, bootstrapToken string, id shared.ID, revision int, passed bool) error {
	proof, err := s.AdminProof(ctx, p, bootstrapToken)
	if err != nil {
		return err
	}
	return s.store.RecordIdentityConnectionTest(ctx, ports.IdentityConnectionTest{ID: s.ids.NewID(), TenantID: shared.ID(p.TenantID), ConnectionID: id, Revision: revision, Passed: passed, At: proof.At, ExpiresAt: proof.At.Add(time.Hour)}, proof)
}
