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

type ProvisioningConfig struct {
	CallbackURL, BootstrapCredentialID string
	AllowedTenant                      func(string) bool
}

// Provisioning owns only an initial connection and the pinned first administrator invitation.
// It never converts its deployment operator into a target organization member.
type Provisioning struct {
	store     ports.IdentityProvisioningStore
	protector ports.IdentitySecretProtector
	clock     ports.Clock
	ids       ports.IDGenerator
	cfg       ProvisioningConfig
}

func NewProvisioning(store ports.IdentityProvisioningStore, protector ports.IdentitySecretProtector, clock ports.Clock, ids ports.IDGenerator, cfg ProvisioningConfig) (*Provisioning, error) {
	u, err := url.Parse(cfg.CallbackURL)
	if store == nil || protector == nil || clock == nil || ids == nil || cfg.AllowedTenant == nil || cfg.BootstrapCredentialID == "" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: initial provisioning requires explicit authority and a fixed HTTPS callback", shared.ErrValidation)
	}
	return &Provisioning{store: store, protector: protector, clock: clock, ids: ids, cfg: cfg}, nil
}

func (s *Provisioning) actorAllowed(p authz.Principal, target shared.ID) bool {
	return p.IsBootstrap() && p.Role == user.RoleAdmin && p.TenantID != "" && p.TenantID != target.String() && p.Credential.ID == s.cfg.BootstrapCredentialID && !target.IsZero() && len(target.String()) <= 128 && strings.TrimSpace(target.String()) == target.String() && s.cfg.AllowedTenant(target.String())
}

func (s *Provisioning) Begin(ctx context.Context, p authz.Principal, target shared.ID, recipient string) (ports.IdentityInitialProvisioning, string, error) {
	if !s.actorAllowed(p, target) {
		return ports.IdentityInitialProvisioning{}, "", shared.ErrForbidden
	}
	if recipient != "" {
		var err error
		recipient, err = user.NormalizeContactEmail(recipient)
		if err != nil {
			return ports.IdentityInitialProvisioning{}, "", shared.ErrValidation
		}
	}
	at := s.clock.Now().UTC()
	state, err := s.store.BeginIdentityProvisioning(ctx, ports.IdentityProvisioningBegin{TenantID: target, ID: s.ids.NewID(), ConnectionID: s.ids.NewID(), InvitationID: s.ids.NewID(), Principal: p, Recipient: recipient, At: at})
	if err != nil {
		return ports.IdentityInitialProvisioning{}, "", err
	}
	if state.State == "closed" {
		return state, "", nil
	}
	proof := ports.IdentityProvisioningProof{TenantID: state.TenantID, ID: state.ID, ConnectionID: state.ConnectionID, InvitationID: state.InvitationID, Principal: p, Recipient: state.Recipient, IssuedAt: at, ExpiresAt: at.Add(15 * time.Minute), At: at}
	if !proof.Active() {
		return ports.IdentityInitialProvisioning{}, "", shared.ErrForbidden
	}
	switch state.State {
	case "open", "draft", "tested", "active", "invited":
	default:
		return ports.IdentityInitialProvisioning{}, "", shared.ErrForbidden
	}
	plain, err := json.Marshal(proof)
	if err != nil {
		return ports.IdentityInitialProvisioning{}, "", err
	}
	defer zero(plain)
	sealed, err := s.protector.Seal(ctx, plain, []byte("identity-initial-provisioning:v1"))
	if err != nil {
		return ports.IdentityInitialProvisioning{}, "", fmt.Errorf("seal initial provisioning authority: %w", err)
	}
	return state, sealed, nil
}

// Proof is also used by a consumed native Test callback, which has no bearer credential.
// It compares the sealed actor binding with the current process configuration before any write.
func (s *Provisioning) Proof(ctx context.Context, token string) (ports.IdentityProvisioningProof, error) {
	var p ports.IdentityProvisioningProof
	if token == "" || len(token) > 8192 {
		return p, shared.ErrForbidden
	}
	plain, err := s.protector.Open(ctx, token, []byte("identity-initial-provisioning:v1"))
	if err != nil {
		return p, shared.ErrForbidden
	}
	defer zero(plain)
	if json.Unmarshal(plain, &p) != nil {
		return ports.IdentityProvisioningProof{}, shared.ErrForbidden
	}
	p.At = s.clock.Now().UTC()
	if !p.Active() || !s.actorAllowed(p.Principal, p.TenantID) {
		return ports.IdentityProvisioningProof{}, shared.ErrForbidden
	}
	return p, nil
}

func (s *Provisioning) RequestProof(ctx context.Context, actor authz.Principal, token string) (ports.IdentityProvisioningProof, error) {
	p, err := s.Proof(ctx, token)
	if err != nil || p.Principal != actor {
		return ports.IdentityProvisioningProof{}, shared.ErrForbidden
	}
	return p, nil
}

func (s *Provisioning) Status(ctx context.Context, actor authz.Principal, token string) (ports.IdentityInitialProvisioning, error) {
	p, err := s.RequestProof(ctx, actor, token)
	if err != nil {
		return ports.IdentityInitialProvisioning{}, err
	}
	return s.store.ReadIdentityProvisioning(ctx, p)
}

func (s *Provisioning) Draft(ctx context.Context, actor authz.Principal, token string, in ConnectionDraftInput) (ports.IdentityInitialProvisioning, error) {
	p, err := s.RequestProof(ctx, actor, token)
	if err != nil {
		return ports.IdentityInitialProvisioning{}, err
	}
	in.ID = p.ConnectionID
	draft, err := prepareConnectionDraft(ctx, s.protector, s.ids, s.cfg.CallbackURL, p.TenantID, in)
	if err != nil {
		return ports.IdentityInitialProvisioning{}, err
	}
	return s.store.SaveIdentityProvisioningDraft(ctx, draft, p)
}

func (s *Provisioning) Activate(ctx context.Context, actor authz.Principal, token string, revision, version int) (ports.IdentityInitialProvisioning, error) {
	p, err := s.RequestProof(ctx, actor, token)
	if err != nil {
		return ports.IdentityInitialProvisioning{}, err
	}
	return s.store.ActivateIdentityProvisioningConnection(ctx, revision, version, p)
}

func (s *Provisioning) RecordTest(ctx context.Context, token string, test ports.IdentityConnectionTest) error {
	p, err := s.Proof(ctx, token)
	if err != nil {
		return err
	}
	if test.TenantID != p.TenantID || test.ConnectionID != p.ConnectionID {
		return shared.ErrForbidden
	}
	test.At = p.At
	test.ExpiresAt = p.At.Add(time.Hour)
	return s.store.RecordIdentityProvisioningTest(ctx, test, p)
}

func (s *Provisioning) Invitation(ctx context.Context, actor authz.Principal, token string) (ports.IdentityInitialProvisioning, string, error) {
	p, err := s.RequestProof(ctx, actor, token)
	if err != nil {
		return ports.IdentityInitialProvisioning{}, "", err
	}
	code, err := admissionSecret()
	if err != nil {
		return ports.IdentityInitialProvisioning{}, "", err
	}
	sealed, err := s.protector.Seal(ctx, []byte(code), provisioningInvitationAAD(p))
	if err != nil {
		return ports.IdentityInitialProvisioning{}, "", fmt.Errorf("seal initial invitation retry result: %w", err)
	}
	v := ports.IdentityInvitation{ID: p.InvitationID, TenantID: p.TenantID, Recipient: p.Recipient, Role: user.RoleAdmin, State: "pending", Version: 1, CreatedAt: p.At, ExpiresAt: p.At.Add(7 * 24 * time.Hour)}
	state, err := s.store.IssueIdentityProvisioningInvitation(ctx, ports.IdentityInvitationCreate{Invitation: v, CodeDigest: admissionDigest(code), Actor: p.Principal.ActorID}, sealed, p)
	if err != nil {
		return ports.IdentityInitialProvisioning{}, "", err
	}
	plain, err := s.protector.Open(ctx, state.InvitationCodeSealed, provisioningInvitationAAD(p))
	if err != nil {
		return ports.IdentityInitialProvisioning{}, "", fmt.Errorf("open initial invitation retry result: %w", err)
	}
	defer zero(plain)
	if len(plain) < 32 || len(plain) > 128 {
		return ports.IdentityInitialProvisioning{}, "", shared.ErrForbidden
	}
	return state, string(plain), nil
}

func provisioningInvitationAAD(p ports.IdentityProvisioningProof) []byte {
	return []byte("identity-initial-invitation:" + p.TenantID.String() + ":" + p.ID.String() + ":" + p.InvitationID.String())
}

// ProvisioningCallbackError carries only a server-owned target for the fixed setup return page.
type ProvisioningCallbackError struct {
	TenantID shared.ID
	Cause    error
}

func (e *ProvisioningCallbackError) Error() string {
	return "initial organization connection Test failed"
}
func (e *ProvisioningCallbackError) Unwrap() error { return e.Cause }
