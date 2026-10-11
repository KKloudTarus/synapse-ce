// Package identityrecovery owns emergency, recovery-only browser session issuance.
package identityrecovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	MaxSessionLifetime = 15 * time.Minute
	MaxRehearsalAge    = 30 * 24 * time.Hour
	ActivationLifetime = 90 * 24 * time.Hour
)

type Service struct {
	store  ports.IdentityRecoveryStore
	clock  ports.Clock
	ids    ports.IDGenerator
	mailer ports.IdentityRecoveryAlertMailer
}

func NewService(store ports.IdentityRecoveryStore, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if store == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: identity recovery service is missing a dependency", shared.ErrValidation)
	}
	return &Service{store: store, clock: clock, ids: ids}, nil
}

func (s *Service) SetAlertMailer(mailer ports.IdentityRecoveryAlertMailer) { s.mailer = mailer }

func (s *Service) Configure(ctx context.Context, policy ports.IdentityRecoveryPolicy, proof ports.IdentityAdminProof) (ports.IdentityRecoveryPolicy, error) {
	now := s.clock.Now().UTC()
	proof.At = now
	if proof.Recovery {
		if policy.Organization.Requirement != authz.SSOOptional || policy.Organization.LegacyBearerGraceEnabled {
			return ports.IdentityRecoveryPolicy{}, shared.ErrForbidden
		}
	} else if err := authorizeAdmin(proof, policy.TenantID, now); err != nil {
		return ports.IdentityRecoveryPolicy{}, err
	}
	// Readiness fields are server evidence. Never accept them from the policy DTO.
	policy.LastRehearsedAt = time.Time{}
	policy.AlertConfigured = false
	policy.UpdatedAt = now
	return s.store.SaveIdentityRecoveryPolicy(ctx, policy, proof)
}

func (s *Service) Rehearse(ctx context.Context, tenant shared.ID, proof ports.IdentityAdminProof) error {
	now := s.clock.Now().UTC()
	proof.At = now
	if err := authorizeAdmin(proof, tenant, now); err != nil {
		return err
	}
	return s.store.RehearseIdentityRecovery(ctx, tenant, proof, now)
}

func (s *Service) TestAlert(ctx context.Context, tenant shared.ID, recipient string, proof ports.IdentityAdminProof) error {
	now := s.clock.Now().UTC()
	proof.At = now
	if err := authorizeAdmin(proof, tenant, now); err != nil {
		return err
	}
	if s.mailer == nil {
		return fmt.Errorf("%w: recovery alert mailer is unavailable", shared.ErrValidation)
	}
	result := s.mailer.SendIdentityRecoveryAlert(ctx, recipient, s.ids.NewID())
	if result.ErrorCode != "" || result.StatusCode < 200 || result.StatusCode >= 300 {
		return fmt.Errorf("%w: recovery alert delivery failed", shared.ErrConflict)
	}
	return s.store.RecordIdentityRecoveryAlertTest(ctx, tenant, proof, now)
}

// DeliverAlerts is the worker entrypoint. It intentionally bypasses notification rules and sends
// only to active verified administrator contacts resolved by the store at delivery time.
func (s *Service) DeliverAlerts(ctx context.Context, tenant shared.ID, limit int) error {
	if s.mailer == nil {
		return fmt.Errorf("%w: recovery alert mailer is unavailable", shared.ErrValidation)
	}
	if limit < 1 || limit > 100 {
		return fmt.Errorf("%w: recovery alert limit must be 1..100", shared.ErrValidation)
	}
	complete := func(id shared.ID, delivered bool, message string) error {
		// Finish accounting for the one leased alert even if delivery exhausted its deadline.
		// Without this bounded final write, accepted sends could repeat without reaching max attempts.
		bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return s.store.CompleteIdentityRecoveryAlert(bounded, tenant, id, delivered, message, s.clock.Now().UTC())
	}
	for attempted := 0; attempted < limit; attempted++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		alerts, err := s.store.ClaimIdentityRecoveryAlerts(ctx, tenant, s.clock.Now().UTC(), 1)
		if err != nil {
			return err
		}
		if len(alerts) == 0 {
			return nil
		}
		a := alerts[0]
		recipients, e := s.store.IdentityRecoveryAlertRecipients(ctx, tenant, a.MembershipID)
		if e != nil || len(recipients) == 0 {
			msg := "no active verified administrator contact"
			if e != nil {
				msg = "administrator contact lookup unavailable"
			}
			if e = complete(a.ID, false, msg); e != nil {
				return e
			}
			continue
		}
		delivered := true
		message := ""
		for _, recipient := range recipients {
			if ctx.Err() != nil {
				delivered, message = false, "delivery deadline exhausted"
				break
			}
			result := s.mailer.SendIdentityRecoveryAlert(ctx, recipient, a.SessionID)
			if result.ErrorCode != "" || result.StatusCode < 200 || result.StatusCode >= 300 {
				delivered = false
				message = result.ErrorCode
				break
			}
		}
		if e = complete(a.ID, delivered, message); e != nil {
			return e
		}
	}
	return nil
}

// CreateActivation rotates the previous usable recovery secret through the store. The raw value
// is returned once and never persisted.
func (s *Service) CreateActivation(ctx context.Context, tenant, membership, person shared.ID, proof ports.IdentityAdminProof) (string, error) {
	now := s.clock.Now().UTC()
	proof.At = now
	if err := authorizeAdmin(proof, tenant, now); err != nil {
		return "", err
	}
	if tenant.IsZero() || membership.IsZero() || person.IsZero() {
		return "", fmt.Errorf("%w: recovery activation identity is incomplete", shared.ErrValidation)
	}
	raw, err := randomSecret()
	if err != nil {
		return "", err
	}
	if err := s.store.CreateIdentityRecoveryActivation(ctx, ports.IdentityRecoveryActivation{ID: s.ids.NewID(), TenantID: tenant, MembershipID: membership, PersonID: person, SecretDigest: digest(raw), ExpiresAt: now.Add(ActivationLifetime), CreatedAt: now, CreatedBy: proof.Principal.ActorID}, proof); err != nil {
		return "", fmt.Errorf("create recovery activation: %w", err)
	}
	return raw, nil
}

type ActivateInput struct{ Secret string }
type ActivatedSession struct {
	Session   identity.EnterpriseSession
	Token     string
	CSRFToken string
}

// ActivationTenant resolves only the exact secret's routing identity. Consumption still
// rechecks the activation and its membership under tenant authority in one transaction.
func (s *Service) ActivationTenant(ctx context.Context, secret string) (shared.ID, error) {
	if strings.TrimSpace(secret) == "" {
		return "", shared.ErrValidation
	}
	return s.store.ResolveIdentityRecoveryActivationTenant(ctx, digest(secret))
}

func (s *Service) Activate(ctx context.Context, in ActivateInput) (ActivatedSession, error) {
	if strings.TrimSpace(in.Secret) == "" {
		return ActivatedSession{}, fmt.Errorf("%w: recovery activation is required", shared.ErrValidation)
	}
	now := s.clock.Now().UTC()
	token, err := randomSecret()
	if err != nil {
		return ActivatedSession{}, err
	}
	csrf, err := randomSecret()
	if err != nil {
		return ActivatedSession{}, err
	}
	// Tenant and membership are loaded and locked from the activation record by the store, so a
	// caller cannot manufacture a normal or differently privileged session.
	v := identity.EnterpriseSession{ID: s.ids.NewID(), CredentialID: s.ids.NewID(), Kind: identity.EnterpriseSessionKindBreakGlass, LineageID: s.ids.NewID(), AuthenticatedAt: now, OriginAt: now, ExpiresAt: now.Add(MaxSessionLifetime), CSRFTokenHash: digest(csrf), CreatedAt: now, PersonEpoch: 1, MembershipEpoch: 1}
	issued, err := s.store.ConsumeIdentityRecoveryActivation(ctx, ports.IdentityRecoveryConsume{SecretDigest: digest(in.Secret), Issue: ports.IdentitySessionIssue{Session: v, CredentialDigest: digest(token)}, Actor: "identity-recovery", Now: now})
	if err != nil {
		return ActivatedSession{}, fmt.Errorf("activate recovery credential: %w", err)
	}
	return ActivatedSession{Session: issued, Token: token, CSRFToken: csrf}, nil
}

func authorizeAdmin(proof ports.IdentityAdminProof, tenant shared.ID, now time.Time) error {
	p := proof.Principal
	if proof.Bootstrap != nil && proof.Bootstrap.Active(now) {
		return nil
	}
	if p.TenantID != tenant.String() || p.Role != user.RoleAdmin || p.Credential.Kind != authz.KindBrowserSession || !authz.RecentlyAuthenticated(p, now) {
		return fmt.Errorf("%w: fresh organization administrator proof required", shared.ErrForbidden)
	}
	return nil
}
func digest(v string) string { sum := sha256.Sum256([]byte(v)); return hex.EncodeToString(sum[:]) }
func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate recovery secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
