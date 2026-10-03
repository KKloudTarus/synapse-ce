package identityenterprise

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AdmissionService owns raw invitation values and browser credentials. Its store receives only
// digests and sealed session data, preserving the no-code-in-notifications/jobs/URLs invariant.
type AdmissionService struct {
	store  ports.IdentityAdmissionStore
	mailer ports.UserContactMailer
	ids    ports.IDGenerator
	clock  ports.Clock
}

func NewAdmissionService(store ports.IdentityAdmissionStore, mailer ports.UserContactMailer, ids ports.IDGenerator, clock ports.Clock) (*AdmissionService, error) {
	if store == nil || ids == nil || clock == nil {
		return nil, fmt.Errorf("%w: identity admission dependencies missing", shared.ErrValidation)
	}
	return &AdmissionService{store: store, mailer: mailer, ids: ids, clock: clock}, nil
}

type CreatedInvitation struct {
	Invitation ports.IdentityInvitation
	Code       string
}

func (s *AdmissionService) CreateInvitation(ctx context.Context, tenant shared.ID, recipient string, role user.Role, proof ports.IdentityAdminProof) (CreatedInvitation, error) {
	recipient, err := user.NormalizeContactEmail(recipient)
	if err != nil || tenant.IsZero() || !role.Valid() {
		return CreatedInvitation{}, fmt.Errorf("%w: invalid invitation", shared.ErrValidation)
	}
	code, err := admissionSecret()
	if err != nil {
		return CreatedInvitation{}, err
	}
	now := s.clock.Now().UTC()
	v := ports.IdentityInvitation{ID: s.ids.NewID(), TenantID: tenant, Recipient: recipient, Role: role, State: "pending", Version: 1, CreatedAt: now, ExpiresAt: now.Add(7 * 24 * time.Hour)}
	if err = s.store.CreateIdentityInvitation(ctx, ports.IdentityInvitationCreate{Invitation: v, CodeDigest: admissionDigest(code), Actor: proof.Principal.ActorID}, proof); err != nil {
		return CreatedInvitation{}, err
	}
	return CreatedInvitation{Invitation: v, Code: code}, nil
}

// ResolveInvitation routes a typed invitation code without exposing invitation metadata.
func (s *AdmissionService) ResolveInvitation(ctx context.Context, code string) (ports.IdentityInvitationRoute, error) {
	if strings.TrimSpace(code) == "" || strings.TrimSpace(code) != code {
		return ports.IdentityInvitationRoute{}, shared.ErrNotFound
	}
	return s.store.ResolveIdentityInvitationCode(ctx, admissionDigest(code))
}

// NewPersonRequiresSender documents that accepting an invitation for a newly-created person needs
// a mailbox challenge when the callback did not already prove the invitation recipient.
func (s *AdmissionService) NewPersonRequiresSender() bool { return true }

// MailboxChallengeAvailable reports whether this process can deliver an alternate proof.
func (s *AdmissionService) MailboxChallengeAvailable() bool { return s.mailer != nil }

// SendMailboxChallenge sends an alternate mailbox proof directly to the invitation recipient.
// The code exists only during this call and is persisted solely as a digest.
func (s *AdmissionService) SendMailboxChallenge(ctx context.Context, route ports.IdentityInvitationRoute, subject string, person shared.ID) error {
	if s.mailer == nil || route.TenantID.IsZero() || route.InvitationID.IsZero() || strings.TrimSpace(subject) == "" || person.IsZero() {
		return shared.ErrForbidden
	}
	v, err := s.store.GetIdentityInvitation(ctx, route.TenantID, route.InvitationID)
	if err != nil || v.State != "pending" {
		return shared.ErrForbidden
	}
	code, err := admissionSecret()
	if err != nil {
		return err
	}
	now := s.clock.Now().UTC()
	if err = s.store.CreateMailboxChallenge(ctx, route.TenantID, v.ID, v.Version, subject, person, admissionDigest(code), now.Add(10*time.Minute), now); err != nil {
		return err
	}
	if result := s.mailer.SendContactVerification(ctx, v.Recipient, code, v.ID); result.ErrorCode != "" {
		return fmt.Errorf("invitation mailbox delivery failed: %s", result.ErrorCode)
	}
	return nil
}

type AdmitInput struct {
	Command ports.IdentityAdmissionCommand
}

func (s *AdmissionService) Admit(ctx context.Context, in AdmitInput) (ports.IdentityAdmissionResult, error) {
	c := in.Command
	now := s.clock.Now().UTC()
	if c.Now.IsZero() {
		c.Now = now
	}
	if c.Issue.Session.ID.IsZero() {
		c.Issue.Session.ID = s.ids.NewID()
	}
	if c.Issue.Session.CredentialID.IsZero() {
		c.Issue.Session.CredentialID = s.ids.NewID()
	}
	if c.Issue.Session.LineageID.IsZero() {
		c.Issue.Session.LineageID = c.Issue.Session.ID
	}
	if c.Issue.Session.Kind == "" {
		c.Issue.Session.Kind = identity.EnterpriseSessionKindBrowser
	}
	if c.Issue.Session.AuthenticatedAt.IsZero() {
		c.Issue.Session.AuthenticatedAt = c.AuthenticatedAt
	}
	if c.Issue.Session.OriginAt.IsZero() {
		c.Issue.Session.OriginAt = now
	}
	if c.Issue.Session.CreatedAt.IsZero() {
		c.Issue.Session.CreatedAt = now
	}
	if c.Issue.Session.ExpiresAt.IsZero() {
		c.Issue.Session.ExpiresAt = now.Add(12 * time.Hour)
	}
	if strings.TrimSpace(c.Issue.CredentialDigest) == "" {
		return ports.IdentityAdmissionResult{}, fmt.Errorf("%w: browser credential digest required", shared.ErrValidation)
	}
	if c.Purpose == ports.IdentityAuthorizationInvitation && !c.NewPersonID.IsZero() && s.mailer == nil {
		return ports.IdentityAdmissionResult{}, shared.ErrForbidden
	}
	return s.store.AdmitIdentity(ctx, c)
}

func admissionSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func admissionDigest(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
