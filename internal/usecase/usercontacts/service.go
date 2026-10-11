// Package usercontacts owns self-service verified delivery identities.
package usercontacts

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const JobKind = "user_contact_verification"

var ErrMailUnavailable = errors.New("email verification is unavailable")

type Service struct {
	store         ports.UserContactStore
	users         ports.UserRepository
	protector     ports.NotificationSecretProtector
	mailer        ports.UserContactMailer
	ids           ports.IDGenerator
	clock         ports.Clock
	key           []byte
	mailAvailable bool
}

func NewService(store ports.UserContactStore, users ports.UserRepository, protector ports.NotificationSecretProtector, mailer ports.UserContactMailer, ids ports.IDGenerator, clock ports.Clock, key []byte, mailAvailable bool) (*Service, error) {
	if store == nil || users == nil || protector == nil || ids == nil || clock == nil || len(key) < 32 {
		return nil, fmt.Errorf("%w: invalid user-contact service configuration", shared.ErrValidation)
	}
	return &Service{store: store, users: users, protector: protector, mailer: mailer, ids: ids, clock: clock, key: append([]byte(nil), key...), mailAvailable: mailAvailable}, nil
}

// DeriveVerifierKey separates low-entropy code verification from vault AEAD.
// API and worker must use the same configured master secret across restarts.
func DeriveVerifierKey(master string) []byte {
	sum := sha256.Sum256([]byte("synapse:user-contact-code:v1:" + master))
	return sum[:]
}

func (s *Service) List(ctx context.Context, tenantID, userID shared.ID) ([]ports.UserContact, error) {
	return s.store.List(ctx, shared.TenantOrDefault(tenantID), userID)
}

func (s *Service) AddEmail(ctx context.Context, tenantID, userID shared.ID, value string) (ports.UserContact, error) {
	address, err := user.NormalizeContactEmail(value)
	if err != nil {
		return ports.UserContact{}, err
	}
	now := s.clock.Now().UTC()
	return s.store.Create(ctx, ports.UserContact{TenantID: shared.TenantOrDefault(tenantID), ID: s.ids.NewID(), UserID: userID, Kind: "email", Source: "manual", Value: address, Version: 1, CreatedAt: now, UpdatedAt: now})
}

func (s *Service) Delete(ctx context.Context, tenantID, userID, contactID shared.ID) error {
	return s.store.Delete(ctx, shared.TenantOrDefault(tenantID), userID, contactID)
}

func (s *Service) RequestVerification(ctx context.Context, tenantID, userID, contactID shared.ID) error {
	if !s.mailAvailable || s.mailer == nil {
		return ErrMailUnavailable
	}
	tenantID = shared.TenantOrDefault(tenantID)
	contacts, err := s.store.List(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	var contact *ports.UserContact
	for i := range contacts {
		if contacts[i].ID == contactID {
			contact = &contacts[i]
			break
		}
	}
	if contact == nil {
		return shared.ErrNotFound
	}
	if contact.Kind != "email" || contact.VerifiedAt != nil {
		return fmt.Errorf("%w: contact cannot be verified", shared.ErrConflict)
	}
	code, err := randomCode()
	if err != nil {
		return err
	}
	id := s.ids.NewID()
	aad := challengeAAD(tenantID, id, contactID, contact.Version)
	sealed, err := s.protector.Seal([]byte(code), aad)
	if err != nil {
		return fmt.Errorf("seal contact challenge: %w", err)
	}
	now := s.clock.Now().UTC()
	challenge := ports.UserContactChallenge{TenantID: tenantID, ID: id, UserID: userID, ContactID: contactID, ContactVersion: contact.Version, Digest: s.digest(id, code), SealedCode: sealed, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	return s.store.RequestVerification(ctx, challenge, s.ids.NewID())
}

func (s *Service) Verify(ctx context.Context, tenantID, userID, contactID shared.ID, code string) (ports.UserContact, error) {
	if len(code) != 8 || strings.Trim(code, "0123456789") != "" {
		return ports.UserContact{}, fmt.Errorf("%w: invalid verification code", shared.ErrValidation)
	}
	return s.store.Verify(ctx, shared.TenantOrDefault(tenantID), userID, contactID, func(id shared.ID) string { return s.digest(id, code) }, s.clock.Now().UTC())
}

func (s *Service) digest(id shared.ID, code string) string {
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(id.String() + ":" + code))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Service) SendVerification(ctx context.Context, tenantID, challengeID shared.ID) error {
	if s.mailer == nil {
		return ErrMailUnavailable
	}
	tenantID = shared.TenantOrDefault(tenantID)
	work, active, err := s.store.LoadDelivery(ctx, tenantID, challengeID)
	if err != nil || !active {
		return err
	}
	// The store enforces the destination/version fence immediately before this read.
	// The transport may still race a later revoke; SMTP cannot recall accepted mail.
	plain, err := s.protector.Open(work.SealedCode, challengeAAD(tenantID, challengeID, work.ContactID, work.ContactVersion))
	if err != nil {
		return fmt.Errorf("open contact challenge: %w", err)
	}
	result := s.mailer.SendContactVerification(ctx, work.Recipient, string(plain), challengeID)
	for i := range plain {
		plain[i] = 0
	}
	if result.ErrorCode != "" {
		if result.Retryable {
			return fmt.Errorf("verification SMTP transient failure: %s", result.ErrorCode)
		}
		return ErrMailUnavailable
	}
	return s.store.MarkSent(ctx, tenantID, challengeID, s.clock.Now().UTC())
}

func (s *Service) HandleJob(ctx context.Context, job ports.QueuedJob) error {
	if job.Kind != JobKind || job.TenantID.IsZero() {
		return fmt.Errorf("%w: invalid contact verification job", shared.ErrValidation)
	}
	var payload struct {
		ChallengeID shared.ID `json:"challenge_id"`
	}
	if len(job.Payload) > 256 || json.Unmarshal(job.Payload, &payload) != nil || payload.ChallengeID.IsZero() {
		return fmt.Errorf("%w: invalid contact verification payload", shared.ErrValidation)
	}
	return s.SendVerification(ctx, job.TenantID, payload.ChallengeID)
}

func (s *Service) OnDeadLetter(ctx context.Context, job ports.QueuedJob) error {
	if job.Kind != JobKind || job.TenantID.IsZero() {
		return nil
	}
	var payload struct {
		ChallengeID shared.ID `json:"challenge_id"`
	}
	if len(job.Payload) > 256 || json.Unmarshal(job.Payload, &payload) != nil || payload.ChallengeID.IsZero() {
		return nil
	}
	return s.store.MarkDeliveryFailed(ctx, job.TenantID, payload.ChallengeID, s.clock.Now().UTC())
}

func (s *Service) ImportOIDCEmail(ctx context.Context, tenantID, userID shared.ID, issuer, email string) error {
	address, err := user.NormalizeContactEmail(email)
	if err != nil {
		return err
	}
	return s.store.ImportOIDCEmail(ctx, shared.TenantOrDefault(tenantID), userID, s.ids.NewID(), issuer, address, s.clock.Now().UTC())
}

func (s *Service) RevokeOIDCEmail(ctx context.Context, tenantID, userID shared.ID, issuer string) error {
	return s.store.RevokeOIDCEmail(ctx, shared.TenantOrDefault(tenantID), userID, issuer, s.clock.Now().UTC())
}

func randomCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return "", fmt.Errorf("generate verification code: %w", err)
	}
	return fmt.Sprintf("%08d", n.Int64()), nil
}

func challengeAAD(tenantID, challengeID, contactID shared.ID, version int) []byte {
	return []byte("contact-verification:" + tenantID.String() + ":" + challengeID.String() + ":" + contactID.String() + ":" + fmt.Sprint(version))
}
