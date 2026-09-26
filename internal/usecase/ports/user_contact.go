package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// UserContact is private to its owner. Directory and rule-picker projections must
// never include this record or its verification metadata.
type UserContact struct {
	TenantID   shared.ID  `json:"-"`
	ID         shared.ID  `json:"id"`
	UserID     shared.ID  `json:"-"`
	Kind       string     `json:"kind"`
	Source     string     `json:"source"`
	Value      string     `json:"value"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	Version    int        `json:"version"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

type UserContactChallenge struct {
	TenantID       shared.ID
	ID             shared.ID
	UserID         shared.ID
	ContactID      shared.ID
	ContactVersion int
	Digest         string
	SealedCode     string
	ExpiresAt      time.Time
	CreatedAt      time.Time
}

type UserContactDelivery struct {
	ChallengeID    shared.ID
	ContactID      shared.ID
	ContactVersion int
	Recipient      string
	SealedCode     string
}

// UserContactStore performs challenge and queue writes in one transaction. The
// worker is at-least-once; a pending challenge remains recoverable after a crash.
type UserContactStore interface {
	List(context.Context, shared.ID, shared.ID) ([]UserContact, error)
	Create(context.Context, UserContact) (UserContact, error)
	Delete(context.Context, shared.ID, shared.ID, shared.ID) error
	RequestVerification(context.Context, UserContactChallenge, shared.ID) error
	Verify(context.Context, shared.ID, shared.ID, shared.ID, func(shared.ID) string, time.Time) (UserContact, error)
	LoadDelivery(context.Context, shared.ID, shared.ID) (UserContactDelivery, bool, error)
	MarkSent(context.Context, shared.ID, shared.ID, time.Time) error
	MarkDeliveryFailed(context.Context, shared.ID, shared.ID, time.Time) error
	ImportOIDCEmail(context.Context, shared.ID, shared.ID, shared.ID, string, string, time.Time) error
	RevokeOIDCEmail(context.Context, shared.ID, shared.ID, string, time.Time) error
}

// UserContactMailer sends security verification mail through the existing SMTP
// transport. It does not consult tenant notification rules or user preferences.
type UserContactMailer interface {
	SendContactVerification(context.Context, string, string, shared.ID) NotificationSendResult
}
