package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// IdentitySessionAuthentication is the complete authorization projection for one routed
// enterprise credential. It is read atomically by the store on every request.
type IdentitySessionAuthentication struct {
	Session identity.EnterpriseSession
	Role    string
}

// IdentitySessionIssue contains only digests. The use case keeps raw values at the HTTP boundary.
type IdentitySessionIssue struct {
	Session          identity.EnterpriseSession
	CredentialDigest string
}

// IdentitySessionSwitch is one atomic source-revoke and destination-issue command. The proof is
// verified by the caller before this command; the store repeats all durable destination fences.
type IdentitySessionSwitch struct {
	SourceCredentialDigest     string
	SourceCSRFTokenHash        string
	DestinationTenantID        shared.ID
	DestinationMembershipID    shared.ID
	DestinationConnectionID    shared.ID
	DestinationSubject         string
	DestinationRevision        int
	DestinationAuthenticatedAt time.Time
	Replacement                IdentitySessionIssue
	RetryKey                   string
	RetryPayloadHash           string
	RetryCiphertext            string
	Now                        time.Time
}

// IdentitySessionSwitchReplay contains only the exact opaque replay locator and a proof that the
// caller still holds the source browser session's CSRF secret. It never carries a replacement
// identity supplied by a browser.
type IdentitySessionSwitchReplay struct {
	SourceCredentialDigest string
	SourceCSRFTokenHash    string
	RetryKey               string
	PayloadHash            string
	Now                    time.Time
}

// IdentitySessionSwitchResult returns the retained encrypted response only for an exact replay.
type IdentitySessionSwitchResult struct {
	Session         identity.EnterpriseSession
	RetryCiphertext string
	Replayed        bool
}

// IdentitySessionStore owns authoritative browser-session reads and all consequential session
// writes. Switch is deliberately one command because ordinary tenant transactions cannot safely
// rebind RLS from a source tenant to a destination tenant.
type IdentitySessionStore interface {
	AuthenticateEnterpriseSession(ctx context.Context, credentialDigest string, now time.Time) (IdentitySessionAuthentication, error)
	CreateEnterpriseSession(ctx context.Context, issue IdentitySessionIssue, actor string, now time.Time) error
	RotateEnterpriseSession(ctx context.Context, sourceCredentialDigest string, issue IdentitySessionIssue, actor string, now time.Time) error
	LogoutEnterpriseSession(ctx context.Context, credentialDigest, actor string, now time.Time) error
	SwitchEnterpriseSession(ctx context.Context, command IdentitySessionSwitch, actor string) (IdentitySessionSwitchResult, error)
	ReplayEnterpriseSessionSwitch(ctx context.Context, replay IdentitySessionSwitchReplay) (IdentitySessionSwitchResult, error)
	CleanupEnterpriseSessionRetries(ctx context.Context, tenantID shared.ID, now time.Time, limit int) (int, error)
}

// IdentityDestinationProof confirms an approved destination connection subject for one person.
// It must perform no network call while an IdentitySessionStore switch transaction is open.
type IdentityDestinationProof interface {
	VerifyDestinationProof(ctx context.Context, tenantID, connectionID, personID shared.ID, subject string, revision int, now time.Time) error
}
