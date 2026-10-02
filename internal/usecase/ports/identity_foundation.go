package ports

import (
	"context"
	"errors"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

// The identity foundation is additive: users stays the writer of record until a tenant declares
// cutover, and nothing here authenticates a request on its own.

// ErrIdentityNotRepresentable rejects a write that could not round-trip to the legacy users model
// before the tenant declares cutover, such as a second membership for one person or a native
// credential. Returned errors also wrap shared.ErrConflict.
var ErrIdentityNotRepresentable = errors.New("identity write is not representable in the legacy user model before cutover")

// ErrIdentityLifecycle rejects a membership, credential, connection or delivery transition that
// the lifecycle rules forbid, such as a source reactivation over a manual suspension or restoring a
// removed membership without an approved rejoin. Returned errors also wrap shared.ErrConflict.
var ErrIdentityLifecycle = errors.New("identity lifecycle transition rejected")

// ErrIdentityFenceLost reports that a newer backfill run owns the tenant fence. Returned errors
// also wrap shared.ErrConflict.
var ErrIdentityFenceLost = errors.New("identity backfill fence is held by a newer run")

// IdentityCredentialKind is the closed set of routable credential kinds.
type IdentityCredentialKind string

const (
	IdentityCredentialAPIKey         IdentityCredentialKind = "api_key"
	IdentityCredentialBrowserSession IdentityCredentialKind = "browser_session"
	IdentityCredentialBreakGlass     IdentityCredentialKind = "break_glass"
)

// Valid reports whether k is one of the closed credential kinds.
func (k IdentityCredentialKind) Valid() bool {
	switch k {
	case IdentityCredentialAPIKey, IdentityCredentialBrowserSession, IdentityCredentialBreakGlass:
		return true
	}
	return false
}

// IdentityCredentialRoute is the only information exact-digest routing reveals. Every later read
// binds TenantID through row level security.
type IdentityCredentialRoute struct {
	TenantID shared.ID
	Kind     IdentityCredentialKind
}

// IdentityCredentialRouter resolves one exact SHA-256 hex digest to its tenant and kind. There is no
// list, prefix or email lookup. An unknown, revoked or malformed digest returns shared.ErrNotFound.
type IdentityCredentialRouter interface {
	RouteCredentialDigest(ctx context.Context, digest string) (IdentityCredentialRoute, error)
}

// IdentityMembershipChoice is one entry of the organization picker.
type IdentityMembershipChoice struct {
	TenantID     shared.ID
	MembershipID shared.ID
	TenantLabel  string
	Role         user.Role
}

// IdentityMembershipProjection exposes only the authenticated person's own active memberships. The
// caller proves the person by presenting an active credential digest bound to that person, so the
// projection cannot enumerate other people. A suspended person, a suspended or removed membership,
// or a digest of another person yields no entries.
type IdentityMembershipProjection interface {
	ActiveMembershipsForPerson(ctx context.Context, credentialDigest string, personID shared.ID) ([]IdentityMembershipChoice, error)
	// PersonEpoch returns the current person epoch, or shared.ErrNotFound when the digest does not
	// bind an active person.
	PersonEpoch(ctx context.Context, credentialDigest string, personID shared.ID) (int64, error)
}

// IdentityPersonAction is the closed set of platform-owned person commands.
type IdentityPersonAction string

const (
	IdentityPersonCreated         IdentityPersonAction = "person.created"
	IdentityPersonSessionsRevoked IdentityPersonAction = "person.sessions_revoked"
	IdentityPersonSuspended       IdentityPersonAction = "person.suspended"
	IdentityPersonReactivated     IdentityPersonAction = "person.reactivated"
)

// IdentityPersonCommandResult reports the effect of a person command. Obligations counts the
// per-tenant delivery obligations appended in the same transaction.
type IdentityPersonCommandResult struct {
	PersonEpoch int64
	AuditID     int64
	Obligations int
}

// IdentityPersonCommands applies a person-global action. The mutation, the chained platform audit
// row and one immutable delivery obligation per member tenant commit or roll back together.
type IdentityPersonCommands interface {
	ApplyPersonCommand(ctx context.Context, personID shared.ID, action IdentityPersonAction, actor, reason string) (IdentityPersonCommandResult, error)
}

// IdentityMembershipState is the explicit membership lifecycle.
type IdentityMembershipState string

const (
	IdentityMembershipActive    IdentityMembershipState = "active"
	IdentityMembershipSuspended IdentityMembershipState = "suspended"
	IdentityMembershipRemoved   IdentityMembershipState = "removed"
)

// IdentityTransitionSource distinguishes an administrator's decision from an identity-source
// lifecycle signal. A source signal never overrides a manual suspension.
type IdentityTransitionSource string

const (
	IdentityTransitionManual IdentityTransitionSource = "manual"
	IdentityTransitionSignal IdentityTransitionSource = "source"
)

// IdentityMembership is the tenant-owned membership record.
type IdentityMembership struct {
	TenantID         shared.ID
	ID               shared.ID
	PersonID         shared.ID
	LegacyUserID     shared.ID
	Role             user.Role
	State            IdentityMembershipState
	SuspensionSource IdentityTransitionSource
	Epoch            int64
	Version          int
	UpdatedAt        time.Time
}

// IdentityMembershipChangeKind is the closed set of membership commands.
type IdentityMembershipChangeKind string

const (
	IdentityMembershipChangeRole       IdentityMembershipChangeKind = "change_role"
	IdentityMembershipChangeSuspend    IdentityMembershipChangeKind = "suspend"
	IdentityMembershipChangeReactivate IdentityMembershipChangeKind = "reactivate"
	IdentityMembershipChangeRemove     IdentityMembershipChangeKind = "remove"
	IdentityMembershipChangeRejoin     IdentityMembershipChangeKind = "rejoin"
)

// IdentityMembershipChange is one audited membership command. ExpectedVersion guards lost updates.
type IdentityMembershipChange struct {
	Kind            IdentityMembershipChangeKind
	Role            user.Role
	Source          IdentityTransitionSource
	ApprovedBy      string
	ExpectedVersion int
	Actor           string
	At              time.Time
}

// IdentityEpochs are the revocation scopes a session is pinned to.
type IdentityEpochs struct {
	Person     int64
	Membership int64
	Connection int64
}

// IdentityMembershipStore is the audit-owning, tenant-bound membership command store. Every
// mutation appends its tenant audit record in the same transaction. Before cutover declaration
// every native change returns ErrIdentityNotRepresentable.
type IdentityMembershipStore interface {
	GetMembership(ctx context.Context, tenantID, membershipID shared.ID) (IdentityMembership, error)
	// AddMembership adds an existing person to tenantID, projecting a tenant-local users row through
	// the membership legacy user ID so existing users foreign keys keep working.
	AddMembership(ctx context.Context, tenantID, personID shared.ID, name string, role user.Role, actor string, at time.Time) (IdentityMembership, error)
	ChangeMembership(ctx context.Context, tenantID, membershipID shared.ID, change IdentityMembershipChange) (IdentityMembership, error)
	CurrentEpochs(ctx context.Context, tenantID, membershipID, connectionID shared.ID, credentialDigest string) (IdentityEpochs, error)
}

// IdentityDeliveryStats summarizes one bounded delivery pass.
type IdentityDeliveryStats struct {
	Delivered int
	Failed    int
	Exhausted int
}

// IdentityDeliveryStatus is the observable delivery state of one tenant's obligations.
type IdentityDeliveryStatus struct {
	Pending       int
	Delivered     int
	Exhausted     int
	MaxAttempts   int
	OldestPending time.Time
}

// IdentityAuditDeliveryStore delivers person-global audit obligations into the tenant audit chain.
type IdentityAuditDeliveryStore interface {
	DeliverPersonAudit(ctx context.Context, tenantID shared.ID, now time.Time, limit int) (IdentityDeliveryStats, error)
	DeliveryStatus(ctx context.Context, tenantID shared.ID) (IdentityDeliveryStatus, error)
}

// IdentityLegacyLink is a preexisting approved OIDC link of a legacy user.
type IdentityLegacyLink struct {
	Issuer  string
	Subject string
	// ApprovedBy is the actor of the user.oidc_identity_linked audit record, or empty for a link
	// that predates operator-approved linking.
	ApprovedBy string
}

// IdentityBootstrapUserID is the bootstrap operator's legacy user ID. It is never projected.
const IdentityBootstrapUserID shared.ID = "operator"

// IdentityKeyEvidence is the durable evidence that a legacy api_key_hash is an issued bearer key.
type IdentityKeyEvidence string

const (
	// IdentityKeyIssued: the latest user.created or user.api_key_rotated audit record is newer than
	// any user.disabled record, so the stored hash is the digest of an issued key.
	IdentityKeyIssued IdentityKeyEvidence = "issued"
	// IdentityKeyRevokedByDisable: a later user.disabled replaced the issued hash with an unusable one.
	IdentityKeyRevokedByDisable IdentityKeyEvidence = "revoked_by_disable"
	// IdentityKeyNoEvidence: no tenant audit record proves issuance.
	IdentityKeyNoEvidence IdentityKeyEvidence = "none"
)

// IdentityLegacyUser is the locked legacy source row the backfill classifies.
type IdentityLegacyUser struct {
	ID          shared.ID
	TenantID    shared.ID
	Name        string
	Role        user.Role
	Disabled    bool
	APIKeyHash  string
	KeyEvidence IdentityKeyEvidence
	// DuplicateHash is true when another users row, or another credential, carries the same digest.
	DuplicateHash bool
	Links         []IdentityLegacyLink
}

// IdentityBackfillClass is the per-user backfill outcome.
type IdentityBackfillClass string

const (
	IdentityBackfillMigrated             IdentityBackfillClass = "migrated"
	IdentityBackfillSuspended            IdentityBackfillClass = "suspended"
	IdentityBackfillBootstrapSkipped     IdentityBackfillClass = "bootstrap_skipped"
	IdentityBackfillAmbiguousDuplicate   IdentityBackfillClass = "ambiguous_duplicate"
	IdentityBackfillAmbiguousCorrupt     IdentityBackfillClass = "ambiguous_corrupt"
	IdentityBackfillAmbiguousForeignLink IdentityBackfillClass = "ambiguous_foreign_link"
	// IdentityBackfillAmbiguousUnprovenKey carries the membership but no credential: the hash has
	// no issuance evidence and no OIDC link, so it is neither provably real nor a placeholder.
	IdentityBackfillAmbiguousUnprovenKey IdentityBackfillClass = "ambiguous_unproven_key"
)

// Ambiguous reports whether the class blocks cutover.
func (c IdentityBackfillClass) Ambiguous() bool {
	switch c {
	case IdentityBackfillAmbiguousDuplicate, IdentityBackfillAmbiguousCorrupt, IdentityBackfillAmbiguousForeignLink, IdentityBackfillAmbiguousUnprovenKey:
		return true
	}
	return false
}

// IdentityCredentialClass records how the legacy bearer hash was classified.
type IdentityCredentialClass string

const (
	IdentityCredentialReal        IdentityCredentialClass = "real"
	IdentityCredentialPlaceholder IdentityCredentialClass = "placeholder"
	IdentityCredentialDisabled    IdentityCredentialClass = "disabled"
	IdentityCredentialAmbiguous   IdentityCredentialClass = "ambiguous"
	IdentityCredentialNone        IdentityCredentialClass = "none"
)

// IdentityBackfillDecision is the classifier's verdict for one legacy user.
type IdentityBackfillDecision struct {
	Class           IdentityBackfillClass
	CredentialClass IdentityCredentialClass
	// Project creates the person and membership. False for bootstrap and most ambiguous rows.
	Project bool
	// ProjectCredential creates the derived credential mirroring users.api_key_hash.
	ProjectCredential bool
	// CredentialActive makes the derived credential routable. False keeps it revoked.
	CredentialActive bool
	// ImportLinks imports the approved OIDC links under the configured issuer's connection.
	ImportLinks bool
}

// IdentityBackfillClassifier maps a locked legacy row to its decision. It must be pure.
type IdentityBackfillClassifier func(IdentityLegacyUser) IdentityBackfillDecision

// IdentityBackfillRun is one fenced backfill run of one tenant.
type IdentityBackfillRun struct {
	TenantID         shared.ID
	ID               shared.ID
	FenceToken       int64
	CheckpointUserID shared.ID
	Processed        int
	Batches          int
}

// IdentityBackfillBatch reports one committed batch.
type IdentityBackfillBatch struct {
	Processed        int
	CheckpointUserID shared.ID
	Done             bool
}

// IdentityShadowThresholds bound acceptable drift before a report aborts.
type IdentityShadowThresholds struct {
	MaxDrift int
}

// IdentityShadowReport is the recorded shadow parity evidence of one tenant.
type IdentityShadowReport struct {
	ID                      shared.ID
	TenantID                shared.ID
	LegacyUsers             int
	BootstrapSkipped        int
	Memberships             int
	MissingMemberships      int
	CredentialsExpected     int
	CredentialsMatched      int
	AuthenticatorsExpected  int
	AuthenticatorsMatched   int
	AuthenticatorMismatches int
	DigestMismatches        int
	RoutingMismatches       int
	RoleDrift               int
	StateDrift              int
	Placeholders            int
	Ambiguous               int
	DriftTotal              int
	Aborted                 bool
	Ready                   bool
	RollbackPrepared        bool
	DriftedUserIDs          []shared.ID
}

// IdentityBackfillStore is the fenced, resumable, idempotent backfill and shadow store. It never
// writes the legacy users source and never rewrites actor strings or audit hashes.
type IdentityBackfillStore interface {
	// StartRun takes the tenant fence with a new token and resumes from the fence checkpoint. A live
	// run updated within lease refuses a new one with ErrIdentityFenceLost.
	StartRun(ctx context.Context, tenantID, runID shared.ID, actor string, batchSize int, lease time.Duration, now time.Time) (IdentityBackfillRun, error)
	// ApplyBatch locks and classifies the next batch after the checkpoint in one tenant transaction
	// under the tenant advisory lock, then advances the checkpoint. A superseded fence returns
	// ErrIdentityFenceLost and writes nothing. Links are imported under the connection pinned to
	// issuer, the configured fixed OIDC issuer.
	ApplyBatch(ctx context.Context, run *IdentityBackfillRun, issuer string, classify IdentityBackfillClassifier, now time.Time) (IdentityBackfillBatch, error)
	FinishRun(ctx context.Context, run IdentityBackfillRun, failure error, now time.Time) error
	RecordShadowReport(ctx context.Context, tenantID, reportID, runID shared.ID, thresholds IdentityShadowThresholds, now time.Time) (IdentityShadowReport, error)
	// Rollback removes the tenant's derived identity rows and disables projection while users stays
	// authoritative. It refuses a tenant that has declared cutover.
	Rollback(ctx context.Context, tenantID shared.ID, actor string, now time.Time) error
}
