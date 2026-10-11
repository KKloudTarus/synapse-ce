// Package users manages operator identities + API keys. It
// issues a per-user bearer key (shown once), authenticates a presented token by its
// hash, and seeds a bootstrap admin from SYNAPSE_API_TOKEN so existing deployments
// keep working and historical "operator" attribution stays valid.
package users

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// BootstrapID is the stable id of the bootstrap admin. Historical actions were
// attributed to "operator", so the bootstrap user owns that id and history stays
// coherent ("who did this?" resolves to the bootstrap admin, not a dangling string).
const BootstrapID = authz.BootstrapActorID

// maxOIDCSubjectLen bounds an operator-supplied subject. OpenID Connect caps sub at 255 ASCII
// characters.
const maxOIDCSubjectLen = 255

const apiKeyPrefix = "syn_"

// Service manages users + authentication.
type Service struct {
	repo  ports.UserRepository
	audit ports.AuditLogger
	clock ports.Clock
	ids   ports.IDGenerator
	// transactions makes the last-admin guard and its write one unit. Optional: the in-memory and
	// file stores have no transactions, and the Postgres composition roots set it.
	transactions ports.TenantTransactionRunner
	// roster serializes the guarded mutations within this process. The guard is a read-modify-write
	// over the tenant's roster, so two concurrent demotions each see the other admin still enabled,
	// both pass, and the tenant is left with nobody who can administer it. A single mutex is enough
	// because user management is a rare, human-paced operation; across replicas the row lock taken
	// by ports.UserRosterLocker inside the transaction is what serializes them.
	roster sync.Mutex
	// identities revokes a user's browser sessions on disable and stores operator-approved OIDC
	// links. Optional: without it there are no browser sessions to revoke and linking is off.
	identities ports.IdentityStore
	// oidcIssuer and oidcTenant are the fixed OIDC relying-party configuration. Linking is
	// available only when both are set.
	oidcIssuer string
	oidcTenant shared.ID
	// bootstrapDigest is the digest of SYNAPSE_API_TOKEN recorded by EnsureBootstrapAdmin. The
	// bootstrap principal is constructed only when the presented token matches it.
	bootstrapDigest string
}

// SetTransactionRunner makes every consequential mutation and its audit record one unit, and the
// last-admin guard atomic against a concurrent second mutation.
func (s *Service) SetTransactionRunner(transactions ports.TenantTransactionRunner) {
	s.transactions = transactions
}

// SetIdentityStore lets disable and re-enable revoke the user's browser sessions in the same
// transaction as the user write.
func (s *Service) SetIdentityStore(identities ports.IdentityStore) { s.identities = identities }

// SetOIDCLinking enables the operator-approved (issuer, subject) link command for the fixed OIDC
// tenant. issuer must be the exact normalized issuer the provider verifies ID tokens against.
func (s *Service) SetOIDCLinking(issuer string, tenant shared.ID) error {
	issuer = strings.TrimSpace(issuer)
	if s.identities == nil || issuer == "" || tenant.IsZero() {
		return fmt.Errorf("%w: OIDC linking requires an identity store, issuer, and tenant", shared.ErrValidation)
	}
	s.oidcIssuer, s.oidcTenant = issuer, shared.TenantOrDefault(tenant)
	return nil
}

// NewService validates dependencies and returns the users service.
func NewService(repo ports.UserRepository, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if repo == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: users service is missing a dependency", shared.ErrValidation)
	}
	return &Service{repo: repo, audit: audit, clock: clock, ids: ids}, nil
}

// HashToken returns the lowercase-hex SHA-256 of a bearer token (the only form
// stored or compared). Exported so the auth resolver and tests agree on the format.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func generateKey() (plaintext, hash string, err error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate api key: %w", err)
	}
	plaintext = apiKeyPrefix + hex.EncodeToString(b)
	return plaintext, HashToken(plaintext), nil
}

// EnsureBootstrapAdmin idempotently makes the bootstrap admin (id "operator") whose
// key is the env SYNAPSE_API_TOKEN, so the existing token keeps authenticating –
// now as a real, admin user. Safe to call on every startup.
func (s *Service) EnsureBootstrapAdmin(ctx context.Context, token string) error {
	if token == "" {
		return fmt.Errorf("%w: bootstrap token is required", shared.ErrValidation)
	}
	// Bootstrap admin lives in tenant '' – the deliberate single-tenant / default-tenant superadmin.
	u, err := user.New(BootstrapID, "", "Operator (bootstrap admin)", user.RoleAdmin, HashToken(token), s.clock.Now())
	if err != nil {
		return err
	}
	if err := s.repo.Bootstrap(ctx, u, ports.AuditEntry{
		Actor:  BootstrapID,
		Action: "user.bootstrap_admin_seeded",
		Target: BootstrapID,
		Metadata: map[string]string{
			"idempotency_key": "bootstrap-admin:" + BootstrapID,
		},
		At: s.clock.Now(),
	}); err != nil {
		return fmt.Errorf("seed bootstrap admin: %w", err)
	}
	s.bootstrapDigest = u.APIKeyHash
	return nil
}

// Actor is the authenticated caller of a user-management action. It carries the caller's own
// tenant, which is the tenant every action is confined to.
type Actor struct {
	ID       string
	TenantID string
}

// tenant returns the actor's normalized tenant (” and "default" name the same tenant).
func (a Actor) tenant() shared.ID { return shared.TenantOrDefault(shared.ID(a.TenantID)) }

// platformAdmin reports whether the actor may act outside its own tenant.
//
// There is deliberately no platform-admin ROLE: a role would be assignable by any tenant admin
// through the same user-management API this guards, which is the escalation being closed. The one
// cross-tenant identity is the bootstrap principal seeded from SYNAPSE_API_TOKEN (id "operator"),
// which only somebody with the deployment's environment can present, and which already owns the
// default-tenant superadmin position. Its single cross-tenant power is provisioning a user in
// another tenant, so a new tenant can be given its first admin; reads and every other mutation stay
// confined to the actor's own tenant for the bootstrap principal too.
func (a Actor) platformAdmin() bool { return a.ID == BootstrapID }

// mayMutate refuses every user-management mutation aimed at the bootstrap principal, including one
// the bootstrap principal makes on itself.
//
// The bootstrap admin is stored with an empty tenant_id, which normalizes to the default tenant, so
// it is a member of that tenant's roster and reachable by its admins through the ordinary
// tenant-scoped lookup. Without this guard a default-tenant admin could rotate the bootstrap key,
// read the new plaintext from the response, and present it to become the platform principal that
// every global-resource guard in the product tests for. Disabling or demoting it would equally lock
// the deployment operator out of its own deployment.
//
// Self-mutation is refused for a different reason. EnsureBootstrapAdmin refreshes this row from
// SYNAPSE_API_TOKEN on every startup, overwriting the key hash, the role and the disabled flag. A
// key rotated through this API therefore authenticates only until the next restart, while the
// environment token stops working in the meantime: two credentials, each valid at a different time,
// and no way to tell which from the outside. The credential is owned by SYNAPSE_API_TOKEN, and
// changing that variable and restarting is the one path that actually moves it.
func (a Actor) mayMutate(id shared.ID) error {
	if id.String() == BootstrapID {
		return fmt.Errorf("%w: the bootstrap operator is managed through SYNAPSE_API_TOKEN, not through user management", shared.ErrForbidden)
	}
	return nil
}

// targetTenant resolves the tenant an action applies to. An empty request means "my own tenant".
// A different tenant is refused unless the actor is the platform admin, so a tenant-A admin can
// neither provision into tenant B nor receive that user's API key.
func (a Actor) targetTenant(requested string) (shared.ID, error) {
	if strings.TrimSpace(requested) == "" {
		return a.tenant(), nil
	}
	target := shared.TenantOrDefault(shared.ID(strings.TrimSpace(requested)))
	if target != a.tenant() && !a.platformAdmin() {
		return "", fmt.Errorf("%w: user management is confined to the caller's own tenant", shared.ErrForbidden)
	}
	return target, nil
}

// CreateUser provisions a new operator and returns the raw API key ONCE (it is never recoverable
// afterwards). tenantID is assigned server-side by the admin provisioning the user (never from the
// new user's own token) and must be the actor's own tenant unless the actor is the platform admin;
// empty means the actor's tenant, so a single-tenant admin keeps creating users with no ceremony.
// The tenant the user lands in is what scopes every read/write they later make, so it is captured
// in the audit record. Audited.
func (s *Service) CreateUser(ctx context.Context, actor Actor, tenantID string, name string, role user.Role) (*user.User, string, error) {
	target, err := actor.targetTenant(tenantID)
	if err != nil {
		return nil, "", err
	}
	plaintext, hash, err := generateKey()
	if err != nil {
		return nil, "", err
	}
	// The provisioning admin assigns the tenant – the aggregate owns it from birth.
	u, err := user.New(s.ids.NewID(), target.String(), name, role, hash, s.clock.Now())
	if err != nil {
		return nil, "", err
	}
	created, err := guarded(ctx, s, actor, func(txCtx context.Context) (*user.User, error) {
		if err := s.repo.Create(txCtx, u); err != nil {
			return nil, fmt.Errorf("create user: %w", err)
		}
		if err := s.record(txCtx, ports.AuditEntry{
			Actor: actor.ID, Action: "user.created", Target: u.ID.String(),
			Metadata: map[string]string{"name": u.Name, "role": string(u.Role), "tenant": target.String()},
			At:       s.clock.Now(),
		}); err != nil {
			return nil, err
		}
		return u, nil
	})
	if err != nil {
		return nil, "", err
	}
	return created, plaintext, nil
}

// record appends the audit record of a consequential mutation. It runs inside the mutation's
// tenant transaction when one exists, so an audit failure rolls the mutation back; either way the
// failure is returned rather than dropped.
func (s *Service) record(ctx context.Context, entry ports.AuditEntry) error {
	if err := s.audit.Record(ctx, entry); err != nil {
		return fmt.Errorf("record %s audit: %w", entry.Action, err)
	}
	return nil
}

// List returns the users of the actor's own tenant (the hash is on the struct; the adapter must not
// serialize it). No caller, the platform admin included, lists another tenant's roster.
func (s *Service) List(ctx context.Context, actor Actor) ([]*user.User, error) {
	return s.repo.List(ctx, actor.tenant())
}

// Update changes a user's display name and role inside the actor's tenant. An empty name or role
// leaves that field unchanged, so a caller can rename without knowing the current role. Demoting
// the tenant's last enabled admin is refused, else the tenant would be left unmanageable. Audited.
func (s *Service) Update(ctx context.Context, actor Actor, id shared.ID, name string, role user.Role) (*user.User, error) {
	if err := actor.mayMutate(id); err != nil {
		return nil, err
	}
	return guarded(ctx, s, actor, func(txCtx context.Context) (*user.User, error) {
		return s.update(txCtx, actor, id, name, role)
	})
}

func (s *Service) update(ctx context.Context, actor Actor, id shared.ID, name string, role user.Role) (*user.User, error) {
	u, roster, err := s.lockedTarget(ctx, actor.tenant(), id)
	if err != nil {
		return nil, err
	}
	before := *u
	now := s.clock.Now()
	if strings.TrimSpace(name) != "" {
		if err := u.Rename(name, now); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(string(role)) != "" {
		if err := u.SetRole(role, now); err != nil {
			return nil, err
		}
		if before.Role.Can(user.PermAdminister) && !u.Role.Can(user.PermAdminister) {
			if err := assertNotLastEnabledAdmin(roster, actor, u.ID, "demote"); err != nil {
				return nil, err
			}
		}
	}
	if err := s.repo.Update(ctx, actor.tenant(), u); err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}
	if err := s.record(ctx, ports.AuditEntry{
		Actor: actor.ID, Action: "user.updated", Target: u.ID.String(),
		Metadata: map[string]string{
			"name": u.Name, "role": string(u.Role), "tenant": actor.tenant().String(),
			"previous_name": before.Name, "previous_role": string(before.Role),
		},
		At: now,
	}); err != nil {
		return nil, err
	}
	return u, nil
}

// SetDisabled turns a user's credentials off or back on inside the actor's tenant. Disabling is the
// revocation the product offers instead of deletion: the identity, and therefore every past
// attribution, is preserved while authentication stops. Disabling the tenant's last enabled admin
// is refused, else nobody could administer the tenant afterwards. Audited.
func (s *Service) SetDisabled(ctx context.Context, actor Actor, id shared.ID, disabled bool) (*user.User, error) {
	if err := actor.mayMutate(id); err != nil {
		return nil, err
	}
	return guarded(ctx, s, actor, func(txCtx context.Context) (*user.User, error) {
		return s.setDisabled(txCtx, actor, id, disabled)
	})
}

func (s *Service) setDisabled(ctx context.Context, actor Actor, id shared.ID, disabled bool) (*user.User, error) {
	u, roster, err := s.lockedTarget(ctx, actor.tenant(), id)
	if err != nil {
		return nil, err
	}
	if disabled && u.Role.Can(user.PermAdminister) && !u.Disabled {
		if err := assertNotLastEnabledAdmin(roster, actor, u.ID, "disable"); err != nil {
			return nil, err
		}
	}
	if u.Disabled == disabled {
		// Nothing changes, so nothing is revoked or audited. Without this, enabling an enabled user
		// would discard a working key, and repeating a disable would record a second revocation.
		return u, nil
	}
	now := s.clock.Now()
	u.SetDisabled(disabled, now)
	metadata := map[string]string{"name": u.Name, "role": string(u.Role), "tenant": actor.tenant().String()}
	// Both transitions permanently revoke the credentials the user holds now: the key digest is
	// replaced with a fresh unusable one and every browser session is revoked. Revoking on enable as
	// well covers an account disabled before disable revoked anything, whose row still holds the old
	// digest and whose sessions were never revoked. After re-enabling, the administrator rotates to
	// issue a new key.
	unusable, err := unusableDigest()
	if err != nil {
		return nil, err
	}
	if err := u.SetAPIKeyHash(unusable, now); err != nil {
		return nil, err
	}
	if err := s.repo.Update(ctx, actor.tenant(), u); err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}
	if s.identities != nil {
		// Same transaction as the user write: a failure here rolls the change back rather than
		// leaving live browser sessions behind it.
		revoked, err := s.identities.RevokeUserSessions(ctx, actor.tenant(), u.ID, now.UTC())
		if err != nil {
			return nil, fmt.Errorf("revoke user sessions: %w", err)
		}
		metadata["sessions_revoked"] = fmt.Sprintf("%d", revoked)
	}
	metadata["api_key_revoked"] = "true"
	action := "user.enabled"
	if disabled {
		action = "user.disabled"
	}
	if err := s.record(ctx, ports.AuditEntry{
		Actor: actor.ID, Action: action, Target: u.ID.String(), Metadata: metadata, At: now,
	}); err != nil {
		return nil, err
	}
	return u, nil
}

// unusableDigest is a random 256-bit value in the digest format. No token hashes to it, so a user
// holding it has no working bearer key.
func unusableDigest() (string, error) {
	b := make([]byte, sha256.Size)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate unusable credential digest: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// RotateAPIKey issues a new API key for a user in the actor's tenant and returns it ONCE. The
// previous key stops authenticating immediately, which is how a leaked key is revoked from the
// product. Audited; the key itself never reaches the audit log. A disabled user may be rotated —
// rotation invalidates the old credential whether or not the account is currently usable.
func (s *Service) RotateAPIKey(ctx context.Context, actor Actor, id shared.ID) (*user.User, string, error) {
	if err := actor.mayMutate(id); err != nil {
		return nil, "", err
	}
	u, plaintext, err := guardedKey(ctx, s, actor, func(txCtx context.Context) (*user.User, string, error) {
		return s.rotateAPIKey(txCtx, actor, id)
	})
	if err != nil {
		return nil, "", err
	}
	return u, plaintext, nil
}

// rotateAPIKey issues the new key, reading the user from the locked roster (see lockedTarget).
func (s *Service) rotateAPIKey(ctx context.Context, actor Actor, id shared.ID) (*user.User, string, error) {
	u, _, err := s.lockedTarget(ctx, actor.tenant(), id)
	if err != nil {
		return nil, "", err
	}
	plaintext, hash, err := generateKey()
	if err != nil {
		return nil, "", err
	}
	now := s.clock.Now()
	if err := u.SetAPIKeyHash(hash, now); err != nil {
		return nil, "", err
	}
	if err := s.repo.Update(ctx, actor.tenant(), u); err != nil {
		return nil, "", fmt.Errorf("update user: %w", err)
	}
	if err := s.record(ctx, ports.AuditEntry{
		Actor: actor.ID, Action: "user.api_key_rotated", Target: u.ID.String(),
		Metadata: map[string]string{"name": u.Name, "role": string(u.Role), "tenant": actor.tenant().String()},
		At:       now,
	}); err != nil {
		return nil, "", err
	}
	return u, plaintext, nil
}

// assertNotLastEnabledAdmin refuses an action that would leave the tenant with no enabled admin.
// It counts the tenant's OTHER enabled admins, so an admin cannot lock the tenant out by disabling
// or demoting itself. roster must be the locked roster read by the same transaction.
func assertNotLastEnabledAdmin(roster []*user.User, actor Actor, id shared.ID, action string) error {
	for _, other := range roster {
		if other.ID == id || other.Disabled {
			continue
		}
		if other.Role.Can(user.PermAdminister) {
			return nil
		}
	}
	return fmt.Errorf("%w: cannot %s the last enabled admin of tenant %q", shared.ErrConflict, action, actor.tenant())
}

// guarded runs one roster mutation with the last-admin guard held: serialized in this process by
// the service mutex, and against other replicas by the row lock the guard's read takes inside the
// transaction. Both are needed, and neither alone is sufficient.
func guarded(ctx context.Context, s *Service, actor Actor, fn func(context.Context) (*user.User, error)) (*user.User, error) {
	s.roster.Lock()
	defer s.roster.Unlock()
	if s.transactions == nil {
		return fn(ctx)
	}
	var out *user.User
	if err := s.transactions.Run(ctx, actor.tenant(), func(txCtx context.Context) error {
		var mutateErr error
		out, mutateErr = fn(txCtx)
		return mutateErr
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// guardedKey is guarded for the mutation that also returns a secret. The two differ only in the
// shape of the value they carry out of the transaction.
func guardedKey(ctx context.Context, s *Service, actor Actor, fn func(context.Context) (*user.User, string, error)) (*user.User, string, error) {
	s.roster.Lock()
	defer s.roster.Unlock()
	if s.transactions == nil {
		return fn(ctx)
	}
	var (
		out       *user.User
		plaintext string
	)
	if err := s.transactions.Run(ctx, actor.tenant(), func(txCtx context.Context) error {
		var mutateErr error
		out, plaintext, mutateErr = fn(txCtx)
		return mutateErr
	}); err != nil {
		return nil, "", err
	}
	return out, plaintext, nil
}

// lockedTarget reads one user from the LOCKED roster rather than through a plain lookup, and
// returns that roster for the last-admin guard. Every mutation writes the whole aggregate, so a read
// outside the lock lets a write on one replica silently revert a disable or a demotion committed on
// another between the two statements. Reading every mutation's target under the same roster lock
// makes each read-modify-write atomic, and taking the same locks in the same order means two user
// mutations cannot deadlock against each other.
func (s *Service) lockedTarget(ctx context.Context, tenant, id shared.ID) (*user.User, []*user.User, error) {
	roster, err := s.lockedRoster(ctx, tenant)
	if err != nil {
		return nil, nil, fmt.Errorf("load user: %w", err)
	}
	for _, candidate := range roster {
		if candidate.ID == id {
			return candidate, roster, nil
		}
	}
	return nil, nil, fmt.Errorf("load user: %w", shared.ErrNotFound)
}

// lockedRoster reads the tenant's roster, locking the rows for the rest of the caller's transaction
// where the repository supports it. A repository that cannot lock falls back to a plain read, which
// leaves the in-process mutex as the only serialization.
func (s *Service) lockedRoster(ctx context.Context, tenant shared.ID) ([]*user.User, error) {
	if locker, ok := s.repo.(ports.UserRosterLocker); ok {
		return locker.ListForUpdate(ctx, tenant)
	}
	return s.repo.List(ctx, tenant)
}

// Authenticate resolves a presented bearer token to its (enabled) user. The error wraps
// authz.ErrCredentialInvalid for an unknown token or a disabled user, and
// authz.ErrAuthenticationUnavailable when the repository failed, so a storage outage is never
// reported as a bad credential.
func (s *Service) Authenticate(ctx context.Context, token string) (*user.User, error) {
	if token == "" {
		return nil, fmt.Errorf("empty token: %w: %w", authz.ErrCredentialInvalid, shared.ErrForbidden)
	}
	u, err := s.repo.GetByAPIKeyHash(ctx, HashToken(token))
	if errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("unknown bearer token: %w: %w", authz.ErrCredentialInvalid, shared.ErrForbidden)
	}
	if err != nil {
		return nil, fmt.Errorf("resolve bearer token: %w: %w", authz.ErrAuthenticationUnavailable, err)
	}
	if u.Disabled {
		return nil, fmt.Errorf("user disabled: %w: %w", authz.ErrCredentialInvalid, shared.ErrForbidden)
	}
	return u, nil
}

// AuthenticatePrincipal resolves a bearer token to a typed principal. The bootstrap principal is
// constructed explicitly: only the user seeded from SYNAPSE_API_TOKEN, presenting exactly that
// token, gets credential kind bootstrap. Every other user gets api_key. A row carrying the
// bootstrap id whose digest is not the configured token's is refused rather than trusted.
func (s *Service) AuthenticatePrincipal(ctx context.Context, token string) (authz.Principal, *user.User, error) {
	u, err := s.Authenticate(ctx, token)
	if err != nil {
		return authz.Principal{}, nil, err
	}
	p := authz.Principal{
		ActorID:    u.ID.String(),
		TenantID:   shared.TenantOrDefault(shared.ID(u.TenantID)).String(),
		Role:       u.Role,
		Credential: authz.Credential{Kind: authz.KindAPIKey},
		Provenance: "bearer",
	}
	if u.ID.String() == BootstrapID {
		digest := HashToken(token)
		if s.bootstrapDigest == "" || subtle.ConstantTimeCompare([]byte(digest), []byte(s.bootstrapDigest)) != 1 {
			return authz.Principal{}, nil, fmt.Errorf("bootstrap credential does not match SYNAPSE_API_TOKEN: %w: %w", authz.ErrCredentialInvalid, shared.ErrForbidden)
		}
		p.Credential.Kind = authz.KindBootstrap
	}
	return p, u, nil
}

// OIDCLink is the non-secret view of an approved (issuer, subject) link.
type OIDCLink = identity.ExternalIdentity

// LinkOIDCIdentity approves one exact (issuer, subject) for an existing user of the fixed OIDC
// tenant, so that subject's next successful callback signs in as that user. It is the only way a
// new subject gains access: there is no provisioning, email lookup, or group lookup.
//
// The command is confined to the configured OIDC tenant and the configured issuer (exact match),
// refuses the bootstrap operator and disabled users, and writes the link and its audit record in
// one tenant transaction, so an audit failure leaves no link behind.
func (s *Service) LinkOIDCIdentity(ctx context.Context, actor Actor, id shared.ID, issuer, subject string) (OIDCLink, error) {
	if s.identities == nil || s.oidcIssuer == "" || s.oidcTenant.IsZero() {
		return OIDCLink{}, fmt.Errorf("%w: OIDC identity linking is not enabled", shared.ErrNotFound)
	}
	if err := actor.mayMutate(id); err != nil {
		return OIDCLink{}, err
	}
	if actor.tenant() != s.oidcTenant {
		return OIDCLink{}, fmt.Errorf("%w: OIDC identity links are confined to the configured OIDC tenant", shared.ErrForbidden)
	}
	if issuer != s.oidcIssuer {
		return OIDCLink{}, fmt.Errorf("%w: issuer must exactly match the configured OIDC issuer", shared.ErrValidation)
	}
	if err := validSubject(subject); err != nil {
		return OIDCLink{}, err
	}
	var link OIDCLink
	_, err := guarded(ctx, s, actor, func(txCtx context.Context) (*user.User, error) {
		target, _, err := s.lockedTarget(txCtx, actor.tenant(), id)
		if err != nil {
			return nil, err
		}
		if target.Disabled {
			return nil, fmt.Errorf("%w: a disabled user cannot be linked to an external identity", shared.ErrConflict)
		}
		now := s.clock.Now().UTC()
		link, err = identity.NewExternalIdentity(s.ids.NewID(), actor.tenant(), target.ID, issuer, subject, now)
		if err != nil {
			return nil, err
		}
		if err := s.identities.CreateExternalIdentity(txCtx, link); err != nil {
			return nil, fmt.Errorf("link OIDC identity: %w", err)
		}
		if err := s.record(txCtx, ports.AuditEntry{
			Actor: actor.ID, Action: "user.oidc_identity_linked", Target: target.ID.String(),
			Metadata: map[string]string{"tenant": actor.tenant().String(), "issuer": issuer, "subject": subject, "link_id": link.ID.String()},
			At:       now,
		}); err != nil {
			return nil, err
		}
		return target, nil
	})
	if err != nil {
		return OIDCLink{}, err
	}
	return link, nil
}

// UnlinkOIDCIdentity removes one approved (issuer, subject) link of a user of the fixed OIDC tenant,
// so that subject's next callback is refused, and revokes every browser session of the user, since
// a session minted through the removed link would otherwise outlive it. It is confined like
// LinkOIDCIdentity: the configured OIDC tenant only, never the bootstrap operator. The removal, the
// session revocation and the audit record are one tenant transaction, so an audit failure leaves
// the link and the sessions in place. A link that does not belong to this user is not found.
func (s *Service) UnlinkOIDCIdentity(ctx context.Context, actor Actor, id, linkID shared.ID) (OIDCLink, error) {
	if s.identities == nil || s.oidcIssuer == "" || s.oidcTenant.IsZero() {
		return OIDCLink{}, fmt.Errorf("%w: OIDC identity linking is not enabled", shared.ErrNotFound)
	}
	if err := actor.mayMutate(id); err != nil {
		return OIDCLink{}, err
	}
	if actor.tenant() != s.oidcTenant {
		return OIDCLink{}, fmt.Errorf("%w: OIDC identity links are confined to the configured OIDC tenant", shared.ErrForbidden)
	}
	if linkID.IsZero() {
		return OIDCLink{}, fmt.Errorf("OIDC identity link: %w", shared.ErrNotFound)
	}
	var link OIDCLink
	_, err := guarded(ctx, s, actor, func(txCtx context.Context) (*user.User, error) {
		// The same roster lock every user mutation takes first, so unlinking orders its locks like
		// a concurrent disable or link and cannot deadlock against one.
		target, _, err := s.lockedTarget(txCtx, actor.tenant(), id)
		if err != nil {
			return nil, err
		}
		link, err = s.identities.DeleteExternalIdentity(txCtx, actor.tenant(), target.ID, linkID)
		if err != nil {
			return nil, fmt.Errorf("unlink OIDC identity: %w", err)
		}
		now := s.clock.Now().UTC()
		revoked, err := s.identities.RevokeUserSessions(txCtx, actor.tenant(), target.ID, now)
		if err != nil {
			return nil, fmt.Errorf("revoke user sessions: %w", err)
		}
		if err := s.record(txCtx, ports.AuditEntry{
			Actor: actor.ID, Action: "user.oidc_identity_unlinked", Target: target.ID.String(),
			Metadata: map[string]string{
				"tenant": actor.tenant().String(), "issuer": link.Issuer, "subject": link.Subject,
				"link_id": link.ID.String(), "sessions_revoked": fmt.Sprintf("%d", revoked),
			},
			At: now,
		}); err != nil {
			return nil, err
		}
		return target, nil
	})
	if err != nil {
		return OIDCLink{}, err
	}
	return link, nil
}

// ListOIDCLinks returns the approved links of one user in the actor's tenant.
func (s *Service) ListOIDCLinks(ctx context.Context, actor Actor, id shared.ID) ([]OIDCLink, error) {
	if s.identities == nil {
		return nil, fmt.Errorf("%w: OIDC identity linking is not enabled", shared.ErrNotFound)
	}
	if _, err := s.repo.GetByID(ctx, actor.tenant(), id); err != nil {
		return nil, fmt.Errorf("load user: %w", err)
	}
	links, err := s.identities.ListExternalIdentities(ctx, actor.tenant(), id)
	if err != nil {
		return nil, fmt.Errorf("list OIDC identity links: %w", err)
	}
	return links, nil
}

// validSubject accepts an OpenID Connect subject: 1 to 255 printable characters, compared
// exactly, never trimmed or case-folded.
func validSubject(subject string) error {
	if subject == "" || len(subject) > maxOIDCSubjectLen || strings.TrimSpace(subject) != subject {
		return fmt.Errorf("%w: subject must be 1 to %d characters without surrounding whitespace", shared.ErrValidation, maxOIDCSubjectLen)
	}
	for _, r := range subject {
		if !unicode.IsPrint(r) {
			return fmt.Errorf("%w: subject contains a non-printable character", shared.ErrValidation)
		}
	}
	return nil
}
