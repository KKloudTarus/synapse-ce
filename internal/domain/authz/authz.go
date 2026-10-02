// Package authz holds the one human authorization decision. A typed Principal describes who
// authenticated and with which credential; Decide combines the static role floor (user.Role.Can)
// with the credential policy tables and the platform-only restriction. Route guards and
// handler-level checks call the same Decide, so no surface reaches a different answer for the
// same principal and action.
package authz

import (
	"errors"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

// BootstrapActorID is the stable actor id of the deployment operator seeded from
// SYNAPSE_API_TOKEN. Historical records are attributed to it, so it never changes.
const BootstrapActorID = "operator"

// Authentication outcome classes. An authenticator returns an error wrapping exactly one of
// these so the transport can tell a definitively bad credential (clear it) from a dependency
// failure (keep it and retry). An error wrapping neither is treated as unavailable: it never
// grants access and never clears a credential that may still be valid.
var (
	// ErrCredentialInvalid means the presented credential is unknown, revoked, expired, over its
	// lineage cap, or belongs to a disabled or unavailable account.
	ErrCredentialInvalid = errors.New("authentication credential is invalid")
	// ErrAuthenticationUnavailable means a storage or provider dependency failed while the
	// credential was being checked. The credential may still be valid.
	ErrAuthenticationUnavailable = errors.New("authentication is temporarily unavailable")
	// ErrCSRFInvalid means a cookie session is valid but the request's CSRF proof is missing or
	// wrong. The session itself is kept.
	ErrCSRFInvalid = errors.New("CSRF token is missing or invalid")
)

// CredentialKind is the closed set of human credential kinds.
type CredentialKind string

const (
	// KindBootstrap is the deployment operator's SYNAPSE_API_TOKEN.
	KindBootstrap CredentialKind = "bootstrap"
	// KindAPIKey is a per-user bearer API key.
	KindAPIKey CredentialKind = "api_key"
	// KindBrowserSession is an opaque OIDC BFF browser session.
	KindBrowserSession CredentialKind = "browser_session"
	// KindBreakGlass is a short-lived emergency credential limited to identity recovery. No
	// route issues one yet; the policy exists so the restriction is decided before the issuer.
	KindBreakGlass CredentialKind = "break_glass"
)

// Valid reports whether k is a known credential kind.
func (k CredentialKind) Valid() bool {
	_, ok := credentialPolicies[k]
	return ok
}

// Credential identifies the credential that authenticated the request.
type Credential struct {
	Kind CredentialKind
	// ID is a stable, non-secret identifier of the credential (for example a session id). It is
	// never the credential value or its digest.
	ID string
}

// Epochs are the revocation epochs verified during authentication. Zero means the scope has no
// epoch yet (legacy identity) and is not compared.
type Epochs struct {
	Person, Membership, Connection int64
}

// Principal is the authenticated human subject of a request.
type Principal struct {
	// ActorID is the stable id recorded on every attributable action.
	ActorID string
	// PersonID and MembershipID are empty until enterprise identity is enabled.
	PersonID     string
	TenantID     string
	MembershipID string
	Role         user.Role
	Credential   Credential
	// AuthenticatedAt is when the credential lineage was first established.
	AuthenticatedAt time.Time
	// Provenance names the authentication source, for example "bearer" or "oidc:<issuer>".
	Provenance string
	Epochs     Epochs
}

// IsBootstrap reports whether p is the deployment operator authenticated with SYNAPSE_API_TOKEN.
// Both the credential kind and the actor id must agree: neither alone is platform authority.
func (p Principal) IsBootstrap() bool {
	return p.Credential.Kind == KindBootstrap && p.ActorID == BootstrapActorID
}

// Action is one thing a principal asks to do.
type Action struct {
	// Permission is the role floor. Empty means any authenticated principal (no role needed).
	Permission user.Permission
	// PlatformOnly restricts the action to the bootstrap principal.
	PlatformOnly bool
	// Recovery names the identity-recovery action this is, if any. Only actions in the recovery
	// allowlist are available to a recovery-only credential.
	Recovery RecoveryAction
}

// Decision is the outcome of Decide. Reason is a stable machine-readable token for logs and
// tests, never shown as authority to a client.
type Decision struct {
	Allowed bool
	Reason  string
}

// Decision reasons.
const (
	ReasonAllowed              = "allowed"
	ReasonUnauthenticated      = "unauthenticated"
	ReasonInvalidCredential    = "invalid_credential" //nolint:gosec // G101 false positive: a decision reason code, not credential material.
	ReasonSSORequired          = "sso_required"
	ReasonNoMembership         = "no_membership"
	ReasonRecoveryOnly         = "recovery_only"
	ReasonPlatformOnly         = "platform_only"
	ReasonPermissionNotGranted = "permission_not_granted"
)

// Decide is the single human authorization decision under the default (optional) SSO
// requirement, which is the only requirement while enterprise identity is disabled.
func Decide(p Principal, a Action) Decision {
	return DecideUnder(SSOOptional, p, a)
}

// DecideUnder evaluates p against a under an explicit SSO requirement. The order is fixed: a
// principal must be authenticated with a known credential, the credential must satisfy the SSO
// requirement and the destination membership rule, a recovery-only credential may reach only the
// recovery allowlist, platform-only actions need the bootstrap principal, and finally the role
// must hold the permission. Every step can only subtract access granted by the role floor.
func DecideUnder(sso SSORequirement, p Principal, a Action) Decision {
	if p.ActorID == "" {
		return deny(ReasonUnauthenticated)
	}
	policy, ok := credentialPolicies[p.Credential.Kind]
	if !ok {
		return deny(ReasonInvalidCredential)
	}
	// A bootstrap credential is meaningful only for the bootstrap actor, and the bootstrap actor
	// only ever authenticates with it.
	if (p.Credential.Kind == KindBootstrap) != (p.ActorID == BootstrapActorID) {
		return deny(ReasonInvalidCredential)
	}
	if !policy.satisfies(sso) {
		return deny(ReasonSSORequired)
	}
	if policy.RequiresMembership && p.TenantID == "" {
		return deny(ReasonNoMembership)
	}
	if policy.RecoveryOnly {
		if !a.Recovery.Allowed() || a.PlatformOnly {
			return deny(ReasonRecoveryOnly)
		}
	}
	if a.PlatformOnly && !p.IsBootstrap() {
		return deny(ReasonPlatformOnly)
	}
	if a.Permission != "" && !p.Role.Can(a.Permission) {
		return deny(ReasonPermissionNotGranted)
	}
	return Decision{Allowed: true, Reason: ReasonAllowed}
}

func deny(reason string) Decision { return Decision{Allowed: false, Reason: reason} }
