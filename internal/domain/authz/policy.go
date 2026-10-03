package authz

import "time"

// SSORequirement is a tenant's single sign-on requirement. While enterprise identity is disabled
// every tenant is SSOOptional.
type SSORequirement string

const (
	SSOOptional SSORequirement = "optional"
	SSORequired SSORequirement = "required"
)

// AuthenticationSource names where a credential kind is proven.
type AuthenticationSource string

const (
	SourceDeploymentToken  AuthenticationSource = "deployment_token"
	SourceBearerKey        AuthenticationSource = "bearer_key"
	SourceIdentityProvider AuthenticationSource = "identity_provider"
	SourceEmergency        AuthenticationSource = "emergency"
)

// credentialPolicy is one row of the credential policy table. Every field is read by Decide or
// RecentlyAuthenticated; the table has no general policy language.
type credentialPolicy struct {
	// Source is the authentication source that proves this kind.
	Source AuthenticationSource
	// SatisfiesSSO reports whether the credential is itself a single sign-on proof.
	SatisfiesSSO bool
	// LegacyBearerGrace keeps a non-SSO credential usable under SSORequired during the migration
	// window. It applies only to per-user API keys.
	LegacyBearerGrace bool
	// ExemptFromSSO marks the deployment operator and emergency credentials, which exist to reach
	// the deployment when the identity provider itself is the problem.
	ExemptFromSSO bool
	// RequiresMembership means the principal must carry a destination tenant.
	RequiresMembership bool
	// RecoveryOnly confines the credential to the recovery allowlist.
	RecoveryOnly bool
	// RecentAuthWindow is how long after AuthenticatedAt the credential counts as a recent
	// authentication. Zero means the credential can never prove recent authentication.
	RecentAuthWindow time.Duration
}

func (c credentialPolicy) satisfies(sso SSORequirement) bool {
	switch sso {
	case SSOOptional:
		return true
	case SSORequired:
		return c.SatisfiesSSO || c.ExemptFromSSO || c.LegacyBearerGrace
	}
	return false
}

// credentialPolicies is the credential policy table: bootstrap, legacy bearer grace,
// authentication source, destination membership, recent-auth and emergency access.
//
// INVARIANT: read-only after package initialization.
var credentialPolicies = map[CredentialKind]credentialPolicy{
	// The bootstrap token is a static environment secret with no authentication time, so it can
	// never prove recent authentication. Its authority is platform scope, not freshness.
	KindBootstrap: {Source: SourceDeploymentToken, ExemptFromSSO: true},
	KindAPIKey:    {Source: SourceBearerKey, LegacyBearerGrace: true, RequiresMembership: true},
	KindBrowserSession: {
		Source: SourceIdentityProvider, SatisfiesSSO: true, RequiresMembership: true,
		RecentAuthWindow: 15 * time.Minute,
	},
	// A fresh emergency activation is recovery-only proof for the life of its short session.
	KindBreakGlass: {
		Source: SourceEmergency, ExemptFromSSO: true, RequiresMembership: true, RecoveryOnly: true,
		RecentAuthWindow: 15 * time.Minute,
	},
}

// SourceOf returns the authentication source that proves kind, or "" for an unknown kind.
func SourceOf(kind CredentialKind) AuthenticationSource {
	return credentialPolicies[kind].Source
}

// RecentlyAuthenticated reports whether p proved its credential within the kind's recent-auth
// window at now. A zero AuthenticatedAt, a future AuthenticatedAt, or a kind without a window
// never qualifies. The window is exclusive at its end.
func RecentlyAuthenticated(p Principal, now time.Time) bool {
	policy, ok := credentialPolicies[p.Credential.Kind]
	if !ok || policy.RecentAuthWindow <= 0 || p.AuthenticatedAt.IsZero() || p.AuthenticatedAt.After(now) {
		return false
	}
	return now.Before(p.AuthenticatedAt.Add(policy.RecentAuthWindow))
}

// RecoveryAction names one action in the closed identity-recovery allowlist.
type RecoveryAction string

const (
	// RecoveryLogout ends the caller's own session.
	RecoveryLogout RecoveryAction = "logout"
	// RecoveryReadSelf reads the caller's own identity.
	RecoveryReadSelf RecoveryAction = "read_self"
	// RecoveryListUsers lists the caller's tenant roster to find the account to restore.
	RecoveryListUsers RecoveryAction = "list_users"
	// RecoveryAssignRole restores an administrator role in the caller's tenant.
	RecoveryAssignRole RecoveryAction = "assign_role"
	// RecoveryDisableUser cuts off a compromised account in the caller's tenant.
	RecoveryDisableUser RecoveryAction = "disable_user"
	// RecoveryEnableUser re-enables an account in the caller's tenant.
	RecoveryEnableUser       RecoveryAction = "enable_user"
	RecoveryReadIdentity     RecoveryAction = "read_identity_configuration"
	RecoveryRepairConnection RecoveryAction = "repair_identity_connection"
	RecoveryRelaxSSO         RecoveryAction = "relax_sso"
)

// recoveryAllowlist is closed. It deliberately omits organization switching, identity linking,
// ordinary key issuance, scans, fleet and integration management, and every data read.
var recoveryAllowlist = map[RecoveryAction]bool{
	RecoveryLogout:           true,
	RecoveryReadSelf:         true,
	RecoveryListUsers:        true,
	RecoveryAssignRole:       true,
	RecoveryDisableUser:      true,
	RecoveryEnableUser:       true,
	RecoveryReadIdentity:     true,
	RecoveryRepairConnection: true,
	RecoveryRelaxSSO:         true,
}

// Allowed reports whether r is in the recovery allowlist. The empty action is not.
func (r RecoveryAction) Allowed() bool { return recoveryAllowlist[r] }

// RecoveryActions returns the allowlist, for inventory tests.
func RecoveryActions() []RecoveryAction {
	out := make([]RecoveryAction, 0, len(recoveryAllowlist))
	for action := range recoveryAllowlist {
		out = append(out, action)
	}
	return out
}
