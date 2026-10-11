package authz

import "time"

// OrganizationPolicy is the current organization's authentication requirement. Grace is a
// deployment duration measured from activation, never a client-selected deadline.
type OrganizationPolicy struct {
	Requirement              SSORequirement
	ActivatedAt              time.Time
	LegacyBearerGraceEnabled bool
	DeploymentGraceDuration  time.Duration
}

// DestinationAuthentication contains facts verified against the destination organization.
// A browser credential from another organization's provider cannot supply its SSO proof.
type DestinationAuthentication struct {
	ActiveMembership       bool
	ApprovedDestinationSSO bool
}

// EvaluateAuthentication is shared by request authentication, callback admission and switching.
// It only subtracts authority; Decide still applies the role and recovery action restrictions.
func (p OrganizationPolicy) EvaluateAuthentication(kind CredentialKind, proof DestinationAuthentication, now time.Time) Decision {
	if !kind.Valid() {
		return deny(ReasonInvalidCredential)
	}
	if p.Requirement != SSOOptional && p.Requirement != SSORequired {
		return deny(ReasonSSORequired)
	}
	if kind == KindBootstrap {
		return Decision{Allowed: true, Reason: ReasonAllowed}
	}
	if !proof.ActiveMembership {
		return deny(ReasonNoMembership)
	}
	if kind == KindBreakGlass || p.Requirement == SSOOptional {
		return Decision{Allowed: true, Reason: ReasonAllowed}
	}
	switch kind {
	case KindBrowserSession:
		if proof.ApprovedDestinationSSO {
			return Decision{Allowed: true, Reason: ReasonAllowed}
		}
	case KindAPIKey:
		if p.LegacyBearerGraceEnabled && !p.ActivatedAt.IsZero() && !now.Before(p.ActivatedAt) && p.DeploymentGraceDuration > 0 && now.Before(p.ActivatedAt.Add(p.DeploymentGraceDuration)) {
			return Decision{Allowed: true, Reason: ReasonAllowed}
		}
	}
	return deny(ReasonSSORequired)
}

// BootstrapEligibility is an explicit server-owned authentication proof for initial identity
// provisioning. It never converts the deployment operator into an organization member.
type BootstrapEligibility struct {
	Principal  Principal
	VerifiedAt time.Time
	ExpiresAt  time.Time
}

func (e BootstrapEligibility) Active(now time.Time) bool {
	return e.Principal.IsBootstrap() && !e.VerifiedAt.IsZero() && !e.VerifiedAt.After(now) && e.ExpiresAt.After(now) && !e.ExpiresAt.After(e.VerifiedAt.Add(15*time.Minute))
}
