package authz

import (
	"testing"
	"time"
)

func TestOrganizationAuthenticationMatrix(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, requirement := range []SSORequirement{SSOOptional, SSORequired, "unknown"} {
		for _, kind := range []CredentialKind{KindBootstrap, KindAPIKey, KindBrowserSession, KindBreakGlass, "unknown"} {
			for _, active := range []bool{false, true} {
				for _, approved := range []bool{false, true} {
					for _, grace := range []bool{false, true} {
						for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Hour - time.Nanosecond, time.Hour, time.Hour + time.Nanosecond} {
							p := OrganizationPolicy{Requirement: requirement, ActivatedAt: at, LegacyBearerGraceEnabled: grace, DeploymentGraceDuration: time.Hour}
							proof := DestinationAuthentication{ActiveMembership: active, ApprovedDestinationSSO: approved}
							want := kind.Valid() && (requirement == SSOOptional || requirement == SSORequired) && (kind == KindBootstrap || active && (kind == KindBreakGlass || requirement == SSOOptional || kind == KindBrowserSession && approved || kind == KindAPIKey && grace && offset >= 0 && offset < time.Hour))
							if got := p.EvaluateAuthentication(kind, proof, at.Add(offset)); got.Allowed != want {
								t.Fatalf("requirement=%s kind=%s member=%v approved=%v grace=%v offset=%v: %+v want=%v", requirement, kind, active, approved, grace, offset, got, want)
							}
						}
					}
				}
			}
		}
	}
}

func TestRequiredPolicyFailsClosedWithoutActivation(t *testing.T) {
	p := OrganizationPolicy{Requirement: SSORequired, LegacyBearerGraceEnabled: true, DeploymentGraceDuration: time.Hour}
	if p.EvaluateAuthentication(KindAPIKey, DestinationAuthentication{ActiveMembership: true}, time.Now()).Allowed {
		t.Fatal("missing activation admitted bearer")
	}
}

func TestBootstrapEligibilityRequiresExplicitBoundedProof(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := BootstrapEligibility{Principal: Principal{ActorID: BootstrapActorID, Credential: Credential{Kind: KindBootstrap}}, VerifiedAt: at, ExpiresAt: at.Add(15 * time.Minute)}
	if !e.Active(at) || e.Active(at.Add(15*time.Minute)) || e.Active(at.Add(-time.Nanosecond)) {
		t.Fatal("eligibility time boundary incorrect")
	}
	e.Principal.Credential.Kind = KindAPIKey
	if e.Active(at) {
		t.Fatal("ordinary principal gained bootstrap eligibility")
	}
}
