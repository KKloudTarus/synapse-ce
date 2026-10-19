package main

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"testing"
	"time"
)

func TestControlPlanePrincipalPreservesCanonicalReleaseAuthority(t *testing.T) {
	at := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	source := authz.Principal{ActorID: "reviewer", PersonID: "person", MembershipID: "membership", TenantID: "tenant", Role: user.RoleReviewer, Credential: authz.Credential{Kind: authz.KindAPIKey, ID: "credential"}, AuthenticatedAt: at, Provenance: "bearer"}
	result := controlPlanePrincipal(source, &user.User{Name: "Reviewer", TenantID: "stale-compatibility"})
	if result.ID != source.ActorID || result.TenantID != source.TenantID || result.PersonID != source.PersonID || result.MembershipID != source.MembershipID || result.Epochs != source.Epochs || result.CredentialID != source.Credential.ID || result.Credential != source.Credential.Kind || !result.AuthenticatedAt.Equal(at) {
		t.Fatalf("canonical authority lost: %+v", result)
	}
	legacy := controlPlanePrincipal(authz.Principal{ActorID: "legacy", TenantID: "default", Role: user.RoleReviewer}, &user.User{Name: "Legacy"})
	if legacy.PersonID != "" || legacy.MembershipID != "" {
		t.Fatal("invented canonical authority for a legacy user")
	}
}
