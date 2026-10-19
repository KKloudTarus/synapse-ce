package main

import (
	"github.com/KKloudTarus/synapse-ce/internal/adapter/httpapi"
	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

// controlPlanePrincipal preserves the canonical membership lineage that a
// durable human-approved release must revalidate at worker execution.
func controlPlanePrincipal(p authz.Principal, u *user.User) httpapi.Principal {
	return httpapi.Principal{ID: p.ActorID, Name: u.Name, Role: string(p.Role), TenantID: p.TenantID, PersonID: p.PersonID, MembershipID: p.MembershipID, Epochs: p.Epochs, Credential: p.Credential.Kind, CredentialID: p.Credential.ID, AuthenticatedAt: p.AuthenticatedAt, Provenance: p.Provenance}
}
