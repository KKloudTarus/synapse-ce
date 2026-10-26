package identityenterprise

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type draftConnections struct {
	authConnections
	draft ports.IdentityConnectionDraft
}

func TestConnectionDraftValidatesExactAuth0OrganizationID(t *testing.T) {
	valid := "org_CaseSensitive"
	for _, tc := range []struct {
		name    string
		orgID   string
		wantErr bool
	}{
		{name: "unset"},
		{name: "valid", orgID: valid},
		{name: "missing suffix", orgID: "org_", wantErr: true},
		{name: "wrong prefix", orgID: "organization_CaseSensitive", wantErr: true},
		{name: "space", orgID: "org_Case Sensitive", wantErr: true},
		{name: "control", orgID: "org_Case\nSensitive", wantErr: true},
		{name: "too long", orgID: "org_" + strings.Repeat("a", 253), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &draftConnections{}
			service, err := NewConnections(store, authProtector{}, authClock{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}, &authIDs{}, "https://synapse.example/callback")
			if err != nil {
				t.Fatal(err)
			}
			principal := authz.Principal{ActorID: authz.BootstrapActorID, TenantID: "tenant", Credential: authz.Credential{Kind: authz.KindBootstrap, ID: "deployment"}}
			proof, err := service.BeginBootstrap(t.Context(), principal)
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.SaveDraft(t.Context(), principal, proof, ConnectionDraftInput{DisplayName: "Workforce", Issuer: "https://issuer.example", ClientID: "client", ClientSecret: "secret", Auth0OrganizationID: tc.orgID})
			if (err != nil) != tc.wantErr {
				t.Fatalf("SaveDraft() error = %v, wantErr %t", err, tc.wantErr)
			}
			if tc.wantErr {
				if !errors.Is(err, shared.ErrValidation) || store.draft.ID != "" {
					t.Fatalf("invalid organization saved draft=%+v err=%v", store.draft, err)
				}
				return
			}
			if got := store.draft.Settings.Auth0OrganizationID; got != tc.orgID {
				t.Fatalf("organization id = %q, want exact %q", got, tc.orgID)
			}
		})
	}
}

func (s *draftConnections) SaveIdentityConnectionDraft(_ context.Context, draft ports.IdentityConnectionDraft, _ ports.IdentityAdminProof) (ports.IdentityConnection, error) {
	s.draft = draft
	return ports.IdentityConnection{ID: draft.ID, Issuer: draft.Issuer, Settings: draft.Settings}, nil
}

func TestConnectionDraftPreservesExactIssuer(t *testing.T) {
	for _, issuer := range []string{"https://issuer.example", "https://issuer.example/", "https://issuer.example/realm/", "https://issuer.example/realm//", "https://issuer.example/a%2Fb/"} {
		t.Run(issuer, func(t *testing.T) {
			store := &draftConnections{}
			service, err := NewConnections(store, authProtector{}, authClock{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}, &authIDs{}, "https://synapse.example/callback")
			if err != nil {
				t.Fatal(err)
			}
			principal := authz.Principal{ActorID: authz.BootstrapActorID, TenantID: "tenant", Credential: authz.Credential{Kind: authz.KindBootstrap, ID: "deployment"}}
			proof, err := service.BeginBootstrap(t.Context(), principal)
			if err != nil {
				t.Fatal(err)
			}
			saved, err := service.SaveDraft(t.Context(), principal, proof, ConnectionDraftInput{DisplayName: "Workforce", Issuer: issuer, ClientID: "client", ClientSecret: "secret"})
			if err != nil {
				t.Fatal(err)
			}
			if saved.Issuer != issuer || store.draft.Issuer != issuer {
				t.Fatalf("draft changed issuer %q to %q", issuer, saved.Issuer)
			}
		})
	}
}
