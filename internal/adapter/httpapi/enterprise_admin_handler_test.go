package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestEnterpriseConnectionViewProjectsAdminUpdateMetadataWithoutSecret(t *testing.T) {
	view := enterpriseConnectionView(ports.IdentityConnection{
		ID:            shared.ID("connection"),
		DisplayName:   "Workforce",
		Issuer:        "https://issuer.example",
		Settings:      ports.IdentityOIDCSettings{ClientID: "client", SealedClientSecret: "sealed-secret", Auth0OrganizationID: "org_CaseSensitive"},
		DraftRevision: 2,
	})
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"auth0_organization_id":"org_CaseSensitive"`) || !strings.Contains(string(raw), `"client_id":"client"`) || strings.Contains(string(raw), "sealed-secret") || strings.Contains(string(raw), "settings") {
		t.Fatalf("unsafe connection projection: %s", raw)
	}
}

func TestEnterpriseConnectionViewProjectsPendingConfigurationClientWithoutSecret(t *testing.T) {
	view := enterpriseConnectionView(ports.IdentityConnection{
		ID: shared.ID("connection"), Settings: ports.IdentityOIDCSettings{SealedClientSecret: "sealed-secret"},
		ConfigurationPending: true, ConfigurationClientID: "configured-client",
	})
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"configuration_pending":true`) || !strings.Contains(string(raw), `"client_id":"configured-client"`) || strings.Contains(string(raw), "sealed-secret") {
		t.Fatalf("unsafe pending configuration projection: %s", raw)
	}
	view = enterpriseConnectionView(ports.IdentityConnection{ID: shared.ID("ordinary"), Settings: ports.IdentityOIDCSettings{ClientID: "ordinary-client", SealedClientSecret: "sealed-secret"}})
	raw, err = json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"client_id":"ordinary-client"`) || strings.Contains(string(raw), "configuration_pending") || strings.Contains(string(raw), "sealed-secret") {
		t.Fatalf("unsafe native connection projection: %s", raw)
	}
}

func TestEnterpriseConnectionDraftRequestAcceptsOldPayloadWithoutOrganizationRestriction(t *testing.T) {
	var request enterpriseConnectionDraftRequest
	if err := json.Unmarshal([]byte(`{"display_name":"Workforce","issuer":"https://issuer.example","client_id":"client","client_secret":"secret"}`), &request); err != nil {
		t.Fatal(err)
	}
	if request.Auth0OrganizationID != "" {
		t.Fatalf("old payload organization id = %q", request.Auth0OrganizationID)
	}
}
