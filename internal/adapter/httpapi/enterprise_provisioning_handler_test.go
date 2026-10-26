package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestInitialProvisioningRefusesTenantAdministratorsBeforeDependencies(t *testing.T) {
	rt := &Router{log: discardLog()}
	for _, credential := range []authz.CredentialKind{authz.KindBrowserSession, authz.KindBreakGlass, authz.KindAPIKey} {
		for _, action := range []string{"begin", "status", "draft", "test", "activate", "invitation"} {
			r := enterpriseSecurityRequest(http.MethodPost, "/api/v1/identity/provisioning/"+action, `{}`, Principal{ID: "admin", Role: string(user.RoleAdmin), TenantID: "source", Credential: credential})
			rec := httptest.NewRecorder()
			rt.enterpriseProvisioning(rec, r, action)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s/%s status=%d", credential, action, rec.Code)
			}
		}
	}
}

func TestInitialProvisioningStatusDoesNotExposeAuthorityOrInvitationSecret(t *testing.T) {
	raw, err := json.Marshal(initialProvisioningView(ports.IdentityInitialProvisioning{
		ID: "operation", TenantID: "destination", Recipient: "admin@example.com", State: "open",
		ActorID: "operator-binding", SourceTenantID: "source-binding", CredentialID: "credential-binding",
		InvitationCodeSealed: "sealed-invitation-code",
		Connection:           &ports.IdentityConnection{ID: "connection", Settings: ports.IdentityOIDCSettings{ClientID: "public-client", SealedClientSecret: "sealed-client-secret"}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	var view map[string]any
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	connection, ok := view["connection"].(map[string]any)
	if !ok || connection["client_id"] != "public-client" {
		t.Fatal("safe provisioning view omits the public client ID needed to resume credential correction")
	}
	for _, secret := range []string{"operator-binding", "source-binding", "credential-binding", "sealed-invitation-code", "sealed-client-secret"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("status leaked protected binding %q", secret)
		}
	}
}

func TestProvisioningCallbackReturnIsFixedLocalPathWithOnlyPublicContext(t *testing.T) {
	rt := &Router{enterprise: &enterpriseDeps{frontend: "https://127.0.0.1:8446/original?capability=secret#fragment"}}
	u, err := url.Parse(rt.provisioningReturnURL("sandbox-secondary", "access_denied"))
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "127.0.0.1:8446" || u.Path != "/settings/authentication" || u.Fragment != "" || len(u.Query()) != 2 || u.Query().Get("provisioning_tenant") != "sandbox-secondary" || u.Query().Get("auth_error") != "access_denied" {
		t.Fatalf("unexpected return URL: %s", u)
	}
}
