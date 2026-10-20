// Package documentproviders implements the provider boundaries for governed
// document destinations. Capability checks precede release, including neutral shells.
package documentproviders

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const Notion integration.Provider = "notion"

var notionDescriptor = integration.ProviderDescriptor{
	Provider: Notion, Name: "Notion (publication unavailable)",
	Description:  "Connection checks only. Notion's public API cannot prove the required page read ACL or permanently purge page history; governed publication is unavailable.",
	Capabilities: []integration.Capability{integration.CapabilityTestConnection},
	ConfigFields: []integration.FieldDescriptor{{Name: "space", Label: "Parent page ID", Kind: integration.FieldText, Required: true}, {Name: "read_group", Label: "Required reader group", Kind: integration.FieldText, Required: true}, {Name: "data_class", Label: "Data classification", Kind: integration.FieldText, Required: true}},
	SecretFields: []integration.FieldDescriptor{{Name: "access_token", Label: "Integration access token", Kind: integration.FieldPassword, Required: true}},
}

type notionAdapter struct {
	client *http.Client
	token  string
}

var _ integration.ConnectionTester = (*notionAdapter)(nil)
var _ ports.DocumentReleasePreflighter = (*notionAdapter)(nil)

func newNotion(item integration.Integration, credentials integration.CredentialBundle, _ selfhosted.Rules) (integration.Adapter, error) {
	if item.Provider != Notion || item.Endpoint != "https://api.notion.com" {
		return nil, fmt.Errorf("%w: Notion requires its pinned HTTPS API origin", shared.ErrValidation)
	}
	if err := notionDescriptor.ValidateSecrets(map[string]string(credentials)); err != nil {
		return nil, err
	}
	if err := validateToken(credentials["access_token"]); err != nil {
		return nil, err
	}
	return &notionAdapter{client: safehttp.NewClient(20*time.Second, safehttp.Policy{AllowHost: func(host, port string) bool { return host == "api.notion.com" && port == "443" }}), token: credentials["access_token"]}, nil
}
func (*notionAdapter) Descriptor() integration.ProviderDescriptor { return notionDescriptor }
func (a *notionAdapter) Close()                                   { a.client.CloseIdleConnections(); a.token = "" }
func (*notionAdapter) CheckDocumentRelease(context.Context, string, string) error {
	return &ports.DocumentProviderError{Code: "notion_release_contract_unavailable"}
}
func (a *notionAdapter) TestConnection(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.notion.com/v1/users/me", nil)
	if err != nil {
		return docError(0, "invalid_request", false)
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Notion-Version", "2025-09-03")
	data, _, err := readResponse(a.client, req, 1<<20, http.StatusOK)
	if err != nil {
		return err
	}
	var user struct {
		Object string `json:"object"`
		Type   string `json:"type"`
		ID     string `json:"id"`
	}
	if json.Unmarshal(data, &user) != nil || user.Object != "user" || user.Type != "bot" || !safeID(user.ID) || containsCredential(user.ID, a.token) {
		return docError(200, "invalid_identity", false)
	}
	return nil
}
