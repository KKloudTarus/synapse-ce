package documentproviders

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Notion is a connection, not a destination. The Notion API cannot prove either
// guarantee a governed publication needs:
//
//   - who may read a page. No endpoint returns a page's permissions, so the
//     exact reader of a published report cannot be verified before an upload.
//   - permanent removal. A page is moved to trash with in_trash, and Notion's
//     own reference states the API does not support permanently deleting pages,
//     so an unpublish could never prove the report is gone.
//
// Releasing under either gap would mean reporting a restriction Synapse did not
// check and a deletion that did not happen, so this profile advertises only a
// connection test. It proves the integration reaches exactly the configured
// container and that the container is not published to the web, which is the
// one sharing fact the API does expose.
const Notion integration.Provider = "notion"

const (
	notionAPIOrigin  = "https://api.notion.com"
	notionAPIVersion = "2022-06-28"
	notionMaxBytes   = 1 << 20
)

// notionIDPattern accepts the dashed and undashed UUID forms Notion returns.
var notionIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

var notionDescriptor = integration.ProviderDescriptor{
	Provider: Notion, Name: "Notion", Description: "Connection check only. The Notion API exposes no page permissions and cannot permanently delete a page, so governed report publication stays unavailable for this provider.",
	Capabilities: []integration.Capability{integration.CapabilityTestConnection},
	ConfigFields: []integration.FieldDescriptor{
		{Name: "space", Label: "Container page ID", Kind: integration.FieldText, Required: true},
		{Name: "read_group", Label: "Intended reader group (recorded, not verified)", Kind: integration.FieldText, Required: true},
		{Name: "data_class", Label: "Data classification (detail)", Kind: integration.FieldText, Required: true},
	},
	SecretFields: []integration.FieldDescriptor{{Name: "integration_token", Label: "Internal integration token", Kind: integration.FieldPassword, Required: true}},
}

type notionAdapter struct {
	client    *http.Client
	token     string
	container string
}

var _ integration.Adapter = (*notionAdapter)(nil)
var _ integration.ConnectionTester = (*notionAdapter)(nil)

func newNotion(item integration.Integration, c integration.CredentialBundle, _ selfhosted.Rules) (integration.Adapter, error) {
	if item.Provider != Notion || item.Endpoint != notionAPIOrigin {
		return nil, fmt.Errorf("%w: Notion requires its pinned HTTPS API origin", shared.ErrValidation)
	}
	if err := notionDescriptor.ValidateSecrets(map[string]string(c)); err != nil {
		return nil, err
	}
	if err := validateToken(c["integration_token"]); err != nil {
		return nil, err
	}
	var cfg struct {
		Space string `json:"space"`
		Group string `json:"read_group"`
		Class string `json:"data_class"`
	}
	if json.Unmarshal(item.Config, &cfg) != nil || !notionIDPattern.MatchString(cfg.Space) ||
		strings.TrimSpace(cfg.Group) == "" || len(cfg.Group) > 255 || cfg.Class != "detail" {
		return nil, shared.ErrValidation
	}
	return &notionAdapter{
		client:    safehttp.NewClient(20*time.Second, safehttp.Policy{AllowHost: func(h, p string) bool { return h == "api.notion.com" && p == "443" }}),
		token:     c["integration_token"],
		container: cfg.Space,
	}, nil
}

func (*notionAdapter) Descriptor() integration.ProviderDescriptor { return notionDescriptor }

func (a *notionAdapter) Close() {
	a.client.CloseIdleConnections()
	a.token = ""
}

func (a *notionAdapter) get(ctx context.Context, path string, out any) error {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") || strings.ContainsAny(path, "?#\\") {
		return docError(0, "invalid_request", false)
	}
	u := url.URL{Scheme: "https", Host: "api.notion.com", Path: path}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), bytes.NewReader(nil))
	if err != nil {
		return docError(0, "invalid_request", false)
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Notion-Version", notionAPIVersion)
	req.Header.Set("Accept", "application/json")
	data, _, err := readResponse(a.client, req, notionMaxBytes, http.StatusOK)
	if err != nil {
		return err
	}
	if out != nil && json.Unmarshal(data, out) != nil {
		return docError(http.StatusOK, "invalid_response", false)
	}
	return nil
}

type notionPage struct {
	Object    string          `json:"object"`
	ID        string          `json:"id"`
	InTrash   *bool           `json:"in_trash"`
	Archived  *bool           `json:"archived"`
	PublicURL json.RawMessage `json:"public_url"`
	Parent    struct {
		Type string `json:"type"`
	} `json:"parent"`
}

// TestConnection proves the integration reaches exactly the configured container
// and that the container is not published to the web. A Notion page carries
// public_url only once it is shared to the web, so a non-null value is an
// observed public exposure and refuses the connection.
func (a *notionAdapter) TestConnection(ctx context.Context) error {
	var bot struct {
		Object string `json:"object"`
		Type   string `json:"type"`
	}
	if err := a.get(ctx, "/v1/users/me", &bot); err != nil {
		return err
	}
	if bot.Object != "user" || bot.Type != "bot" {
		return docError(http.StatusOK, "invalid_identity", false)
	}
	var page notionPage
	if err := a.get(ctx, "/v1/pages/"+a.container, &page); err != nil {
		// Notion answers 404 both for a page that does not exist and for a page
		// the integration was never given access to, and the operator fixes the
		// second case in the page's own connections menu.
		var refusal *ports.DocumentProviderError
		if errors.As(err, &refusal) && refusal.Status == http.StatusNotFound {
			return docError(http.StatusNotFound, "container_not_shared", false)
		}
		return err
	}
	if page.Object != "page" || !notionSameID(page.ID, a.container) {
		return docError(http.StatusOK, "invalid_container", false)
	}
	if (page.InTrash != nil && *page.InTrash) || (page.Archived != nil && *page.Archived) {
		return docError(http.StatusOK, "container_in_trash", false)
	}
	if page.Parent.Type == "" {
		return docError(http.StatusOK, "complete_identity_unverifiable", false)
	}
	if notionPublished(page.PublicURL) {
		return restrictionLostError(http.StatusOK, "container_published_to_web")
	}
	return nil
}

// notionPublished reads public_url. Absent or JSON null means the page is not
// published; anything else is treated as published, including a value this
// client cannot parse, because an unreadable sharing state is not proof of a
// private page.
func notionPublished(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return false
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return true
	}
	return strings.TrimSpace(value) != ""
}

// notionSameID compares the dashed and undashed forms of the same identifier.
func notionSameID(a, b string) bool {
	return strings.EqualFold(strings.ReplaceAll(a, "-", ""), strings.ReplaceAll(b, "-", ""))
}
