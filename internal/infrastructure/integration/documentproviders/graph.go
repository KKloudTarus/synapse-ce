package documentproviders

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const SharePoint integration.Provider = "sharepoint"
const OneDrive integration.Provider = "onedrive"

func graphDescriptor(provider integration.Provider) integration.ProviderDescriptor {
	name := "SharePoint"
	if provider == OneDrive {
		name = "OneDrive"
	}
	return integration.ProviderDescriptor{Provider: provider, Name: name, Description: "Governed SharePoint or OneDrive Business publication with complete SharePoint role-assignment proof.", Capabilities: []integration.Capability{integration.CapabilityTestConnection, integration.CapabilityDocuments}, ConfigFields: []integration.FieldDescriptor{{Name: "drive_id", Label: "Drive ID", Kind: integration.FieldText, Required: true}, {Name: "space", Label: "Restricted folder item ID", Kind: integration.FieldText, Required: true}, {Name: "folder_path", Label: "Server-relative restricted folder path", Kind: integration.FieldText, Required: true}, {Name: "read_group", Label: "Exact Microsoft group principal ID", Kind: integration.FieldText, Required: true}, {Name: "custodian_principal_id", Label: "Service custodian SharePoint principal ID", Kind: integration.FieldText, Required: true}, {Name: "data_class", Label: "Data classification (detail)", Kind: integration.FieldText, Required: true}}, SecretFields: []integration.FieldDescriptor{{Name: "access_token", Label: "Scoped Microsoft Graph access token", Kind: integration.FieldPassword, Required: true}, {Name: "sharepoint_token", Label: "Scoped SharePoint REST access token", Kind: integration.FieldPassword, Required: true}}}
}

type graphAdapter struct {
	client                                                                 *http.Client
	provider                                                               integration.Provider
	token, sharePointToken, drive, container, group, folderPath, custodian string
	site                                                                   *url.URL
}

var _ ports.DocumentReleasePreflighter = (*graphAdapter)(nil)
var _ ports.DocumentProvider = (*graphAdapter)(nil)
var _ ports.DocumentRevisionWriter = (*graphAdapter)(nil)
var _ integration.ConnectionTester = (*graphAdapter)(nil)

// Microsoft Graph drive IDs commonly use the documented b! prefix. Item IDs
// remain constrained by safeID because they are persisted in RemotePage IDs.
func safeGraphDriveID(v string) bool {
	return safeID(v) || (strings.HasPrefix(v, "b!") && safeID(strings.TrimPrefix(v, "b!")))
}

func newGraph(item integration.Integration, c integration.CredentialBundle, _ selfhosted.Rules) (integration.Adapter, error) {
	if item.Provider != SharePoint && item.Provider != OneDrive {
		return nil, shared.ErrValidation
	}
	site, err := url.Parse(item.Endpoint)
	if err != nil || site.Scheme != "https" || !strings.HasSuffix(strings.ToLower(site.Hostname()), ".sharepoint.com") || site.User != nil || site.RawQuery != "" || site.Fragment != "" || (site.Path != "" && path.Clean(site.Path) != site.Path) {
		return nil, shared.ErrValidation
	}
	d := graphDescriptor(item.Provider)
	if err := d.ValidateSecrets(map[string]string(c)); err != nil {
		return nil, err
	}
	if err := validateToken(c["access_token"]); err != nil {
		return nil, err
	}
	var cfg struct {
		Drive      string `json:"drive_id"`
		Container  string `json:"space"`
		Group      string `json:"read_group"`
		Class      string `json:"data_class"`
		FolderPath string `json:"folder_path"`
		Custodian  string `json:"custodian_principal_id"`
	}
	if json.Unmarshal(item.Config, &cfg) != nil {
		return nil, shared.ErrValidation
	}
	if !safeGraphDriveID(cfg.Drive) || !safeID(cfg.Container) || !safeID(cfg.Group) || !safeID(cfg.Custodian) || !validSPPath(cfg.FolderPath) || cfg.Class != "detail" || validateToken(c["sharepoint_token"]) != nil {
		return nil, shared.ErrValidation
	}
	return &graphAdapter{client: safehttp.NewClient(20*time.Second, safehttp.Policy{AllowHost: func(h, p string) bool {
		return p == "443" && (h == "graph.microsoft.com" || strings.EqualFold(h, site.Hostname()))
	}}), provider: item.Provider, token: c["access_token"], sharePointToken: c["sharepoint_token"], drive: cfg.Drive, container: cfg.Container, group: cfg.Group, folderPath: cfg.FolderPath, custodian: cfg.Custodian, site: site}, nil
}
func (a *graphAdapter) Descriptor() integration.ProviderDescriptor {
	return graphDescriptor(a.provider)
}
func (a *graphAdapter) Close() { a.client.CloseIdleConnections(); a.token = ""; a.sharePointToken = "" }
func (a *graphAdapter) get(ctx context.Context, p string, q url.Values, out any) error {
	u := url.URL{Scheme: "https", Host: "graph.microsoft.com", Path: "/v1.0" + p, RawQuery: q.Encode()}
	req, e := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if e != nil {
		return shared.ErrValidation
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	data, _, e := readResponse(a.client, req, 4<<20, 200)
	if e != nil {
		return e
	}
	if strings.Contains(string(data), a.token) || strings.Contains(string(data), a.sharePointToken) || json.Unmarshal(data, out) != nil {
		return docError(200, "unsafe_provider_response", false)
	}
	return nil
}
func (a *graphAdapter) TestConnection(ctx context.Context) error {
	return a.CheckDocumentRelease(ctx, a.container, a.group)
}
