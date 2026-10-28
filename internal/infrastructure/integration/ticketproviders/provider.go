// Package ticketproviders implements the non-Jira ticket destinations.  It keeps
// provider wire formats at the egress boundary; the ticket workflow retains the
// intent, lease, audit and recovery policy.
package ticketproviders

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scmconnector"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/integration/selfhostedhttp"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/messageformat"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	GitHubProvider     integration.Provider = "github-issues"
	GitLabProvider     integration.Provider = "gitlab-issues"
	AzureProvider      integration.Provider = "azure-boards"
	ServiceNowProvider integration.Provider = "servicenow"
	LinearProvider     integration.Provider = "linear"
	maxPayload                              = 64 << 10
	maxResponse                             = 4 << 20
	maxPages                                = 20
)

var markerRE = regexp.MustCompile(`^synapse-intent-[a-z0-9][a-z0-9-]{0,127}$`)
var repoRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
var projectPathRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}(?:/[A-Za-z0-9_.-]{1,100})+$`)
var ordinaryPathPartRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
var azureProjectPartRE = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,99}$`)

type gitLabSearchIssue struct {
	IID          int      `json:"iid"`
	WebURL       string   `json:"web_url"`
	Confidential bool     `json:"confidential"`
	Labels       []string `json:"labels"`
}
type gitLabSearchPage struct {
	Items    []gitLabSearchIssue
	nextPage string
}

func (p *gitLabSearchPage) UnmarshalJSON(data []byte) error { return json.Unmarshal(data, &p.Items) }
func (p *gitLabSearchPage) setResponseHeaders(headers http.Header) {
	p.nextPage = strings.TrimSpace(headers.Get("X-Next-Page"))
}

type responseHeaderSink interface{ setResponseHeaders(http.Header) }

var descriptors = map[integration.Provider]integration.ProviderDescriptor{
	GitHubProvider:     {Provider: GitHubProvider, Name: "GitHub Issues", Description: "Private GitHub repository issues using the tenant SCM connector.", Capabilities: []integration.Capability{integration.CapabilityTickets, integration.CapabilityTestConnection}, ConfigFields: []integration.FieldDescriptor{{Name: "repository", Label: "Repository", Kind: integration.FieldText, Required: true}}},
	GitLabProvider:     {Provider: GitLabProvider, Name: "GitLab Issues", Description: "Confidential GitLab issues using the tenant SCM connector.", Capabilities: []integration.Capability{integration.CapabilityTickets, integration.CapabilityTestConnection}, ConfigFields: []integration.FieldDescriptor{{Name: "project", Label: "Project path", Kind: integration.FieldText, Required: true}}},
	AzureProvider:      {Provider: AzureProvider, Name: "Azure Boards", Description: "Azure DevOps Services work items.", Capabilities: []integration.Capability{integration.CapabilityTickets, integration.CapabilityTestConnection}, ConfigFields: []integration.FieldDescriptor{{Name: "work_item_type", Label: "Work item type", Kind: integration.FieldText, Required: true}}, SecretFields: []integration.FieldDescriptor{{Name: "pat", Label: "Personal access token", Kind: integration.FieldPassword, Required: true}}},
	ServiceNowProvider: {Provider: ServiceNowProvider, Name: "ServiceNow", Description: "ServiceNow incident or vulnerability records.", Capabilities: []integration.Capability{integration.CapabilityTickets, integration.CapabilityTestConnection}, ConfigFields: []integration.FieldDescriptor{{Name: "table", Label: "Table", Kind: integration.FieldText, Required: true}}, SecretFields: []integration.FieldDescriptor{{Name: "token", Label: "API token", Kind: integration.FieldPassword, Required: true}}},
	LinearProvider:     {Provider: LinearProvider, Name: "Linear", Description: "Linear issues through its GraphQL API.", Capabilities: []integration.Capability{integration.CapabilityTickets, integration.CapabilityTestConnection}, ConfigFields: []integration.FieldDescriptor{{Name: "team_id", Label: "Team ID", Kind: integration.FieldText, Required: true}}, SecretFields: []integration.FieldDescriptor{{Name: "token", Label: "API token", Kind: integration.FieldPassword, Required: true}}},
}

// Register uses the existing tenant-scoped SCM connector for GitHub/GitLab.
// The other three providers use the ordinary sealed integration credential store.
func Register(registry *integration.Registry, scm ports.SCMConnectorStore) error {
	if registry == nil || scm == nil {
		return fmt.Errorf("%w: ticket provider registry and SCM connector store are required", shared.ErrValidation)
	}
	for _, p := range []integration.Provider{GitHubProvider, GitLabProvider, AzureProvider, ServiceNowProvider, LinearProvider} {
		d := descriptors[p]
		provider := p
		if err := registry.Register(d, func(item integration.Integration, credentials integration.CredentialBundle, rules selfhosted.Rules) (integration.Adapter, error) {
			return New(item, credentials, rules, scm, provider)
		}); err != nil {
			return err
		}
	}
	return nil
}

// New is public for adapter contract tests.  Runtime construction should use Register.
func New(item integration.Integration, credentials integration.CredentialBundle, rules selfhosted.Rules, scm ports.SCMConnectorStore, expected integration.Provider) (*Adapter, error) {
	if item.Provider != expected {
		return nil, fmt.Errorf("%w: wrong ticket provider", shared.ErrValidation)
	}
	if err := item.Normalize(); err != nil {
		return nil, err
	}
	d, ok := descriptors[expected]
	if !ok {
		return nil, fmt.Errorf("%w: unsupported ticket provider", shared.ErrValidation)
	}
	if err := d.ValidateSecrets(map[string]string(credentials)); err != nil {
		return nil, err
	}
	a := &Adapter{item: item, descriptor: d, provider: expected, scm: scm, token: []byte(credentials[secretField(expected)]), rules: rules}
	if expected == GitHubProvider || expected == GitLabProvider {
		if len(credentials) != 0 || scm == nil {
			return nil, fmt.Errorf("%w: SCM ticket providers require connector credentials only", shared.ErrValidation)
		}
		if err := a.configureSCM(); err != nil {
			return nil, err
		}
	} else if err := a.configureOrdinary(rules); err != nil {
		return nil, err
	}
	return a, nil
}

type Adapter struct {
	item       integration.Integration
	descriptor integration.ProviderDescriptor
	provider   integration.Provider
	scm        ports.SCMConnectorStore
	client     *http.Client
	base       *url.URL
	token      []byte
	project    string
	// credentialHost is the normalized connector identity. It is intentionally
	// distinct from base: GitHub SaaS authenticates github.com credentials to
	// api.github.com, while a self-hosted connector authenticates only to its
	// validated API base.
	credentialHost string
	browserBase    *url.URL
	rules          selfhosted.Rules
	payloadTokens  [][]byte
}

type scmRequest struct {
	token   []byte
	apiBase string
	base    *url.URL
	client  *http.Client
}

func (r *scmRequest) clear() { clear(r.token); r.token = nil }

type ticketRequest func(context.Context, string, string, url.Values, []byte, any) error

var _ integration.Adapter = (*Adapter)(nil)
var _ integration.ConnectionTester = (*Adapter)(nil)
var _ ports.TicketProvider = (*Adapter)(nil)
var _ ports.TicketPayloadBuilder = (*Adapter)(nil)
var _ ports.TicketReader = (*Adapter)(nil)
var _ ports.TicketIdentityReader = (*Adapter)(nil)

func (a *Adapter) Descriptor() integration.ProviderDescriptor { return a.descriptor }
func (a *Adapter) Close() {
	if a.client != nil {
		a.client.CloseIdleConnections()
	}
	clear(a.token)
	for _, token := range a.payloadTokens {
		clear(token)
	}
	a.payloadTokens = nil
}

func secretField(p integration.Provider) string {
	if p == AzureProvider {
		return "pat"
	}
	return "token"
}
func (a *Adapter) configureSCM() error {
	u, err := url.Parse(a.item.Endpoint)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" || strings.Trim(u.Path, "/") != "" {
		return fmt.Errorf("%w: invalid SCM endpoint", shared.ErrValidation)
	}
	host, err := scmconnector.NormalizeHost(u.Host)
	if err != nil {
		return fmt.Errorf("%w: invalid SCM endpoint", shared.ErrValidation)
	}
	config, err := integration.DecodeConfig(a.item.Config)
	if err != nil {
		return err
	}
	key := "repository"
	if a.provider == GitLabProvider {
		key = "project"
	}
	a.project, _ = config[key].(string)
	a.project = strings.TrimSpace(a.project)
	if (a.provider == GitHubProvider && !repoRE.MatchString(a.project)) || (a.provider == GitLabProvider && !projectPathRE.MatchString(a.project)) {
		return fmt.Errorf("%w: SCM repository/project path is invalid", shared.ErrValidation)
	}
	a.credentialHost = host
	a.browserBase = &url.URL{Scheme: "https", Host: u.Host}
	if a.provider == GitHubProvider && host == "github.com" {
		a.base = &url.URL{Scheme: "https", Host: "api.github.com"}
	} else if a.provider == GitLabProvider && host == "gitlab.com" {
		a.base = &url.URL{Scheme: "https", Host: "gitlab.com", Path: "/api/v4"}
	} else {
		// The connector's API base is authoritative for a self-hosted forge.
		a.base = &url.URL{Scheme: "https", Host: u.Host}
	}
	if (a.provider == GitHubProvider && host == "github.com") || (a.provider == GitLabProvider && host == "gitlab.com") {
		a.client = safehttp.NewClient(20*time.Second, safehttp.Policy{AllowHost: func(h, p string) bool { return strings.EqualFold(h, a.base.Hostname()) && p == effectivePort(a.base) }})
	} else {
		a.client = selfhostedhttp.NewClient(20*time.Second, a.rules, true)
	}
	return nil
}
func (a *Adapter) configureOrdinary(rules selfhosted.Rules) error {
	u, err := url.Parse(a.item.Endpoint)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" {
		return fmt.Errorf("%w: invalid endpoint", shared.ErrValidation)
	}
	host := strings.ToLower(u.Hostname())
	switch a.provider {
	case AzureProvider:
		if host != "dev.azure.com" || u.Port() != "" && u.Port() != "443" {
			return fmt.Errorf("%w: Azure Boards requires dev.azure.com", shared.ErrValidation)
		}
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) != 2 || !ordinaryPathPartRE.MatchString(parts[0]) || !azureProjectPartRE.MatchString(parts[1]) || strings.TrimSpace(parts[1]) != parts[1] || u.RawPath != "" {
			return fmt.Errorf("%w: Azure Boards endpoint must name organization/project", shared.ErrValidation)
		}
		a.project = strings.Join(parts, "/")
	case LinearProvider:
		if host != "api.linear.app" || u.Port() != "" && u.Port() != "443" || u.EscapedPath() != "/graphql" {
			return fmt.Errorf("%w: Linear requires https://api.linear.app/graphql", shared.ErrValidation)
		}
	case ServiceNowProvider:
		if !strings.HasSuffix(host, ".service-now.com") || host == "service-now.com" || u.Port() != "" && u.Port() != "443" || strings.Trim(u.Path, "/") != "" {
			return fmt.Errorf("%w: ServiceNow requires a SaaS instance host", shared.ErrValidation)
		}
	}
	config, err := integration.DecodeConfig(a.item.Config)
	if err != nil {
		return err
	}
	if a.provider == AzureProvider {
		a.project += "/" + strings.TrimSpace(stringValue(config, "work_item_type"))
	} else if a.provider == ServiceNowProvider {
		a.project = strings.TrimSpace(stringValue(config, "table"))
		if a.project != "incident" && a.project != "sn_vul_vulnerable_item" {
			return fmt.Errorf("%w: ServiceNow table must be incident or sn_vul_vulnerable_item", shared.ErrValidation)
		}
	} else if a.provider == LinearProvider {
		a.project = strings.TrimSpace(stringValue(config, "team_id"))
		if a.project == "" {
			return fmt.Errorf("%w: Linear team ID required", shared.ErrValidation)
		}
	} else {
		return fmt.Errorf("%w: unsupported ticket provider", shared.ErrValidation)
	}
	// Azure endpoints name the target organization/project but API requests are
	// rooted at dev.azure.com. Keeping the root here prevents every operation
	// from accidentally appending org/project twice.
	if a.provider == AzureProvider {
		a.base = &url.URL{Scheme: u.Scheme, Host: u.Host}
	} else {
		a.base = u
	}
	a.base.RawQuery = ""
	a.base.Fragment = ""
	a.client = safehttp.NewClient(20*time.Second, safehttp.Policy{AllowHost: func(h, p string) bool { return p == "443" && strings.EqualFold(h, host) }})
	_ = rules
	return nil
}
func stringValue(v map[string]any, k string) string { s, _ := v[k].(string); return s }

func (a *Adapter) BuildTicketPayload(_ context.Context, in ports.TicketPayloadInput) (ports.TicketPayload, error) {
	if strings.TrimSpace(in.Summary) == "" || len(in.Summary) > 1024 || len(in.Description) > maxPayload || !json.Valid(in.Description) {
		return ports.TicketPayload{}, ticketErr(0, "invalid_payload", false)
	}
	var desc string
	if err := json.Unmarshal(in.Description, &desc); err != nil {
		return ports.TicketPayload{}, ticketErr(0, "invalid_description", false)
	}
	switch a.provider {
	case GitHubProvider:
		return marshalPayload(map[string]any{"title": in.Summary, "body": desc, "labels": []string{}}, ports.TicketMarkerDescriptor{Version: 1, Strategy: ports.TicketMarkerJSONArray, Path: []string{"labels"}})
	case GitLabProvider:
		return marshalPayload(map[string]any{"title": in.Summary, "description": desc, "confidential": true, "labels": ""}, ports.TicketMarkerDescriptor{Version: 1, Strategy: ports.TicketMarkerTag, Path: []string{"labels"}})
	case AzureProvider:
		fragment, err := messageformat.HTMLFragment(desc, in.Links)
		if err != nil {
			return ports.TicketPayload{}, ticketErr(0, "invalid_link", false)
		}
		return marshalPayload([]map[string]any{{"op": "add", "path": "/fields/System.Title", "value": in.Summary}, {"op": "add", "path": "/fields/System.Description", "value": fragment}}, ports.TicketMarkerDescriptor{Version: 1, Strategy: ports.TicketMarkerJSONPatchAdd, Path: []string{"fields", "System.Tags"}})
	case ServiceNowProvider:
		return marshalPayload(map[string]any{"short_description": in.Summary, "description": desc, "correlation_id": ""}, ports.TicketMarkerDescriptor{Version: 1, Strategy: ports.TicketMarkerScalar, Path: []string{"correlation_id"}})
	case LinearProvider:
		return marshalPayload(map[string]any{"query": "mutation IssueCreate($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier url } } }", "variables": map[string]any{"input": map[string]any{"teamId": a.project, "title": in.Summary, "description": desc}}}, ports.TicketMarkerDescriptor{Version: 1, Strategy: ports.TicketMarkerTextSuffix, Path: []string{"variables", "input", "description"}})
	default:
		return ports.TicketPayload{}, ticketErr(0, "unsupported_provider", false)
	}
}
func marshalPayload(v any, m ports.TicketMarkerDescriptor) (ports.TicketPayload, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return ports.TicketPayload{}, ticketErr(0, "invalid_payload", false)
	}
	return ports.TicketPayload{Wire: b, Marker: m}, nil
}
func (a *Adapter) FormatTicketDescription(body string, links []ports.RenderedLink) (json.RawMessage, error) {
	if len(body) > maxPayload {
		return nil, ticketErr(0, "description_too_large", false)
	}
	if a.provider == AzureProvider {
		// Validate at both formatter and serializer boundaries; keep typed links
		// separate so only the native builder can create HTML anchors.
		if _, err := messageformat.HTMLFragment("", links); err != nil {
			return nil, ticketErr(0, "invalid_link", false)
		}
		return json.Marshal(body)
	}
	if a.provider == ServiceNowProvider {
		body = messageformat.PlainText(body)
	}
	for _, l := range links {
		u, e := url.Parse(l.URL)
		if e != nil || u.Scheme != "https" || u.Host == "" {
			return nil, ticketErr(0, "invalid_link", false)
		}
		body += "\n" + l.Label + ": " + u.String()
	}
	return json.Marshal(body)
}
func (a *Adapter) ValidateTicketPayload(payload json.RawMessage) error {
	if len(payload) == 0 || len(payload) > maxPayload || !json.Valid(payload) {
		return ticketErr(0, "invalid_payload", false)
	}
	tokens := make([][]byte, 0, len(a.payloadTokens)+1)
	if len(a.token) > 0 {
		tokens = append(tokens, a.token)
	}
	tokens = append(tokens, a.payloadTokens...)
	defer func() {
		for _, token := range a.payloadTokens {
			clear(token)
		}
		a.payloadTokens = nil
	}()
	if err := rejectPayloadSecrets(payload, tokens); err != nil {
		return err
	}
	return nil
}

// BindTicketCredentials supplies the current SCM credential only to the
// payload redactor. Requests resolve it again at the moment they are sent, so
// a rotated or revoked connector cannot be used for an outward write.
func (a *Adapter) BindTicketCredentials(ctx context.Context) error {
	if a.provider != GitHubProvider && a.provider != GitLabProvider {
		return nil
	}
	credential, ok, err := a.scm.ResolveGitCredential(ctx, a.credentialHost)
	if err != nil || !ok || len(credential.Token) == 0 {
		return ticketErr(0, "connector_missing", false)
	}
	a.payloadTokens = append(a.payloadTokens, append([]byte(nil), credential.Token...))
	return nil
}

func rejectPayloadSecrets(payload []byte, tokens [][]byte) error {
	variants := make(map[string]struct{})
	secrets := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if len(token) == 0 {
			continue
		}
		value := string(token)
		secrets = append(secrets, value)
		variants[value] = struct{}{}
		variants[base64.StdEncoding.EncodeToString(token)] = struct{}{}
		variants[base64.RawStdEncoding.EncodeToString(token)] = struct{}{}
		variants[base64.URLEncoding.EncodeToString(token)] = struct{}{}
		variants[base64.RawURLEncoding.EncodeToString(token)] = struct{}{}
		variants[url.QueryEscape(value)] = struct{}{}
	}
	if len(variants) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return ticketErr(0, "invalid_payload", false)
		}
		value, ok := token.(string)
		if !ok {
			continue
		}
		if redact.String(value, secrets) != value {
			return ticketErr(0, "payload_contains_credential", false)
		}
		for forbidden := range variants {
			if forbidden != "" && strings.Contains(value, forbidden) {
				return ticketErr(0, "payload_contains_credential", false)
			}
		}
	}
}

func (a *Adapter) TestConnection(ctx context.Context) error {
	_, err := a.TicketIdentity(ctx)
	return err
}
func (a *Adapter) DiscoverTickets(ctx context.Context, project, issueType, issue string) (ports.TicketMetadata, error) {
	if _, err := a.TicketIdentity(ctx); err != nil {
		return ports.TicketMetadata{}, err
	}
	policy := "provider_access"
	if a.provider == GitHubProvider {
		policy = "private_repository"
	}
	if a.provider == GitLabProvider {
		policy = "confidential_issue"
	}
	// These providers intentionally expose no grouping or transition controls.
	// The selected project/type remains pinned to the native destination rather
	// than accepting an unverified UI-supplied value.
	return ports.TicketMetadata{
		Projects:       []ports.TicketChoice{{ID: a.project, Name: a.project}},
		IssueTypes:     []ports.TicketChoice{{ID: ticketKind(a.provider, a.project), Name: ticketKind(a.provider, a.project)}},
		SecurityPolicy: policy, SupportsGrouping: false, SupportsStatusSync: false, SupportsStatusTransitions: false,
	}, nil
}

func ticketKind(provider integration.Provider, project string) string {
	if provider == AzureProvider {
		parts := strings.Split(project, "/")
		if len(parts) == 3 {
			return parts[2]
		}
	}
	if provider == ServiceNowProvider {
		return project
	}
	return "issue"
}

func (a *Adapter) CreateTicket(ctx context.Context, payload json.RawMessage) (ticketing.RemoteTicket, error) {
	if err := a.ValidateTicketPayload(payload); err != nil {
		return ticketing.RemoteTicket{}, err
	}
	if a.provider == GitHubProvider || a.provider == GitLabProvider {
		preflight, err := a.scmPreflightRequest(ctx)
		if err != nil {
			return ticketing.RemoteTicket{}, err
		}
		defer preflight.clear()
		outbound, err := a.currentSCMRequest(ctx, preflight)
		if err != nil {
			return ticketing.RemoteTicket{}, err
		}
		defer outbound.clear()
		// The connector may have rotated since preview or literal validation.
		// Validate against the exact credential selected for this outward write.
		if err := rejectPayloadSecrets(payload, [][]byte{outbound.token}); err != nil {
			return ticketing.RemoteTicket{}, err
		}
		return a.createWithRequest(ctx, payload, func(ctx context.Context, method, path string, q url.Values, body []byte, out any) error {
			return a.requestWithClient(ctx, outbound.client, outbound.base, outbound.token, method, path, q, body, out)
		})
	}
	return a.createWithRequest(ctx, payload, a.request)
}

func (a *Adapter) createWithRequest(ctx context.Context, payload json.RawMessage, request ticketRequest) (ticketing.RemoteTicket, error) {
	switch a.provider {
	case GitHubProvider:
		return a.createGitHubWith(ctx, payload, request)
	case GitLabProvider:
		return a.createGitLabWith(ctx, payload, request)
	case AzureProvider:
		return a.createAzureWith(ctx, payload, request)
	case ServiceNowProvider:
		return a.createServiceNowWith(ctx, payload, request)
	case LinearProvider:
		return a.createLinearWith(ctx, payload, request)
	default:
		return ticketing.RemoteTicket{}, ticketErr(0, "unsupported_provider", false)
	}
}
func (a *Adapter) SearchTicketMarker(ctx context.Context, project, issueType, marker string) ([]ticketing.RemoteTicket, error) {
	if !markerRE.MatchString(marker) {
		return nil, ticketErr(0, "invalid_marker", false)
	}
	if a.provider == GitHubProvider || a.provider == GitLabProvider {
		if err := a.scmPreflight(ctx); err != nil {
			return nil, err
		}
	}
	return a.search(ctx, marker)
}
func (a *Adapter) GetTicket(ctx context.Context, id string) (ports.TicketObservation, error) {
	if strings.TrimSpace(id) == "" || len(id) > 512 {
		return ports.TicketObservation{}, ticketErr(0, "invalid_ticket", false)
	}
	// Reading a ticket body/status is also content exposure. Recheck the current
	// repository/project policy before every GitHub/GitLab outward read.
	if a.provider == GitHubProvider || a.provider == GitLabProvider {
		if err := a.scmPreflight(ctx); err != nil {
			return ports.TicketObservation{}, err
		}
	}
	switch a.provider {
	case GitHubProvider:
		var out struct {
			Number    int        `json:"number"`
			UpdatedAt time.Time  `json:"updated_at"`
			State     string     `json:"state"`
			ClosedAt  *time.Time `json:"closed_at"`
			ClosedBy  *struct {
				Login string `json:"login"`
			} `json:"closed_by"`
		}
		if err := a.request(ctx, http.MethodGet, "/repos/"+a.project+"/issues/"+url.PathEscape(id), nil, nil, &out); err != nil {
			return ports.TicketObservation{}, err
		}
		if out.Number < 1 || out.UpdatedAt.IsZero() {
			return ports.TicketObservation{}, ticketErr(http.StatusOK, "invalid_ticket_response", false)
		}
		obs := ports.TicketObservation{ExternalID: id, UpdatedAt: out.UpdatedAt, StatusCategory: githubStatus(out.State)}
		if githubStatus(out.State) == "done" && out.ClosedAt != nil && out.ClosedBy != nil && strings.TrimSpace(out.ClosedBy.Login) != "" {
			obs.StatusChangedAt = *out.ClosedAt
			obs.AuthorID = out.ClosedBy.Login
		}
		return obs, nil
	case GitLabProvider:
		var out struct {
			IID          int        `json:"iid"`
			UpdatedAt    time.Time  `json:"updated_at"`
			State        string     `json:"state"`
			Confidential bool       `json:"confidential"`
			ClosedAt     *time.Time `json:"closed_at"`
			ClosedBy     *struct {
				Username string `json:"username"`
			} `json:"closed_by"`
		}
		if err := a.request(ctx, http.MethodGet, "/projects/"+url.PathEscape(a.project)+"/issues/"+url.PathEscape(id), nil, nil, &out); err != nil {
			return ports.TicketObservation{}, err
		}
		if out.IID < 1 || !out.Confidential || out.UpdatedAt.IsZero() {
			return ports.TicketObservation{}, ticketErr(http.StatusOK, "invalid_ticket_response", false)
		}
		obs := ports.TicketObservation{ExternalID: id, UpdatedAt: out.UpdatedAt, StatusCategory: githubStatus(out.State)}
		if githubStatus(out.State) == "done" && out.ClosedAt != nil && out.ClosedBy != nil && strings.TrimSpace(out.ClosedBy.Username) != "" {
			obs.StatusChangedAt = *out.ClosedAt
			obs.AuthorID = out.ClosedBy.Username
		}
		return obs, nil
	case AzureProvider:
		parts := strings.Split(a.project, "/")
		if len(parts) != 3 {
			return ports.TicketObservation{}, ticketErr(0, "invalid_project", false)
		}
		var out struct {
			ID     int                        `json:"id"`
			Fields map[string]json.RawMessage `json:"fields"`
		}
		if err := a.request(ctx, http.MethodGet, "/"+parts[0]+"/"+parts[1]+"/_apis/wit/workitems/"+url.PathEscape(id), url.Values{"api-version": {"7.1"}}, nil, &out); err != nil {
			return ports.TicketObservation{}, err
		}
		if out.ID < 1 {
			return ports.TicketObservation{}, ticketErr(http.StatusOK, "invalid_ticket_response", false)
		}
		updated, ok := azureTime(out.Fields["System.ChangedDate"])
		if !ok {
			return ports.TicketObservation{}, ticketErr(http.StatusOK, "invalid_ticket_response", false)
		}
		state, _ := jsonString(out.Fields["System.State"])
		observation := ports.TicketObservation{ExternalID: id, UpdatedAt: updated, StatusCategory: azureStatus(state)}
		// System.ChangedBy/ChangedDate describe the last edit, which can be an
		// unrelated field change. Only an update record that changed System.State
		// to the current terminal state is admissible as an external proposal.
		if observation.StatusCategory == "done" {
			author, at, proven, err := a.azureStateEpisode(ctx, parts, id, state)
			if err != nil {
				return ports.TicketObservation{}, err
			}
			if proven {
				observation.AuthorID, observation.StatusChangedAt = author, at
			}
		}
		return observation, nil
	case ServiceNowProvider:
		var out struct {
			Result struct {
				SysID        string `json:"sys_id"`
				SysUpdatedOn string `json:"sys_updated_on"`
				State        string `json:"state"`
			} `json:"result"`
		}
		if err := a.request(ctx, http.MethodGet, "/api/now/table/"+a.project+"/"+url.PathEscape(id), nil, nil, &out); err != nil {
			return ports.TicketObservation{}, err
		}
		updated, ok := providerTime(out.Result.SysUpdatedOn)
		if out.Result.SysID == "" || !ok {
			return ports.TicketObservation{}, ticketErr(http.StatusOK, "invalid_ticket_response", false)
		}
		// The record's closed_by/closed_at fields do not prove the actor who made
		// the state change. ServiceNow sys_audit is not available on every table,
		// so leave this proposal unattributed unless a bounded audit reader exists.
		return ports.TicketObservation{ExternalID: id, UpdatedAt: updated, StatusCategory: serviceNowStatus(out.Result.State)}, nil
	case LinearProvider:
		payload, _ := json.Marshal(map[string]any{"query": "query Issue($id: String!) { issue(id: $id) { id updatedAt state { type } } }", "variables": map[string]string{"id": id}})
		var out struct {
			Data struct {
				Issue struct {
					ID        string    `json:"id"`
					UpdatedAt time.Time `json:"updatedAt"`
					State     struct {
						Type string `json:"type"`
					} `json:"state"`
				} `json:"issue"`
			} `json:"data"`
			Errors []json.RawMessage `json:"errors"`
		}
		if err := a.request(ctx, http.MethodPost, "", nil, payload, &out); err != nil {
			return ports.TicketObservation{}, err
		}
		if len(out.Errors) > 0 || out.Data.Issue.ID != id {
			return ports.TicketObservation{}, ticketErr(http.StatusOK, "invalid_ticket_response", false)
		}
		if out.Data.Issue.UpdatedAt.IsZero() {
			return ports.TicketObservation{}, ticketErr(http.StatusOK, "invalid_ticket_response", false)
		}
		// Linear's issue query exposes updatedAt but not a state-history
		// episode. Leave author/time empty until a bounded state history proves it.
		return ports.TicketObservation{ExternalID: id, StatusCategory: linearStatus(out.Data.Issue.State.Type), UpdatedAt: out.Data.Issue.UpdatedAt}, nil
	}
	return ports.TicketObservation{}, ticketErr(0, "unsupported_provider", false)
}
func (a *Adapter) azureStateEpisode(ctx context.Context, parts []string, id, current string) (string, time.Time, bool, error) {
	var out struct {
		Count int `json:"count"`
		Value []struct {
			RevisedDate time.Time `json:"revisedDate"`
			RevisedBy   struct {
				ID string `json:"id"`
			} `json:"revisedBy"`
			Fields map[string]struct {
				OldValue json.RawMessage `json:"oldValue"`
				NewValue json.RawMessage `json:"newValue"`
			} `json:"fields"`
		} `json:"value"`
	}
	if err := a.request(ctx, http.MethodGet, "/"+parts[0]+"/"+parts[1]+"/_apis/wit/workitems/"+url.PathEscape(id)+"/updates", url.Values{"api-version": {"7.1"}, "$top": {"20"}}, nil, &out); err != nil {
		return "", time.Time{}, false, err
	}
	// A full page is deliberately inconclusive: there may be a later state
	// change outside the bounded response, so it cannot safely authenticate it.
	if out.Count < 0 || len(out.Value) > 20 || out.Count > 20 || len(out.Value) == 20 {
		return "", time.Time{}, false, nil
	}
	var author string
	var changed time.Time
	for _, update := range out.Value {
		field, ok := update.Fields["System.State"]
		if !ok {
			continue
		}
		next, valid := jsonString(field.NewValue)
		if !valid || !strings.EqualFold(next, current) || update.RevisedDate.IsZero() || strings.TrimSpace(update.RevisedBy.ID) == "" {
			continue
		}
		if update.RevisedDate.After(changed) {
			changed = update.RevisedDate
			author = update.RevisedBy.ID
		}
	}
	if changed.IsZero() {
		return "", time.Time{}, false, nil
	}
	return author, changed, true, nil
}
func githubStatus(v string) string {
	switch strings.ToLower(v) {
	case "open":
		return "new"
	case "closed":
		return "done"
	}
	return "indeterminate"
}
func azureStatus(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "new", "active", "approved":
		return "new"
	case "closed", "done", "resolved", "removed":
		return "done"
	}
	return "indeterminate"
}
func serviceNowStatus(v string) string {
	switch strings.TrimSpace(v) {
	case "1", "2", "3":
		return "new"
	case "6", "7":
		return "done"
	}
	return "indeterminate"
}
func providerTime(v string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05"} {
		if t, e := time.Parse(layout, v); e == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
func jsonString(v json.RawMessage) (string, bool) {
	var s string
	e := json.Unmarshal(v, &s)
	return s, e == nil
}
func azureTime(v json.RawMessage) (time.Time, bool) {
	s, ok := jsonString(v)
	if !ok {
		return time.Time{}, false
	}
	return providerTime(s)
}
func (a *Adapter) TicketIdentity(ctx context.Context) (string, error) {
	if a.provider == GitHubProvider || a.provider == GitLabProvider {
		if err := a.scmPreflight(ctx); err != nil {
			return "", err
		}
	}
	if len(a.token) == 0 && a.provider != GitHubProvider && a.provider != GitLabProvider {
		return "", ticketErr(0, "credential_missing", false)
	}
	switch a.provider {
	case GitHubProvider:
		var out struct {
			Login string `json:"login"`
		}
		if err := a.request(ctx, http.MethodGet, "/user", nil, nil, &out); err != nil {
			return "", err
		}
		return identity(out.Login)
	case GitLabProvider:
		var out struct {
			ID       int    `json:"id"`
			Username string `json:"username"`
		}
		if err := a.request(ctx, http.MethodGet, "/user", nil, nil, &out); err != nil {
			return "", err
		}
		if out.ID < 1 {
			return "", ticketErr(http.StatusOK, "invalid_identity", false)
		}
		return identity(out.Username)
	case AzureProvider:
		parts := strings.Split(a.project, "/")
		if len(parts) != 3 {
			return "", ticketErr(0, "invalid_project", false)
		}
		var out struct {
			AuthenticatedUser struct {
				ID string `json:"id"`
			} `json:"authenticatedUser"`
		}
		if err := a.request(ctx, http.MethodGet, "/"+parts[0]+"/_apis/connectionData", url.Values{"api-version": {"7.1-preview.1"}}, nil, &out); err != nil {
			return "", err
		}
		return identity(out.AuthenticatedUser.ID)
	case ServiceNowProvider:
		var out struct {
			Result []struct {
				SysID string `json:"sys_id"`
			} `json:"result"`
		}
		query := url.Values{
			"sysparm_query":  {"sys_id=javascript:gs.getUserID()"},
			"sysparm_fields": {"sys_id"},
			"sysparm_limit":  {"2"},
		}
		if err := a.request(ctx, http.MethodGet, "/api/now/table/sys_user", query, nil, &out); err != nil {
			return "", err
		}
		if len(out.Result) != 1 || len(out.Result[0].SysID) != 32 || strings.Trim(out.Result[0].SysID, "0123456789abcdef") != "" {
			return "", ticketErr(http.StatusOK, "invalid_identity", false)
		}
		return identity(out.Result[0].SysID)
	case LinearProvider:
		payload, _ := json.Marshal(map[string]string{"query": "query Viewer { viewer { id } }"})
		var out struct {
			Data struct {
				Viewer struct {
					ID string `json:"id"`
				} `json:"viewer"`
			} `json:"data"`
			Errors []json.RawMessage `json:"errors"`
		}
		if err := a.request(ctx, http.MethodPost, "", nil, payload, &out); err != nil {
			return "", err
		}
		if len(out.Errors) > 0 {
			return "", ticketErr(http.StatusOK, "invalid_identity", false)
		}
		return identity(out.Data.Viewer.ID)
	default:
		return "", ticketErr(0, "unsupported_provider", false)
	}
}
func identity(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 255 {
		return "", ticketErr(http.StatusOK, "invalid_identity", false)
	}
	return v, nil
}

func (a *Adapter) scmPreflight(ctx context.Context) error {
	request, err := a.scmPreflightRequest(ctx)
	if err != nil {
		return err
	}
	request.clear()
	return nil
}

func (a *Adapter) scmPreflightRequest(ctx context.Context) (*scmRequest, error) {
	metas, err := a.scm.List(ctx)
	if err != nil {
		return nil, ticketErr(0, "connector_unavailable", false)
	}
	host := a.credentialHost
	want := scmconnector.ProviderGitHub
	if a.provider == GitLabProvider {
		want = scmconnector.ProviderGitLab
	}
	found := false
	for _, m := range metas {
		if m.Host == host && m.Provider == want {
			found = true
			break
		}
	}
	if !found {
		return nil, ticketErr(0, "connector_missing", false)
	}
	cred, ok, err := a.scm.ResolveGitCredential(ctx, host)
	if err != nil || !ok || len(cred.Token) == 0 {
		return nil, ticketErr(0, "connector_missing", false)
	}
	base, client, browser, err := a.resolveSCMEndpoint(cred)
	if err != nil {
		return nil, err
	}
	request := &scmRequest{token: append([]byte(nil), cred.Token...), apiBase: cred.APIBase, base: base, client: client}
	fail := func(err error) (*scmRequest, error) { request.clear(); return nil, err }
	if a.provider == GitHubProvider {
		var repo struct {
			Private     bool            `json:"private"`
			Visibility  string          `json:"visibility"`
			HasIssues   bool            `json:"has_issues"`
			Permissions map[string]bool `json:"permissions"`
		}
		if err := a.requestWithClient(ctx, client, base, request.token, http.MethodGet, "/repos/"+a.project, nil, nil, &repo); err != nil {
			return fail(err)
		}
		if !repo.Private || repo.Visibility != "private" || !repo.HasIssues || !(repo.Permissions["push"] || repo.Permissions["maintain"] || repo.Permissions["admin"]) {
			return fail(ticketErr(http.StatusForbidden, "private_repository_required", false))
		}
	} else {
		var p struct {
			Permissions struct {
				ProjectAccess *struct {
					AccessLevel int `json:"access_level"`
				} `json:"project_access"`
				GroupAccess *struct {
					AccessLevel int `json:"access_level"`
				} `json:"group_access"`
			} `json:"permissions"`
		}
		if err := a.requestWithClient(ctx, client, base, request.token, http.MethodGet, "/projects/"+url.PathEscape(a.project), nil, nil, &p); err != nil {
			return fail(err)
		}
		accessLevel := 0
		if p.Permissions.ProjectAccess != nil {
			accessLevel = p.Permissions.ProjectAccess.AccessLevel
		}
		if p.Permissions.GroupAccess != nil {
			accessLevel = max(accessLevel, p.Permissions.GroupAccess.AccessLevel)
		}
		if accessLevel < 30 {
			return fail(ticketErr(http.StatusForbidden, "provider_access_required", false))
		}
	}
	_ = browser
	return request, nil
}

func (a *Adapter) currentSCMRequest(ctx context.Context, expected *scmRequest) (*scmRequest, error) {
	metas, err := a.scm.List(ctx)
	if err != nil {
		return nil, ticketErr(0, "connector_unavailable", false)
	}
	want := scmconnector.ProviderGitHub
	if a.provider == GitLabProvider {
		want = scmconnector.ProviderGitLab
	}
	found := false
	for _, meta := range metas {
		if meta.Host == a.credentialHost && meta.Provider == want && meta.APIBase == expected.apiBase {
			found = true
			break
		}
	}
	if !found {
		return nil, ticketErr(0, "credential_changed", false)
	}
	credential, ok, err := a.scm.ResolveGitCredential(ctx, a.credentialHost)
	if err != nil || !ok || len(credential.Token) == 0 || !bytes.Equal(credential.Token, expected.token) || credential.APIBase != expected.apiBase {
		return nil, ticketErr(0, "credential_changed", false)
	}
	base, client, _, err := a.resolveSCMEndpoint(credential)
	if err != nil {
		return nil, ticketErr(0, "credential_changed", false)
	}
	return &scmRequest{token: append([]byte(nil), credential.Token...), apiBase: credential.APIBase, base: base, client: client}, nil
}

// resolveSCMEndpoint binds a token only to the connector host's validated API
// endpoint. Public forge browser hosts and APIs deliberately differ for GitHub.
func (a *Adapter) resolveSCMEndpoint(credential ports.GitCredential) (*url.URL, *http.Client, *url.URL, error) {
	if a.credentialHost == "" {
		return nil, nil, nil, ticketErr(0, "connector_api_base_invalid", false)
	}
	if credential.APIBase == "" {
		if (a.provider == GitHubProvider && a.credentialHost != "github.com") || (a.provider == GitLabProvider && a.credentialHost != "gitlab.com") {
			return nil, nil, nil, ticketErr(0, "connector_api_base_invalid", false)
		}
		return a.base, a.client, a.browserBase, nil
	}
	want := scmconnector.ProviderGitHub
	if a.provider == GitLabProvider {
		want = scmconnector.ProviderGitLab
	}
	normalized, err := scmconnector.NormalizeAPIBase(want, a.credentialHost, credential.APIBase)
	if err != nil {
		return nil, nil, nil, ticketErr(0, "connector_api_base_invalid", false)
	}
	if err := a.rules.CheckListedEndpoint(normalized, true); err != nil {
		return nil, nil, nil, ticketErr(0, "connector_api_base_invalid", false)
	}
	base, err := url.Parse(normalized)
	if err != nil {
		return nil, nil, nil, ticketErr(0, "connector_api_base_invalid", false)
	}
	return base, a.client, a.browserBase, nil
}
func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (a *Adapter) createGitHubWith(ctx context.Context, p json.RawMessage, request ticketRequest) (ticketing.RemoteTicket, error) {
	var out struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	if err := request(ctx, http.MethodPost, "/repos/"+a.project+"/issues", nil, p, &out); err != nil {
		return ticketing.RemoteTicket{}, err
	}
	if out.Number <= 0 || !a.ticketURLValid(out.HTMLURL) {
		return ticketing.RemoteTicket{}, ticketErr(http.StatusCreated, "malformed_create_response", true)
	}
	return ticketing.RemoteTicket{ID: strconv.Itoa(out.Number), URL: out.HTMLURL}, nil
}
func (a *Adapter) createGitLabWith(ctx context.Context, p json.RawMessage, request ticketRequest) (ticketing.RemoteTicket, error) {
	var out struct {
		IID          int    `json:"iid"`
		WebURL       string `json:"web_url"`
		Confidential bool   `json:"confidential"`
	}
	if err := request(ctx, http.MethodPost, "/projects/"+url.PathEscape(a.project)+"/issues", nil, p, &out); err != nil {
		return ticketing.RemoteTicket{}, err
	}
	if out.IID <= 0 || !out.Confidential || !a.ticketURLValid(out.WebURL) {
		return ticketing.RemoteTicket{}, ticketErr(http.StatusCreated, "malformed_create_response", true)
	}
	return ticketing.RemoteTicket{ID: strconv.Itoa(out.IID), URL: out.WebURL}, nil
}
func (a *Adapter) createAzureWith(ctx context.Context, p json.RawMessage, request ticketRequest) (ticketing.RemoteTicket, error) {
	var out struct {
		ID int `json:"id"`
	}
	parts := strings.Split(a.project, "/")
	if len(parts) != 3 {
		return ticketing.RemoteTicket{}, ticketErr(0, "invalid_project", false)
	}
	if err := request(ctx, http.MethodPost, "/"+parts[0]+"/"+parts[1]+"/_apis/wit/workitems/$"+url.PathEscape(parts[2]), url.Values{"api-version": {"7.1"}}, p, &out); err != nil {
		return ticketing.RemoteTicket{}, err
	}
	if out.ID <= 0 {
		return ticketing.RemoteTicket{}, ticketErr(http.StatusCreated, "malformed_create_response", true)
	}
	browser := (&url.URL{Scheme: "https", Host: "dev.azure.com", Path: "/" + parts[0] + "/" + parts[1] + "/_workitems/edit/" + strconv.Itoa(out.ID)}).String()
	return ticketing.RemoteTicket{ID: strconv.Itoa(out.ID), URL: browser}, nil
}
func (a *Adapter) createServiceNowWith(ctx context.Context, p json.RawMessage, request ticketRequest) (ticketing.RemoteTicket, error) {
	var out struct {
		Result struct {
			SysID  string `json:"sys_id"`
			Number string `json:"number"`
		} `json:"result"`
	}
	if err := request(ctx, http.MethodPost, "/api/now/table/"+a.project, nil, p, &out); err != nil {
		return ticketing.RemoteTicket{}, err
	}
	if out.Result.SysID == "" || out.Result.Number == "" {
		return ticketing.RemoteTicket{}, ticketErr(http.StatusCreated, "malformed_create_response", true)
	}
	return ticketing.RemoteTicket{ID: out.Result.SysID, URL: a.base.Scheme + "://" + a.base.Host + "/now/nav/ui/classic/params/target/" + url.QueryEscape(a.project+".do?sys_id="+out.Result.SysID)}, nil
}
func (a *Adapter) createLinearWith(ctx context.Context, p json.RawMessage, request ticketRequest) (ticketing.RemoteTicket, error) {
	var out struct {
		Data struct {
			IssueCreate struct {
				Success bool `json:"success"`
				Issue   struct{ ID, URL string }
			} `json:"issueCreate"`
		} `json:"data"`
		Errors []any `json:"errors"`
	}
	if err := request(ctx, http.MethodPost, "", nil, p, &out); err != nil {
		return ticketing.RemoteTicket{}, err
	}
	if len(out.Errors) > 0 || !out.Data.IssueCreate.Success || out.Data.IssueCreate.Issue.ID == "" || !safeHTTPS(out.Data.IssueCreate.Issue.URL, "linear.app") {
		return ticketing.RemoteTicket{}, ticketErr(http.StatusOK, "malformed_create_response", true)
	}
	return ticketing.RemoteTicket{ID: out.Data.IssueCreate.Issue.ID, URL: out.Data.IssueCreate.Issue.URL}, nil
}

func (a *Adapter) search(ctx context.Context, marker string) ([]ticketing.RemoteTicket, error) { // A provider-specific search is deliberately bounded. Unsupported search is never proof of absence.
	const limit = 3
	switch a.provider {
	case GitHubProvider:
		var out struct {
			TotalCount int  `json:"total_count"`
			Incomplete bool `json:"incomplete_results"`
			Items      []struct {
				Number  int    `json:"number"`
				HTMLURL string `json:"html_url"`
				Labels  []struct {
					Name string `json:"name"`
				} `json:"labels"`
			} `json:"items"`
		}
		q := url.Values{"q": {"repo:" + a.project + " is:issue label:" + marker}, "per_page": {strconv.Itoa(limit)}}
		if err := a.request(ctx, http.MethodGet, "/search/issues", q, nil, &out); err != nil {
			return nil, err
		}
		if out.Incomplete || out.TotalCount > 2 || len(out.Items) > 2 || out.TotalCount != len(out.Items) {
			return nil, ticketErr(http.StatusOK, "search_truncated", false)
		}
		result := make([]ticketing.RemoteTicket, 0, len(out.Items))
		seen := make(map[int]struct{}, len(out.Items))
		for _, v := range out.Items {
			if v.Number < 1 || !a.ticketURLValid(v.HTMLURL) || !hasLabel(v.Labels, marker) {
				return nil, ticketErr(http.StatusOK, "invalid_search_response", false)
			}
			if _, duplicate := seen[v.Number]; duplicate {
				return nil, ticketErr(http.StatusOK, "invalid_search_response", false)
			}
			seen[v.Number] = struct{}{}
			result = append(result, ticketing.RemoteTicket{ID: strconv.Itoa(v.Number), URL: v.HTMLURL})
		}
		return result, nil
	case GitLabProvider:
		var out gitLabSearchPage
		q := url.Values{"labels": {marker}, "per_page": {strconv.Itoa(limit)}, "scope": {"all"}}
		if err := a.request(ctx, http.MethodGet, "/projects/"+url.PathEscape(a.project)+"/issues", q, nil, &out); err != nil {
			return nil, err
		}
		if out.nextPage != "" || len(out.Items) >= limit {
			return nil, ticketErr(http.StatusOK, "search_truncated", false)
		}
		result := make([]ticketing.RemoteTicket, 0, len(out.Items))
		seen := make(map[int]struct{}, len(out.Items))
		for _, v := range out.Items {
			if v.IID < 1 || !v.Confidential || !hasString(v.Labels, marker) || !a.ticketURLValid(v.WebURL) {
				return nil, ticketErr(http.StatusOK, "invalid_search_response", false)
			}
			if _, duplicate := seen[v.IID]; duplicate {
				return nil, ticketErr(http.StatusOK, "invalid_search_response", false)
			}
			seen[v.IID] = struct{}{}
			result = append(result, ticketing.RemoteTicket{ID: strconv.Itoa(v.IID), URL: v.WebURL})
		}
		return result, nil
	case AzureProvider:
		parts := strings.Split(a.project, "/")
		if len(parts) != 3 {
			return nil, ticketErr(0, "invalid_project", false)
		}
		query, _ := json.Marshal(map[string]string{"query": "SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = '" + wiqlLiteral(parts[1]) + "' AND [System.WorkItemType] = '" + wiqlLiteral(parts[2]) + "' AND [System.Tags] CONTAINS '" + wiqlLiteral(marker) + "'"})
		var out struct {
			WorkItems []struct {
				ID int `json:"id"`
			} `json:"workItems"`
		}
		if err := a.request(ctx, http.MethodPost, "/"+parts[0]+"/"+parts[1]+"/_apis/wit/wiql", url.Values{"api-version": {"7.1"}}, query, &out); err != nil {
			return nil, err
		}
		if len(out.WorkItems) > 2 {
			return nil, ticketErr(http.StatusOK, "search_truncated", false)
		}
		r := make([]ticketing.RemoteTicket, 0, len(out.WorkItems))
		seen := make(map[int]struct{}, len(out.WorkItems))
		for _, v := range out.WorkItems {
			if v.ID < 1 {
				return nil, ticketErr(http.StatusOK, "invalid_search_response", false)
			}
			if _, duplicate := seen[v.ID]; duplicate {
				return nil, ticketErr(http.StatusOK, "invalid_search_response", false)
			}
			seen[v.ID] = struct{}{}
			var candidate struct {
				ID     int                        `json:"id"`
				Fields map[string]json.RawMessage `json:"fields"`
			}
			if err := a.request(ctx, http.MethodGet, "/"+parts[0]+"/"+parts[1]+"/_apis/wit/workitems/"+strconv.Itoa(v.ID), url.Values{"api-version": {"7.1"}}, nil, &candidate); err != nil {
				return nil, err
			}
			team, teamOK := jsonString(candidate.Fields["System.TeamProject"])
			typ, typeOK := jsonString(candidate.Fields["System.WorkItemType"])
			tags, tagsOK := jsonString(candidate.Fields["System.Tags"])
			if candidate.ID != v.ID || !teamOK || !typeOK || !tagsOK || team != parts[1] || typ != parts[2] || !hasAzureTag(tags, marker) {
				return nil, ticketErr(http.StatusOK, "invalid_search_response", false)
			}
			r = append(r, ticketing.RemoteTicket{ID: strconv.Itoa(v.ID), URL: "https://dev.azure.com/" + parts[0] + "/" + parts[1] + "/_workitems/edit/" + strconv.Itoa(v.ID)})
		}
		return r, nil
	case ServiceNowProvider:
		var out struct {
			Result []struct {
				SysID         string `json:"sys_id"`
				CorrelationID string `json:"correlation_id"`
			} `json:"result"`
		}
		q := url.Values{"sysparm_query": {"correlation_id=" + marker}, "sysparm_limit": {strconv.Itoa(limit)}, "sysparm_fields": {"sys_id,correlation_id"}}
		if err := a.request(ctx, http.MethodGet, "/api/now/table/"+a.project, q, nil, &out); err != nil {
			return nil, err
		}
		if len(out.Result) >= limit {
			return nil, ticketErr(http.StatusOK, "search_truncated", false)
		}
		r := make([]ticketing.RemoteTicket, 0, len(out.Result))
		seen := make(map[string]struct{}, len(out.Result))
		for _, v := range out.Result {
			if v.SysID == "" || v.CorrelationID != marker {
				return nil, ticketErr(http.StatusOK, "invalid_search_response", false)
			}
			if _, duplicate := seen[v.SysID]; duplicate {
				return nil, ticketErr(http.StatusOK, "invalid_search_response", false)
			}
			seen[v.SysID] = struct{}{}
			r = append(r, ticketing.RemoteTicket{ID: v.SysID, URL: a.base.Scheme + "://" + a.base.Host + "/now/nav/ui/classic/params/target/" + url.QueryEscape(a.project+".do?sys_id="+v.SysID)})
		}
		return r, nil
	case LinearProvider:
		payload, _ := json.Marshal(map[string]any{"query": "query Search($query: String!, $team: String!) { issueSearch(query: $query, first: 3, filter: { team: { id: { eq: $team } } }) { nodes { id url description team { id } } pageInfo { hasNextPage } } }", "variables": map[string]string{"query": marker, "team": a.project}})
		var out struct {
			Data struct {
				IssueSearch struct {
					Nodes []struct {
						ID, URL, Description string
						Team                 struct {
							ID string `json:"id"`
						} `json:"team"`
					} `json:"nodes"`
					PageInfo struct {
						HasNextPage bool `json:"hasNextPage"`
					} `json:"pageInfo"`
				} `json:"issueSearch"`
			} `json:"data"`
			Errors []json.RawMessage `json:"errors"`
		}
		if err := a.request(ctx, http.MethodPost, "", nil, payload, &out); err != nil {
			return nil, err
		}
		if len(out.Errors) > 0 || out.Data.IssueSearch.PageInfo.HasNextPage || len(out.Data.IssueSearch.Nodes) > 2 {
			return nil, ticketErr(http.StatusOK, "search_truncated", false)
		}
		r := make([]ticketing.RemoteTicket, 0, len(out.Data.IssueSearch.Nodes))
		seen := make(map[string]struct{}, len(out.Data.IssueSearch.Nodes))
		for _, v := range out.Data.IssueSearch.Nodes {
			if v.ID == "" || v.Team.ID != a.project || !strings.HasSuffix(v.Description, "\n\n["+marker+"]") || strings.Count(v.Description, marker) != 1 || !safeHTTPS(v.URL, "linear.app") {
				return nil, ticketErr(http.StatusOK, "invalid_search_response", false)
			}
			if _, duplicate := seen[v.ID]; duplicate {
				return nil, ticketErr(http.StatusOK, "invalid_search_response", false)
			}
			seen[v.ID] = struct{}{}
			r = append(r, ticketing.RemoteTicket{ID: v.ID, URL: v.URL})
		}
		return r, nil
	default:
		return nil, ticketErr(0, "unsupported_provider", false)
	}
}
func wiqlLiteral(value string) string { return strings.ReplaceAll(value, "'", "''") }
func hasAzureTag(tags, marker string) bool {
	for _, tag := range strings.Split(tags, ";") {
		if strings.TrimSpace(tag) == marker {
			return true
		}
	}
	return false
}
func hasString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
func hasLabel(values []struct {
	Name string `json:"name"`
}, want string) bool {
	for _, v := range values {
		if v.Name == want {
			return true
		}
	}
	return false
}
func linearStatus(v string) string {
	if v == "completed" || v == "canceled" {
		return "done"
	}
	if v == "backlog" || v == "unstarted" {
		return "new"
	}
	return "indeterminate"
}
func (a *Adapter) request(ctx context.Context, method, path string, q url.Values, body []byte, out any) error {
	if a.provider == GitHubProvider || a.provider == GitLabProvider {
		credential, ok, err := a.scm.ResolveGitCredential(ctx, a.credentialHost)
		if err != nil || !ok || len(credential.Token) == 0 {
			return ticketErr(0, "connector_missing", false)
		}
		token := append([]byte(nil), credential.Token...)
		defer clear(token)
		base, client, _, err := a.resolveSCMEndpoint(credential)
		if err != nil {
			return err
		}
		return a.requestWithClient(ctx, client, base, token, method, path, q, body, out)
	}
	return a.requestWith(ctx, a.base, a.token, method, path, q, body, out)
}
func (a *Adapter) requestWith(ctx context.Context, base *url.URL, token []byte, method, path string, q url.Values, body []byte, out any) error {
	return a.requestWithClient(ctx, a.client, base, token, method, path, q, body, out)
}
func (a *Adapter) requestWithClient(ctx context.Context, client *http.Client, base *url.URL, token []byte, method, path string, q url.Values, body []byte, out any) error {
	if client == nil || base == nil {
		return ticketErr(0, "invalid_request", false)
	}
	u := *base
	if path != "" {
		if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
			return ticketErr(0, "invalid_request", false)
		}
		joined := strings.TrimSuffix(base.EscapedPath(), "/") + path
		decoded, decodeErr := url.PathUnescape(joined)
		if decodeErr != nil {
			return ticketErr(0, "invalid_request", false)
		}
		u.Path, u.RawPath = decoded, joined
	}
	if q != nil {
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return ticketErr(0, "invalid_request", false)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		contentType := "application/json"
		if a.provider == AzureProvider && strings.Contains(path, "/_apis/wit/workitems/$") {
			contentType = "application/json-patch+json"
		}
		req.Header.Set("Content-Type", contentType)
	}
	if a.provider == GitHubProvider {
		req.Header.Set("Authorization", "Bearer "+string(token))
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	} else if a.provider == GitLabProvider {
		req.Header.Set("PRIVATE-TOKEN", string(token))
	} else if a.provider == AzureProvider {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(append([]byte(":"), token...)))
	} else if a.provider == LinearProvider {
		req.Header.Set("Authorization", string(token))
	} else {
		req.Header.Set("Authorization", "Bearer "+string(token))
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, safehttp.ErrBlockedDestination) {
			return ticketErr(0, "blocked_destination", false)
		}
		return ticketErr(0, "network", method == http.MethodPost || method == http.MethodPatch)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return statusErr(resp.StatusCode, resp.Header)
	}
	if sink, ok := out.(responseHeaderSink); ok {
		sink.setResponseHeaders(resp.Header)
	}
	if out == nil {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil || len(data) > maxResponse {
		return ticketErr(resp.StatusCode, "response_invalid", method == http.MethodPost || method == http.MethodPatch)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return ticketErr(resp.StatusCode, "invalid_response", method == http.MethodPost || method == http.MethodPatch)
	}
	return nil
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	return "443"
}
func ticketErr(status int, code string, amb bool) error {
	return &ports.TicketProviderError{Status: status, Code: code, Ambiguous: amb}
}
func statusErr(s int, h http.Header) error {
	e := &ports.TicketProviderError{Status: s, Code: "request_failed", Ambiguous: s >= 500}
	if s == 401 || s == 403 {
		e.Code = "unauthorized"
	}
	if s == 429 || (s == http.StatusForbidden && h.Get("X-RateLimit-Remaining") == "0") {
		e.Code = "rate_limited"
		if n, _ := strconv.Atoi(h.Get("Retry-After")); n > 0 {
			e.RetryAfter = time.Duration(n) * time.Second
		}
	}
	if s >= 500 {
		e.Code = "server_error"
	}
	return e
}
func safeHTTPS(raw, host string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && !u.ForceQuery && (u.Port() == "" || u.Port() == "443") && strings.EqualFold(u.Hostname(), host) && u.Path != ""
}

func (a *Adapter) ticketURLValid(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || a.browserBase == nil || !strings.EqualFold(u.Host, a.browserBase.Host) {
		return false
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return false
	}
	projectPath := "/" + a.project + "/issues/"
	if a.provider == GitLabProvider {
		projectPath = "/" + a.project + "/-/"
		path := u.EscapedPath()
		switch {
		case strings.HasPrefix(path, projectPath+"issues/"):
			projectPath += "issues/"
		case strings.HasPrefix(path, projectPath+"work_items/"):
			projectPath += "work_items/"
		default:
			return false
		}
	}
	if !strings.HasPrefix(u.EscapedPath(), projectPath) {
		return false
	}
	number := strings.TrimPrefix(u.EscapedPath(), projectPath)
	_, err = strconv.ParseUint(number, 10, 63)
	return err == nil && number != "0" && !strings.HasPrefix(number, "0")
}
