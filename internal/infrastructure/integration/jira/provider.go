// Package jira implements the narrow Jira ticket-provider port for Cloud and Data Center.
package jira

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
	CloudProvider         integration.Provider = "jira-cloud"
	DCProvider            integration.Provider = "jira-dc"
	maxResponseBytes                           = 4 << 20
	maxTicketPayloadBytes                      = 64 << 10
	maxPages                                   = 20
	pageSize                                   = 50
)

var (
	cloudDescriptor  = integration.ProviderDescriptor{Provider: CloudProvider, Name: "Jira Cloud", Description: "Jira Cloud ticket creation and metadata.", Capabilities: []integration.Capability{integration.CapabilityTestConnection}, SecretFields: []integration.FieldDescriptor{{Name: "email", Label: "Atlassian account email", Kind: integration.FieldText, Required: true}, {Name: "api_token", Label: "API token", Kind: integration.FieldPassword, Required: true}}}
	dcDescriptor     = integration.ProviderDescriptor{Provider: DCProvider, Name: "Jira Data Center", Description: "Jira Data Center ticket creation and metadata.", SelfHosted: true, Capabilities: []integration.Capability{integration.CapabilityTestConnection}, SecretFields: []integration.FieldDescriptor{{Name: "pat", Label: "Personal access token", Kind: integration.FieldPassword, Required: true}}}
	projectPattern   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
	issueTypePattern = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
	markerPattern    = regexp.MustCompile(`^synapse-intent-[a-z0-9][a-z0-9-]{0,127}$`)
	issueKeyPattern  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}-[1-9][0-9]*$`)
)

type Adapter struct {
	descriptor integration.ProviderDescriptor
	base       *url.URL
	client     *http.Client
	email      string
	token      string
	cloud      bool
}

var _ integration.ConnectionTester = (*Adapter)(nil)
var _ ports.TicketProvider = (*Adapter)(nil)

// Register adds both Jira variants. They deliberately share the ticket-provider port while
// retaining distinct credentials and egress policies.
func Register(registry *integration.Registry) error {
	if registry == nil {
		return fmt.Errorf("%w: Jira integration registry is required", shared.ErrValidation)
	}
	if err := registry.Register(cloudDescriptor, New); err != nil {
		return err
	}
	return registry.Register(dcDescriptor, New)
}

func New(item integration.Integration, credentials integration.CredentialBundle, rules selfhosted.Rules) (integration.Adapter, error) {
	provider := item.Provider
	if provider != CloudProvider && provider != DCProvider {
		return nil, fmt.Errorf("%w: wrong Jira provider", shared.ErrValidation)
	}
	if err := validateRawEndpoint(item.Endpoint, provider == CloudProvider); err != nil {
		return nil, err
	}
	if err := item.Normalize(); err != nil {
		return nil, err
	}
	d := dcDescriptor
	if provider == CloudProvider {
		d = cloudDescriptor
	}
	if err := d.ValidateSecrets(map[string]string(credentials)); err != nil {
		return nil, err
	}
	if containsSecret(item.Endpoint, credentials) {
		return nil, fmt.Errorf("%w: Jira endpoint contains credential material", shared.ErrValidation)
	}
	base, err := url.Parse(item.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: Jira endpoint is invalid", shared.ErrValidation)
	}
	cloud := provider == CloudProvider
	var client *http.Client
	if cloud {
		host := strings.ToLower(strings.TrimSuffix(base.Hostname(), "."))
		if base.Path != "" || (base.Port() != "" && base.Port() != "443") || !strings.HasSuffix(host, ".atlassian.net") || host == "atlassian.net" {
			return nil, fmt.Errorf("%w: Jira Cloud requires an HTTPS *.atlassian.net origin", shared.ErrValidation)
		}
		base.Host = host
		client = safehttp.NewClient(20*time.Second, safehttp.Policy{AllowHost: func(h, p string) bool { return p == "443" && strings.EqualFold(h, host) }})
	} else {
		if rules.Hosts.Empty() {
			return nil, fmt.Errorf("%w: Jira Data Center needs an explicit operator host allowlist", shared.ErrValidation)
		}
		if err := rules.CheckListedEndpoint(item.Endpoint, item.AllowPrivateNetwork); err != nil {
			return nil, err
		}
		client = selfhostedhttp.NewClient(20*time.Second, rules, item.AllowPrivateNetwork)
	}
	return &Adapter{descriptor: d, base: base, client: client, email: credentials["email"], token: credentialToken(provider, credentials), cloud: cloud}, nil
}

func credentialToken(provider integration.Provider, credentials integration.CredentialBundle) string {
	if provider == CloudProvider {
		return credentials["api_token"]
	}
	return credentials["pat"]
}

func (a *Adapter) Descriptor() integration.ProviderDescriptor { return a.descriptor }
func (a *Adapter) Close()                                     { a.client.CloseIdleConnections() }

func (a *Adapter) TestConnection(ctx context.Context) error {
	_, err := a.authenticatedIdentity(ctx)
	return err
}

func (a *Adapter) authenticatedIdentity(ctx context.Context) (string, error) {
	var out struct {
		AccountID string `json:"accountId"`
		Name      string `json:"name"`
	}
	_, err := a.request(ctx, http.MethodGet, "/myself", nil, nil, &out, http.StatusOK)
	if err != nil {
		return "", err
	}
	identity := out.Name
	if a.cloud {
		identity = out.AccountID
	}
	identity = strings.TrimSpace(identity)
	if identity == "" || len(identity) > 255 {
		return "", ticketError(http.StatusOK, "invalid_identity", 0, false)
	}
	if a.containsCredential(identity) {
		return "", ticketError(http.StatusOK, "unsafe_provider_response", 0, false)
	}
	return identity, nil
}

func (a *Adapter) FormatTicketDescription(body string, links []ports.RenderedLink) (json.RawMessage, error) {
	if err := a.validateDescriptionLiterals(body, links, nil, nil); err != nil {
		return nil, err
	}
	if a.cloud {
		doc, err := messageformat.JiraADF(body, links)
		if err != nil {
			return nil, err
		}
		out, err := json.Marshal(doc)
		return out, err
	}
	wiki, err := messageformat.JiraWiki(body, links)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(wiki)
	return out, err
}

func (a *Adapter) CreateTicket(ctx context.Context, payload json.RawMessage) (ticketing.RemoteTicket, error) {
	if err := a.ValidateTicketPayload(payload); err != nil {
		return ticketing.RemoteTicket{}, err
	}
	var created struct {
		Key string `json:"key"`
	}
	_, err := a.request(ctx, http.MethodPost, "/issue", nil, payload, &created, http.StatusCreated)
	if err != nil {
		return ticketing.RemoteTicket{}, err
	}
	if !issueKeyPattern.MatchString(created.Key) || a.containsCredential(created.Key) {
		return ticketing.RemoteTicket{}, ticketError(http.StatusCreated, "malformed_create_response", 0, true)
	}
	return ticketing.RemoteTicket{ID: created.Key, URL: a.browseURL(created.Key)}, nil
}

// ValidateTicketPayload rejects credential material before a preview is persisted or Jira receives
// a write. Decoder tokens retain every object key, including duplicates, and unescape JSON strings
// before checking them. The error is intentionally classified without echoing the offending value.
func (a *Adapter) ValidateTicketPayload(payload json.RawMessage) error {
	if len(payload) == 0 || len(payload) > maxTicketPayloadBytes || !json.Valid(payload) {
		return ticketError(0, "invalid_payload", 0, false)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return ticketError(0, "invalid_payload", 0, false)
		}
		if text, ok := token.(string); ok && a.containsCredential(text) {
			return ticketError(0, "credential_in_payload", 0, false)
		}
	}
}

func (a *Adapter) DiscoverTickets(ctx context.Context, project, issueType, issue string) (ports.TicketMetadata, error) {
	if project != "" && !projectPattern.MatchString(project) {
		return ports.TicketMetadata{}, ticketError(0, "invalid_project", 0, false)
	}
	if issueType != "" && len(issueType) > 255 {
		return ports.TicketMetadata{}, ticketError(0, "invalid_issue_type", 0, false)
	}
	metadata := ports.TicketMetadata{}
	projects, err := a.projects(ctx)
	if err != nil {
		return metadata, err
	}
	if err := a.safeChoices(projects); err != nil {
		return metadata, err
	}
	metadata.Projects = projects
	if project == "" {
		return metadata, nil
	}
	types, fields, err := a.createMetadata(ctx, project, issueType)
	if err != nil {
		return metadata, err
	}
	if err := a.safeChoices(types); err != nil {
		return metadata, err
	}
	if err := a.safeFields(fields); err != nil {
		return metadata, err
	}
	metadata.IssueTypes, metadata.Fields = types, fields
	if !a.cloud && requiresResolvedReporter(fields) {
		reporter, err := a.authenticatedIdentity(ctx)
		if err != nil {
			return metadata, err
		}
		metadata.ResolvedReporter = reporter
	}
	for _, f := range fields {
		switch f.ID {
		case "security":
			metadata.SecurityLevels = append(metadata.SecurityLevels, f.Values...)
		case "priority":
			metadata.Priorities = append(metadata.Priorities, f.Values...)
		case "components":
			metadata.Components = append(metadata.Components, f.Values...)
		}
	}
	if issue != "" {
		if !issueKeyPattern.MatchString(issue) {
			return metadata, ticketError(0, "invalid_issue", 0, false)
		}
		var transitions struct {
			Transitions []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"transitions"`
		}
		if _, err := a.request(ctx, http.MethodGet, "/issue/"+url.PathEscape(issue)+"/transitions", nil, nil, &transitions, http.StatusOK); err != nil {
			return metadata, err
		}
		metadata.Transitions = choicesFrom(transitions.Transitions)
		if err := a.safeChoices(metadata.Transitions); err != nil {
			return metadata, err
		}
	}
	return metadata, nil
}

func requiresResolvedReporter(fields []ports.TicketField) bool {
	for _, field := range fields {
		if field.ID == "reporter" && field.Required && !field.HasDefault && field.Type == "user" {
			return true
		}
	}
	return false
}

func (a *Adapter) SearchTicketMarker(ctx context.Context, project, issueType, marker string) ([]ticketing.RemoteTicket, error) {
	if !projectPattern.MatchString(project) || !issueTypePattern.MatchString(issueType) || !markerPattern.MatchString(marker) {
		return nil, ticketError(0, "invalid_marker_search", 0, false)
	}
	path := "/search"
	if a.cloud {
		path = "/search/jql"
	}
	query := url.Values{"jql": {`project = "` + project + `" AND issuetype = "` + issueType + `" AND labels = "` + marker + `"`}, "maxResults": {"2"}, "fields": {"key"}}
	var result struct {
		Issues []struct {
			Key string `json:"key"`
		} `json:"issues"`
		Total         *int   `json:"total"`
		StartAt       *int   `json:"startAt"`
		MaxResults    *int   `json:"maxResults"`
		IsLast        bool   `json:"isLast"`
		NextPageToken string `json:"nextPageToken"`
	}
	if _, err := a.request(ctx, http.MethodGet, path, query, nil, &result, http.StatusOK); err != nil {
		return nil, err
	}
	if len(result.Issues) > 2 || (result.Total != nil && *result.Total > 2) || (a.cloud && (!result.IsLast || result.NextPageToken != "")) {
		return nil, ticketError(http.StatusOK, "search_truncated", 0, false)
	}
	if !a.cloud && (result.Total == nil || result.StartAt == nil || result.MaxResults == nil ||
		*result.Total < 0 || *result.Total != len(result.Issues) || *result.StartAt != 0 ||
		*result.MaxResults < 1 || *result.MaxResults < len(result.Issues)) {
		return nil, ticketError(http.StatusOK, "search_truncated", 0, false)
	}
	matched := make([]ticketing.RemoteTicket, 0, len(result.Issues))
	for _, candidate := range result.Issues {
		if !issueKeyPattern.MatchString(candidate.Key) || a.containsCredential(candidate.Key) {
			return nil, ticketError(http.StatusOK, "invalid_search_response", 0, false)
		}
		var verified struct {
			Fields struct {
				Labels  []string `json:"labels"`
				Project struct {
					Key string `json:"key"`
				} `json:"project"`
				IssueType struct {
					ID string `json:"id"`
				} `json:"issuetype"`
			} `json:"fields"`
		}
		if _, err := a.request(ctx, http.MethodGet, "/issue/"+url.PathEscape(candidate.Key), url.Values{"fields": {"project,labels,issuetype"}}, nil, &verified, http.StatusOK); err != nil {
			return nil, err
		}
		if verified.Fields.Project.Key != project || verified.Fields.IssueType.ID != issueType || !contains(verified.Fields.Labels, marker) {
			return nil, ticketError(http.StatusOK, "invalid_search_response", 0, false)
		}
		matched = append(matched, ticketing.RemoteTicket{ID: candidate.Key, URL: a.browseURL(candidate.Key)})
	}
	return matched, nil
}

func (a *Adapter) projects(ctx context.Context) ([]ports.TicketChoice, error) {
	if !a.cloud {
		var out []project
		_, err := a.request(ctx, http.MethodGet, "/project", nil, nil, &out, http.StatusOK)
		if len(out) > maxPages*pageSize {
			return nil, ticketError(http.StatusOK, "metadata_truncated", 0, false)
		}
		return projectChoices(out), err
	}
	var all []ports.TicketChoice
	for start := 0; start < maxPages*pageSize; start += pageSize {
		var page struct {
			Values []project `json:"values"`
			IsLast bool      `json:"isLast"`
			Total  int       `json:"total"`
		}
		_, err := a.request(ctx, http.MethodGet, "/project/search", url.Values{"startAt": {strconv.Itoa(start)}, "maxResults": {strconv.Itoa(pageSize)}}, nil, &page, http.StatusOK)
		if err != nil {
			return nil, err
		}
		if len(page.Values) > pageSize || page.Total > maxPages*pageSize {
			return nil, ticketError(http.StatusOK, "metadata_truncated", 0, false)
		}
		all = append(all, projectChoices(page.Values)...)
		if page.IsLast {
			return all, nil
		}
		if len(page.Values) == 0 {
			return nil, ticketError(http.StatusOK, "metadata_truncated", 0, false)
		}
	}
	return nil, ticketError(http.StatusOK, "metadata_truncated", 0, false)
}

func (a *Adapter) createMetadata(ctx context.Context, project, wantedType string) ([]ports.TicketChoice, []ports.TicketField, error) {
	// Cloud's old all-in-one createmeta response is deprecated. Both Cloud and current
	// Data Center expose the bounded, paged resources, so always prefer them. Older DC
	// releases alone may use the legacy expand response as a compatibility fallback.
	types, fields, err := a.pagedCreateMetadata(ctx, project, wantedType)
	if err == nil || a.cloud {
		return types, fields, err
	}
	var providerErr *ports.TicketProviderError
	if !errors.As(err, &providerErr) || providerErr.Status != http.StatusNotFound {
		return nil, nil, err
	}
	return a.legacyCreateMetadata(ctx, project, wantedType)
}

func (a *Adapter) legacyCreateMetadata(ctx context.Context, project, wantedType string) ([]ports.TicketChoice, []ports.TicketField, error) {
	var out struct {
		Projects []struct {
			IssueTypes []issueType `json:"issuetypes"`
		} `json:"projects"`
	}
	if _, err := a.request(ctx, http.MethodGet, "/issue/createmeta", url.Values{"projectKeys": {project}, "expand": {"projects.issuetypes.fields"}}, nil, &out, http.StatusOK); err != nil {
		return nil, nil, err
	}
	if len(out.Projects) != 1 || len(out.Projects[0].IssueTypes) > maxPages*pageSize {
		return nil, nil, ticketError(http.StatusOK, "invalid_metadata", 0, false)
	}
	return issueChoices(out.Projects[0].IssueTypes), fieldsFor(out.Projects[0].IssueTypes, wantedType), nil
}

// Jira Cloud calls the issue-type array issueTypes while Data Center and older
// Cloud responses call it values. The details resource is likewise paged and
// uses an array of fields; accepting the legacy field map remains necessary for
// old Data Center only.
func (a *Adapter) pagedCreateMetadata(ctx context.Context, project, wantedType string) ([]ports.TicketChoice, []ports.TicketField, error) {
	types, err := a.pagedIssueTypes(ctx, project)
	if err != nil {
		return nil, nil, err
	}
	fields := []ports.TicketField{}
	if wantedType != "" {
		fields, err = a.pagedFields(ctx, project, wantedType)
		if err != nil {
			return nil, nil, err
		}
	}
	return issueChoices(types), fields, nil
}

func (a *Adapter) pagedIssueTypes(ctx context.Context, project string) ([]issueType, error) {
	all := make([]issueType, 0)
	for pageNumber, start := 0, 0; pageNumber < maxPages; pageNumber++ {
		var page struct {
			Values     []issueType `json:"values"`
			IssueTypes []issueType `json:"issueTypes"`
			IsLast     bool        `json:"isLast"`
			Total      *int        `json:"total"`
		}
		_, err := a.request(ctx, http.MethodGet, "/issue/createmeta/"+url.PathEscape(project)+"/issuetypes", url.Values{"startAt": {strconv.Itoa(start)}, "maxResults": {strconv.Itoa(pageSize)}}, nil, &page, http.StatusOK)
		if err != nil {
			return nil, err
		}
		values := page.IssueTypes
		if values == nil {
			values = page.Values
		}
		if err := validateMetadataPage(start, len(values), page.Total, page.IsLast); err != nil {
			return nil, err
		}
		all = append(all, values...)
		if pageDone(start, len(values), page.Total, page.IsLast) {
			return all, nil
		}
		start += len(values)
	}
	return nil, ticketError(http.StatusOK, "metadata_truncated", 0, false)
}

func (a *Adapter) pagedFields(ctx context.Context, project, issueType string) ([]ports.TicketField, error) {
	all := make([]ports.TicketField, 0)
	for pageNumber, start := 0, 0; pageNumber < maxPages; pageNumber++ {
		var page fieldPage
		_, err := a.request(ctx, http.MethodGet, "/issue/createmeta/"+url.PathEscape(project)+"/issuetypes/"+url.PathEscape(issueType), url.Values{"startAt": {strconv.Itoa(start)}, "maxResults": {strconv.Itoa(pageSize)}}, nil, &page, http.StatusOK)
		if err != nil {
			return nil, err
		}
		values, legacy, err := page.items()
		if err != nil {
			return nil, ticketError(http.StatusOK, "invalid_metadata", 0, false)
		}
		if legacy != nil {
			// The old expanded response is a map keyed by field ID and is not
			// paginated. DC installations may still return it for this resource.
			if a.cloud {
				return nil, ticketError(http.StatusOK, "invalid_metadata", 0, false)
			}
			return mapFields(legacy), nil
		}
		if err := validateMetadataPage(start, len(values), page.Total, page.IsLast); err != nil {
			return nil, err
		}
		all = append(all, mapModernFields(values)...)
		if pageDone(start, len(values), page.Total, page.IsLast) {
			return all, nil
		}
		start += len(values)
	}
	return nil, ticketError(http.StatusOK, "metadata_truncated", 0, false)
}

type fieldPage struct {
	Fields json.RawMessage    `json:"fields"`
	Values []modernIssueField `json:"values"`
	IsLast bool               `json:"isLast"`
	Total  *int               `json:"total"`
}

func (p fieldPage) items() ([]modernIssueField, map[string]issueField, error) {
	if len(p.Fields) == 0 || string(p.Fields) == "null" {
		return p.Values, nil, nil
	}
	var fields []modernIssueField
	if err := json.Unmarshal(p.Fields, &fields); err == nil {
		return fields, nil, nil
	}
	var legacy map[string]issueField
	if err := json.Unmarshal(p.Fields, &legacy); err != nil || legacy == nil {
		return nil, nil, fmt.Errorf("invalid Jira field page")
	}
	return nil, legacy, nil
}

func validateMetadataPage(start, count int, total *int, isLast bool) error {
	if count > pageSize || (total != nil && (*total > maxPages*pageSize || *total < 0)) || (count == 0 && !pageDone(start, count, total, isLast)) {
		return ticketError(http.StatusOK, "metadata_truncated", 0, false)
	}
	if total != nil && start+count > *total {
		return ticketError(http.StatusOK, "invalid_metadata", 0, false)
	}
	return nil
}

func pageDone(start, count int, total *int, isLast bool) bool {
	return isLast || (total != nil && *total > 0 && start+count >= *total)
}

type project struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Name string `json:"name"`
}
type issueType struct {
	ID     string                `json:"id"`
	Name   string                `json:"name"`
	Fields map[string]issueField `json:"fields"`
}
type issueField struct {
	Name       string `json:"name"`
	Required   bool   `json:"required"`
	HasDefault bool   `json:"hasDefaultValue"`
	Schema     struct {
		Type  string `json:"type"`
		Items string `json:"items"`
	} `json:"schema"`
	AllowedValues []struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"allowedValues"`
}

type modernIssueField struct {
	FieldID    string `json:"fieldId"`
	Key        string `json:"key"`
	ID         string `json:"id"`
	Name       string `json:"name"`
	Required   bool   `json:"required"`
	HasDefault bool   `json:"hasDefaultValue"`
	Schema     struct {
		Type  string `json:"type"`
		Items string `json:"items"`
	} `json:"schema"`
	AllowedValues []struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"allowedValues"`
}

func fieldsFor(types []issueType, wanted string) []ports.TicketField {
	for _, t := range types {
		if wanted == "" || t.ID == wanted || t.Name == wanted {
			return mapFields(t.Fields)
		}
	}
	return nil
}
func mapFields(fields map[string]issueField) []ports.TicketField {
	out := make([]ports.TicketField, 0, len(fields))
	for id, f := range fields {
		values := make([]ports.TicketChoice, 0, len(f.AllowedValues))
		for _, v := range f.AllowedValues {
			name := v.Name
			if name == "" {
				name = v.Value
			}
			if v.ID != "" && name != "" {
				values = append(values, ports.TicketChoice{ID: v.ID, Name: name})
			}
		}
		out = append(out, ports.TicketField{ID: id, Name: f.Name, Required: f.Required, Values: values, Type: f.Schema.Type, ItemType: f.Schema.Items, HasDefault: f.HasDefault})
	}
	return out
}

func mapModernFields(fields []modernIssueField) []ports.TicketField {
	out := make([]ports.TicketField, 0, len(fields))
	for _, f := range fields {
		id := f.FieldID
		if id == "" {
			id = f.Key
		}
		if id == "" {
			id = f.ID
		}
		values := make([]ports.TicketChoice, 0, len(f.AllowedValues))
		for _, value := range f.AllowedValues {
			name := value.Name
			if name == "" {
				name = value.Value
			}
			if value.ID != "" && name != "" {
				values = append(values, ports.TicketChoice{ID: value.ID, Name: name})
			}
		}
		out = append(out, ports.TicketField{ID: id, Name: f.Name, Required: f.Required, Values: values, Type: f.Schema.Type, ItemType: f.Schema.Items, HasDefault: f.HasDefault})
	}
	return out
}
func issueChoices(types []issueType) []ports.TicketChoice {
	out := make([]ports.TicketChoice, 0, len(types))
	for _, t := range types {
		if t.ID != "" && t.Name != "" {
			out = append(out, ports.TicketChoice{ID: t.ID, Name: t.Name})
		}
	}
	return out
}
func choicesFrom(values []struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}) []ports.TicketChoice {
	out := make([]ports.TicketChoice, 0, len(values))
	for _, v := range values {
		if v.ID != "" && v.Name != "" {
			out = append(out, ports.TicketChoice{ID: v.ID, Name: v.Name})
		}
	}
	return out
}
func projectChoices(values []project) []ports.TicketChoice {
	out := make([]ports.TicketChoice, 0, len(values))
	for _, v := range values {
		id := v.Key
		if id == "" {
			id = v.ID
		}
		if id != "" && v.Name != "" {
			out = append(out, ports.TicketChoice{ID: id, Name: v.Name})
		}
	}
	return out
}

func (a *Adapter) safeChoices(choices []ports.TicketChoice) error {
	if len(choices) > maxPages*pageSize {
		return ticketError(http.StatusOK, "metadata_truncated", 0, false)
	}
	for _, choice := range choices {
		if choice.ID == "" || choice.Name == "" || a.containsCredential(choice.ID) || a.containsCredential(choice.Name) {
			return ticketError(http.StatusOK, "unsafe_provider_response", 0, false)
		}
	}
	return nil
}

func (a *Adapter) safeFields(fields []ports.TicketField) error {
	if len(fields) > maxPages*pageSize {
		return ticketError(http.StatusOK, "metadata_truncated", 0, false)
	}
	values := 0
	for _, field := range fields {
		if field.ID == "" || field.Name == "" || a.containsCredential(field.ID) || a.containsCredential(field.Name) || a.containsCredential(field.Type) || a.containsCredential(field.ItemType) {
			return ticketError(http.StatusOK, "unsafe_provider_response", 0, false)
		}
		values += len(field.Values)
		if values > maxPages*pageSize {
			return ticketError(http.StatusOK, "metadata_truncated", 0, false)
		}
		if err := a.safeChoices(field.Values); err != nil {
			return err
		}
	}
	return nil
}

func (a *Adapter) request(ctx context.Context, method, resource string, query url.Values, body []byte, out any, want int) (http.Header, error) {
	u, err := a.resourceURL(resource, query)
	if err != nil {
		return nil, ticketError(0, "invalid_request", 0, false)
	}
	request, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, ticketError(0, "invalid_request", 0, false)
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if a.cloud {
		request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(a.email+":"+a.token)))
	} else {
		request.Header.Set("Authorization", "Bearer "+a.token)
	}
	response, err := a.client.Do(request)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			if method == http.MethodPost {
				return nil, ticketError(0, "network", 0, true)
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			// A transport timeout can happen independently of the caller's context.
			return nil, ticketError(0, "network", 0, true)
		}
		if errors.Is(err, safehttp.ErrBlockedDestination) {
			return nil, ticketError(0, "blocked_destination", 0, false)
		}
		return nil, ticketError(0, "network", 0, true)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != want {
		return response.Header, statusError(response.StatusCode, response.Header)
	}
	if out == nil {
		return response.Header, nil
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, ticketError(response.StatusCode, "response_read", 0, method == http.MethodPost)
	}
	if len(data) > maxResponseBytes {
		return nil, ticketError(response.StatusCode, "response_too_large", 0, method == http.MethodPost)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return nil, ticketError(response.StatusCode, "invalid_response", 0, method == http.MethodPost)
	}
	return response.Header, nil
}

func (a *Adapter) resourceURL(resource string, query url.Values) (*url.URL, error) {
	if !strings.HasPrefix(resource, "/") || strings.Contains(resource, "..") {
		return nil, errors.New("invalid path")
	}
	u := *a.base
	prefix := "/rest/api/2"
	if a.cloud {
		prefix = "/rest/api/3"
	}
	u.Path = strings.TrimSuffix(a.base.Path, "/") + prefix + resource
	u.RawPath = ""
	u.RawQuery = query.Encode()
	u.Fragment = ""
	return &u, nil
}
func (a *Adapter) browseURL(key string) string {
	u := *a.base
	u.Path = strings.TrimSuffix(a.base.Path, "/") + "/browse/" + key
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
func ticketError(status int, code string, retry time.Duration, ambiguous bool) error {
	return &ports.TicketProviderError{Status: status, Code: code, RetryAfter: retry, Ambiguous: ambiguous}
}
func statusError(status int, headers http.Header) error {
	retry := time.Duration(0)
	if status == http.StatusTooManyRequests {
		retry = parseRetryAfter(headers.Get("Retry-After"))
	}
	ambiguous := status >= 500
	code := "request_failed"
	switch status {
	case 401, 403:
		code = "unauthorized"
	case 400, 404:
		code = "request_rejected"
	case 429:
		code = "rate_limited"
	default:
		if status >= 500 {
			code = "server_error"
		}
	}
	return ticketError(status, code, retry, ambiguous)
}

const (
	defaultRetryAfter = time.Minute
	maxRetryAfter     = time.Duration(1<<63 - 1)
)

func parseRetryAfter(v string) time.Duration {
	return parseRetryAfterAt(v, time.Now())
}

func parseRetryAfterAt(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return defaultRetryAfter
	}
	if seconds, err := strconv.ParseUint(v, 10, 64); err == nil {
		if seconds > uint64(maxRetryAfter/time.Second) {
			return maxRetryAfter
		}
		return time.Duration(seconds) * time.Second
	}
	when, err := http.ParseTime(v)
	if err != nil {
		return defaultRetryAfter
	}
	if !when.After(now) {
		return 0
	}
	if when.After(now.Add(maxRetryAfter)) {
		return maxRetryAfter
	}
	return when.Sub(now)
}
func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
func containsSecret(endpoint string, credentials integration.CredentialBundle) bool {
	for _, v := range credentials {
		if v != "" && (strings.Contains(endpoint, v) || redact.String(endpoint, []string{v}) != endpoint) {
			return true
		}
	}
	return false
}

func (a *Adapter) containsCredential(value string) bool {
	basic := base64.StdEncoding.EncodeToString([]byte(a.email + ":" + a.token))
	secrets := []string{a.token, a.email}
	if a.email != "" && a.token != "" {
		secrets = append(secrets, a.email+":"+a.token)
	}
	for tries := 0; tries < 4; tries++ {
		if (a.token != "" && strings.Contains(value, a.token)) || (a.email != "" && strings.Contains(value, a.email)) || (a.email != "" && a.token != "" && strings.Contains(value, basic)) || redact.String(value, secrets) != value {
			return true
		}
		decoded, err := url.QueryUnescape(value)
		if err != nil || decoded == value {
			break
		}
		value = decoded
	}
	return false
}
func validateRawEndpoint(raw string, cloud bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("%w: Jira endpoint is invalid", shared.ErrValidation)
	}
	for _, s := range strings.Split(u.EscapedPath(), "/") {
		d, e := url.PathUnescape(s)
		if e != nil || d == "." || d == ".." || strings.ContainsAny(d, "\\\x00") {
			return fmt.Errorf("%w: Jira endpoint path is invalid", shared.ErrValidation)
		}
	}
	if cloud && strings.Trim(u.Path, "/") != "" {
		return fmt.Errorf("%w: Jira Cloud endpoint must be an origin", shared.ErrValidation)
	}
	if len(u.Path) > 256 {
		return fmt.Errorf("%w: Jira endpoint path is too long", shared.ErrValidation)
	}
	return nil
}
