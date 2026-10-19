// Package confluence implements the document publishing port for Confluence Cloud
// and Data Center.  It deliberately keeps the public-sharing check in the provider:
// a page ACL by itself does not disable a Cloud public link.
package confluence

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/integration/selfhostedhttp"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	CloudProvider integration.Provider = "confluence-cloud"
	DCProvider    integration.Provider = "confluence-dc"

	maxResponseBytes   = 4 << 20
	maxStorageBytes    = 1 << 20
	maxAttachmentBytes = 20 << 20
	maxImages          = 16
	maxPageSize        = 100
	maxPages           = 20
)

var (
	cloudDescriptor = integration.ProviderDescriptor{
		Provider: CloudProvider, Name: "Confluence Cloud", Description: "Confluence Cloud governed document publishing.",
		Capabilities: []integration.Capability{integration.CapabilityTestConnection},
		ConfigFields: []integration.FieldDescriptor{
			{Name: "space", Label: "Confluence space key", Kind: integration.FieldText, Required: true},
			{Name: "read_group", Label: "Exact read group", Kind: integration.FieldText, Required: true},
			{Name: "data_class", Label: "Data classification", Kind: integration.FieldText, Required: true},
			{Name: "org_id", Label: "Atlassian organization ID", Kind: integration.FieldText},
			{Name: "site_ari", Label: "Confluence site ARI", Kind: integration.FieldText},
			{Name: "policy_id", Label: "Public-link block policy ID", Kind: integration.FieldText},
		},
		SecretFields: []integration.FieldDescriptor{
			{Name: "email", Label: "Atlassian account email", Kind: integration.FieldText, Required: true},
			{Name: "api_token", Label: "API token", Kind: integration.FieldPassword, Required: true},
			{Name: "org_api_key", Label: "Organization policy read key", Kind: integration.FieldPassword},
		},
	}
	dcDescriptor = integration.ProviderDescriptor{
		Provider: DCProvider, Name: "Confluence Data Center", Description: "Confluence Data Center governed document publishing.", SelfHosted: true,
		Capabilities: []integration.Capability{integration.CapabilityTestConnection},
		ConfigFields: []integration.FieldDescriptor{{Name: "space", Label: "Confluence space key", Kind: integration.FieldText, Required: true}, {Name: "read_group", Label: "Exact read group", Kind: integration.FieldText, Required: true}, {Name: "data_class", Label: "Data classification", Kind: integration.FieldText, Required: true}, {Name: "legacy_xmlrpc_restrictions", Label: "Confluence 10.2 XML-RPC restriction compatibility", Kind: integration.FieldBoolean, Description: "Use only for Confluence Data Center 10.2 when its REST API rejects a safe group-only restriction."}},
		SecretFields: []integration.FieldDescriptor{{Name: "pat", Label: "Personal access token", Kind: integration.FieldPassword, Required: true}},
	}
	markerPattern       = regexp.MustCompile(`^synapse-intent-[a-z0-9][a-z0-9-]{0,127}$`)
	markerSearchPattern = regexp.MustCompile(`synapse-intent-[a-z0-9][a-z0-9-]{0,127}`)
	groupPattern        = regexp.MustCompile(`^[\pL\pN][\pL\pN _.-]{0,127}$`)
	spacePattern        = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)
	cloudIDPattern      = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	policyTypePattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	identityARIPattern  = regexp.MustCompile(`^ari:cloud:identity::[a-z][a-z0-9-]*/[A-Za-z0-9._:-]+$`)
	pageIDPattern       = regexp.MustCompile(`^[0-9]{1,20}$`)
)

// Adapter implements the application-owned document port.  It has no durable
// policy cache: every sensitive write is preceded by a fresh verification call.
type Adapter struct {
	descriptor   integration.ProviderDescriptor
	base         *url.URL
	client       *http.Client
	policy       *http.Client
	cloud        bool
	email        string
	token        string
	orgKey       string
	orgID        string
	siteARI      string
	policyID     string
	space        string
	readGroup    string
	legacyXMLRPC bool
}

var _ integration.ConnectionTester = (*Adapter)(nil)
var _ ports.DocumentProvider = (*Adapter)(nil)

func Register(registry *integration.Registry) error {
	if registry == nil {
		return fmt.Errorf("%w: Confluence integration registry is required", shared.ErrValidation)
	}
	if err := registry.Register(cloudDescriptor, New); err != nil {
		return err
	}
	return registry.Register(dcDescriptor, New)
}

func New(item integration.Integration, credentials integration.CredentialBundle, rules selfhosted.Rules) (integration.Adapter, error) {
	if item.Provider != CloudProvider && item.Provider != DCProvider {
		return nil, fmt.Errorf("%w: wrong Confluence provider", shared.ErrValidation)
	}
	if err := item.Normalize(); err != nil {
		return nil, err
	}
	descriptor := dcDescriptor
	if item.Provider == CloudProvider {
		descriptor = cloudDescriptor
	}
	config := mustConfig(item.Config)
	if err := descriptor.ValidateConfig(config); err != nil {
		return nil, err
	}
	if err := descriptor.ValidateSecrets(map[string]string(credentials)); err != nil {
		return nil, err
	}
	if containsAny(item.Endpoint, credentials) {
		return nil, fmt.Errorf("%w: Confluence endpoint contains credential material", shared.ErrValidation)
	}
	base, err := url.Parse(item.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: Confluence endpoint is invalid", shared.ErrValidation)
	}
	cloud := item.Provider == CloudProvider
	a := &Adapter{descriptor: descriptor, base: base, cloud: cloud, email: credentials["email"], orgKey: credentials["org_api_key"]}
	a.space, _ = config["space"].(string)
	a.readGroup, _ = config["read_group"].(string)
	a.legacyXMLRPC, _ = config["legacy_xmlrpc_restrictions"].(bool)
	dataClass, _ := config["data_class"].(string)
	if !spacePattern.MatchString(a.space) || !groupPattern.MatchString(a.readGroup) || dataClass != "detail" {
		return nil, fmt.Errorf("%w: Confluence destination configuration is invalid", shared.ErrValidation)
	}
	if cloud {
		host := strings.ToLower(strings.TrimSuffix(base.Hostname(), "."))
		if base.Path != "" || (base.Port() != "" && base.Port() != "443") || !strings.HasSuffix(host, ".atlassian.net") || host == "atlassian.net" {
			return nil, fmt.Errorf("%w: Confluence Cloud requires an HTTPS *.atlassian.net origin", shared.ErrValidation)
		}
		base.Host = host
		a.token = credentials["api_token"]
		a.client = safehttp.NewClient(20*time.Second, safehttp.Policy{AllowHost: func(h, p string) bool { return p == "443" && strings.EqualFold(h, host) }})
		a.policy = safehttp.NewClient(20*time.Second, safehttp.Policy{AllowHost: func(h, p string) bool { return p == "443" && h == "api.atlassian.com" }})
		a.orgID, _ = config["org_id"].(string)
		a.siteARI, _ = config["site_ari"].(string)
		a.policyID, _ = config["policy_id"].(string)
		if !safeIdentifier(a.orgID, 255) || !safeIdentifier(a.siteARI, 1024) || !safeIdentifier(a.policyID, 255) {
			// Both are optional as a pair, but a partial proof is never usable.
			if a.orgID != "" || a.siteARI != "" || a.policyID != "" || a.orgKey != "" {
				return nil, fmt.Errorf("%w: Cloud public-sharing proof configuration is incomplete", shared.ErrValidation)
			}
		}
	} else {
		if rules.Hosts.Empty() {
			return nil, fmt.Errorf("%w: Confluence Data Center needs an explicit operator host allowlist", shared.ErrValidation)
		}
		if err := rules.CheckListedEndpoint(item.Endpoint, item.AllowPrivateNetwork); err != nil {
			return nil, err
		}
		a.token = credentials["pat"]
		a.client = selfhostedhttp.NewClient(20*time.Second, rules, item.AllowPrivateNetwork)
	}
	return a, nil
}

func mustConfig(raw json.RawMessage) map[string]any {
	v, err := integration.DecodeConfig(raw)
	if err != nil {
		return map[string]any{}
	}
	return v
}

func (a *Adapter) Descriptor() integration.ProviderDescriptor { return a.descriptor }
func (a *Adapter) Close() {
	a.client.CloseIdleConnections()
	if a.policy != nil {
		a.policy.CloseIdleConnections()
	}
}

func (a *Adapter) TestConnection(ctx context.Context) error {
	var current struct {
		Type      string `json:"type"`
		Username  string `json:"username"`
		AccountID string `json:"accountId"`
	}
	if err := a.request(ctx, a.client, http.MethodGet, a.apiPath("/user/current"), nil, nil, &current, false, http.StatusOK); err != nil {
		return err
	}
	identity := current.Username
	if a.cloud {
		identity = current.AccountID
	}
	if !safeIdentifier(identity, 255) || a.containsCredential(identity) {
		return providerError(200, "invalid_identity", false)
	}
	var space struct {
		Key string `json:"key"`
	}
	if err := a.requestJSON(ctx, http.MethodGet, "/space/"+url.PathEscape(a.space), nil, nil, &space, false, http.StatusOK); err != nil {
		return err
	}
	if space.Key != a.space || a.containsCredential(space.Key) {
		return providerError(200, "invalid_space", false)
	}
	if a.legacyXMLRPC {
		return a.legacyXMLRPCPreflight(ctx, identity)
	}
	return nil
}

func (a *Adapter) CreateDocumentShell(ctx context.Context, container, marker string) (docpublish.RemotePage, error) {
	if container != a.space || !markerPattern.MatchString(marker) {
		return docpublish.RemotePage{}, providerError(0, "invalid_shell", false)
	}
	// The shell has only a neutral title and a recovery marker. Content does not arrive until
	// RestrictDocument and VerifyDocumentRestriction have succeeded.
	body := map[string]any{"type": "page", "title": neutralShellTitle(marker), "space": map[string]string{"key": container}, "body": map[string]any{"storage": map[string]string{"value": neutralShellStorage(marker), "representation": "storage"}}}
	var out contentResponse
	if err := a.requestJSON(ctx, http.MethodPost, "/content", nil, body, &out, true, http.StatusOK, http.StatusCreated); err != nil {
		return docpublish.RemotePage{}, err
	}
	state, err := a.contentState(out, marker)
	if err != nil {
		var classified *ports.DocumentProviderError
		if errors.As(err, &classified) {
			copy := *classified
			copy.Ambiguous = true
			return docpublish.RemotePage{}, &copy
		}
		return docpublish.RemotePage{}, providerError(200, "invalid_write_response", true)
	}
	if state.Container != container || state.Marker != marker {
		return docpublish.RemotePage{}, providerError(200, "invalid_shell_response", true)
	}
	return state.RemotePage, nil
}

func (a *Adapter) RestrictDocument(ctx context.Context, page, group string) error {
	if !pageIDPattern.MatchString(page) || group != a.readGroup || a.containsCredential(group) {
		return providerError(0, "invalid_restriction", false)
	}
	// A confirmed existing exact restriction is a completed write. This keeps a
	// retry idempotent when an operator has already repaired the provider ACL.
	// Any incomplete proof follows the normal narrowing path and is verified by
	// the caller before content can be uploaded.
	if err := a.VerifyDocumentRestriction(ctx, page, a.space, group); err == nil {
		return nil
	}
	if a.cloud {
		// Cloud's V1 restriction endpoint cannot safely replace a direct grant
		// when the publisher is a member of the target group: it rejects the
		// self-eviction even though the group preserves effective access. The
		// documented V2 replacement endpoint represents that single effective
		// grant directly. Keep the provider default self-lockout protection; a
		// caller that would lose access receives a fail-closed error instead.
		permissions := map[string]any{"permissions": []map[string]any{{
			"operation":  "update",
			"principals": []map[string]string{{"principalType": "group", "principalId": group}},
		}}}
		if err := a.requestCloudV2JSON(ctx, http.MethodPut, "/pages/"+page+"/permissions", nil, permissions, nil, true, http.StatusOK); err != nil {
			return err
		}
		return a.requestCloudV2JSON(ctx, http.MethodPut, "/pages/"+page+"/restriction-state", nil, map[string]string{"state": "VIEW_RESTRICTED"}, nil, true, http.StatusOK)
	}
	if a.legacyXMLRPC {
		return a.setLegacyXMLRPCPermissions(ctx, page, group)
	}
	groupField := "name"
	restrictions := map[string]any{"group": []map[string]string{{"type": "group", groupField: group}}}
	// Data Center's documented update endpoint replaces only the supplied
	// operation. An explicit empty user list removes direct read grants while
	// omitting update preserves its separate restriction state.
	restrictions["user"] = []map[string]string{}
	body := []map[string]any{{"operation": "read", "restrictions": restrictions}}
	return a.requestJSON(ctx, http.MethodPut, "/content/"+page+"/restriction", nil, body, nil, true, http.StatusOK)
}

func (a *Adapter) VerifyDocumentRestriction(ctx context.Context, page, container, group string) error {
	if !pageIDPattern.MatchString(page) || container != a.space || group != a.readGroup {
		return providerError(0, "invalid_restriction", false)
	}
	if a.legacyXMLRPC {
		if err := a.legacyXMLRPCPreflight(ctx, ""); err != nil {
			return err
		}
	}
	state, err := a.GetDocument(ctx, page)
	if err != nil {
		return err
	}
	if state.Container != container {
		return providerError(200, "wrong_container", false)
	}
	if a.cloud {
		if err := a.verifyCloudV2Restriction(ctx, page, group); err != nil {
			return err
		}
	}
	for _, operation := range []string{"read", "update"} {
		var restrictions restrictionResponse
		if err := a.requestJSON(ctx, http.MethodGet, "/content/"+page+"/restriction/byOperation/"+operation, url.Values{"expand": {"restrictions.user,restrictions.group"}, "start": {"0"}, "limit": {"100"}}, nil, &restrictions, false, http.StatusOK); err != nil {
			return err
		}
		if !restrictions.exactGroup(operation, group, a.cloud) {
			return providerError(200, "restriction_unverified", false)
		}
	}
	if a.cloud {
		return a.verifyCloudPublicSharing(ctx)
	}
	return nil
}

func (a *Adapter) verifyCloudV2Restriction(ctx context.Context, page, group string) error {
	var state cloudRestrictionState
	if err := a.requestCloudV2JSON(ctx, http.MethodGet, "/pages/"+page+"/restriction-state", nil, nil, &state, false, http.StatusOK); err != nil {
		return err
	}
	if state.State != "VIEW_RESTRICTED" {
		return providerError(http.StatusOK, "restriction_unverified", false)
	}
	var permissions cloudPermissionsResponse
	if err := a.requestCloudV2JSON(ctx, http.MethodGet, "/pages/"+page+"/permissions", url.Values{"limit": {strconv.Itoa(maxPageSize)}}, nil, &permissions, false, http.StatusOK); err != nil {
		return err
	}
	if !permissions.exactGroup(group) {
		return providerError(http.StatusOK, "restriction_unverified", false)
	}
	return nil
}

func (a *Adapter) GetDocument(ctx context.Context, page string) (ports.DocumentRemoteState, error) {
	if !pageIDPattern.MatchString(page) {
		return ports.DocumentRemoteState{}, providerError(0, "invalid_page", false)
	}
	var out contentResponse
	if err := a.requestJSON(ctx, http.MethodGet, "/content/"+page, url.Values{"expand": {"space,version,body.storage"}}, nil, &out, false, http.StatusOK); err != nil {
		return ports.DocumentRemoteState{}, err
	}
	return a.contentState(out, "")
}

func (a *Adapter) FindDocumentMarker(ctx context.Context, container, marker string) ([]ports.DocumentRemoteState, error) {
	if container != a.space || !markerPattern.MatchString(marker) {
		return nil, providerError(0, "invalid_marker", false)
	}
	var out searchResponse
	query := url.Values{"cql": {"space = \"" + container + "\" AND text ~ \"" + marker + "\""}, "limit": {"2"}, "expand": {"space,version,body.storage"}}
	if err := a.requestJSON(ctx, http.MethodGet, "/content/search", query, nil, &out, false, http.StatusOK); err != nil {
		return nil, err
	}
	if len(out.Results) > 2 {
		return nil, providerError(200, "marker_search_truncated", false)
	}
	states := make([]ports.DocumentRemoteState, 0, len(out.Results))
	for _, item := range out.Results {
		state, err := a.contentState(item, marker)
		if err != nil {
			return nil, err
		}
		if state.Container == container && state.Marker == marker {
			states = append(states, state)
		}
	}
	return states, nil
}

func (a *Adapter) UploadDocumentAttachment(ctx context.Context, page string, image ports.DocumentImage) error {
	if !pageIDPattern.MatchString(page) || !validAttachment(image) || a.containsCredential(image.Name) {
		return providerError(0, "invalid_attachment", false)
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", image.Name)
	if err != nil {
		return providerError(0, "invalid_attachment", false)
	}
	if _, err := part.Write(image.Data); err != nil {
		return providerError(0, "invalid_attachment", false)
	}
	if err := writer.Close(); err != nil {
		return providerError(0, "invalid_attachment", false)
	}
	headers := http.Header{"Content-Type": {writer.FormDataContentType()}, "X-Atlassian-Token": {"nocheck"}}
	return a.requestWithHeaders(ctx, a.client, http.MethodPost, a.apiPath("/content/"+page+"/child/attachment"), nil, body.Bytes(), nil, headers, true, http.StatusOK, http.StatusCreated)
}

func (a *Adapter) WriteDocument(ctx context.Context, page string, expectedVersion int, title, storage, marker string) (docpublish.RemotePage, error) {
	if !pageIDPattern.MatchString(page) || expectedVersion < 1 || !validTitle(title) || !markerPattern.MatchString(marker) || !validStorage(storage) {
		return docpublish.RemotePage{}, providerError(0, "invalid_document", false)
	}
	if err := a.ValidateDocumentText(title); err != nil {
		return docpublish.RemotePage{}, err
	}
	if err := a.ValidateDocumentText(storage); err != nil {
		return docpublish.RemotePage{}, err
	}
	body := map[string]any{"id": page, "type": "page", "title": title, "version": map[string]int{"number": expectedVersion + 1}, "body": map[string]any{"storage": map[string]string{"value": storage, "representation": "storage"}}}
	var out contentResponse
	if err := a.requestJSON(ctx, http.MethodPut, "/content/"+page, nil, body, &out, true, http.StatusOK); err != nil {
		return docpublish.RemotePage{}, err
	}
	state, err := a.contentState(out, marker)
	if err != nil {
		var classified *ports.DocumentProviderError
		if errors.As(err, &classified) {
			copy := *classified
			copy.Ambiguous = true
			return docpublish.RemotePage{}, &copy
		}
		return docpublish.RemotePage{}, providerError(200, "invalid_write_response", true)
	}
	if state.ID != page || state.Version != expectedVersion+1 || state.Marker != marker {
		return docpublish.RemotePage{}, providerError(200, "version_conflict", true)
	}
	return state.RemotePage, nil
}

func (a *Adapter) PurgeDocument(ctx context.Context, page string, guard func(context.Context) error) error {
	if !pageIDPattern.MatchString(page) || guard == nil {
		return providerError(0, "invalid_page", false)
	}
	// Purge each whole attachment, including its history, before purging the page.
	// Once a delete is dispatched, a later failure requires reconciliation.
	attachments, err := a.listAttachments(ctx, page)
	if err != nil {
		return err
	}
	partial := false
	deleteOne := func(resource string, query url.Values) error {
		if err := guard(ctx); err != nil {
			return partialPurgeError(err, partial)
		}
		partial = true
		if err := a.request(ctx, a.client, http.MethodDelete, resource, query, nil, nil, true, http.StatusNoContent); err != nil {
			return partialPurgeError(err, true)
		}
		return nil
	}
	purge := func(id, kind string) error {
		resource := a.apiPath("/content/" + id)
		trash, permanent := url.Values{"status": {"current"}}, url.Values{"status": {"trashed"}}
		if a.cloud {
			resource = "/wiki/api/v2/" + kind + "/" + id
			trash, permanent = nil, url.Values{"purge": {"true"}}
		}
		if err := deleteOne(resource, trash); err != nil {
			return err
		}
		return deleteOne(resource, permanent)
	}
	for _, attachment := range attachments {
		if err := purge(attachment, "attachments"); err != nil {
			return err
		}
	}
	return purge(page, "pages")
}

func (a *Adapter) ValidateDocumentText(text string) error {
	if len(text) > maxStorageBytes || !utf8.ValidString(text) || strings.ContainsRune(text, 0) || a.containsCredential(text) {
		return providerError(0, "credential_in_document", false)
	}
	return nil
}

func (a *Adapter) listAttachments(ctx context.Context, page string) ([]string, error) {
	seen := map[string]struct{}{}
	for start := 0; start < maxPages*maxPageSize; start += maxPageSize {
		var out attachmentResponse
		query := url.Values{"start": {strconv.Itoa(start)}, "limit": {strconv.Itoa(maxPageSize)}, "expand": {"version"}}
		if err := a.requestJSON(ctx, http.MethodGet, "/content/"+page+"/child/attachment", query, nil, &out, false, http.StatusOK); err != nil {
			return nil, err
		}
		if out.Results == nil || out.Size == nil || out.Start == nil || *out.Start != start || *out.Size != len(out.Results) || len(out.Results) > maxPageSize || (len(out.Results) < maxPageSize && out.Links.Next != "") {
			return nil, providerError(200, "attachment_list_truncated", false)
		}
		for _, item := range out.Results {
			id := item.ID
			if a.cloud && strings.HasPrefix(id, "att") {
				id = strings.TrimPrefix(id, "att")
			}
			if !pageIDPattern.MatchString(id) || a.containsCredential(item.ID) || a.containsCredential(id) {
				return nil, providerError(200, "invalid_attachment_response", false)
			}
			seen[id] = struct{}{}
		}
		if len(out.Results) < maxPageSize {
			break
		}
		if start+maxPageSize >= maxPages*maxPageSize {
			return nil, providerError(200, "attachment_list_truncated", false)
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

func partialPurgeError(err error, partial bool) error {
	if !partial {
		return err
	}
	var provider *ports.DocumentProviderError
	if errors.As(err, &provider) {
		copy := *provider
		copy.Ambiguous = true
		return &copy
	}
	return providerError(0, "purge_partial", true)
}

func (a *Adapter) verifyCloudPublicSharing(ctx context.Context) error {
	refuse := func() error { return providerError(0, "public_sharing_unverifiable", false) }
	if a.orgKey == "" || a.orgID == "" || a.siteARI == "" || a.policyID == "" {
		return refuse()
	}
	// Bind the administrator's policy resource to this actual site. A protected
	// resource in another site cannot authorize uploading to the configured origin.
	var tenant struct {
		CloudID string `json:"cloudId"`
	}
	if err := a.request(ctx, a.client, http.MethodGet, "/_edge/tenant_info", nil, nil, &tenant, false, http.StatusOK); err != nil {
		return providerErrorFrom(err, "public_sharing_unverifiable")
	}
	if !cloudIDPattern.MatchString(tenant.CloudID) || a.siteARI != "ari:cloud:confluence::site/"+tenant.CloudID {
		return refuse()
	}
	policies, err := a.cloudPolicies(ctx)
	if err != nil {
		return providerErrorFrom(err, "public_sharing_unverifiable")
	}
	if len(policies) == 0 || len(policies) > 64 {
		return refuse()
	}
	seen := map[string]bool{}
	orgDefault := false
	targetFound := false
	for _, listed := range policies {
		if !safeIdentifier(listed.ID, 255) || seen[listed.ID] || !policyTypePattern.MatchString(listed.Attributes.Type) {
			return refuse()
		}
		seen[listed.ID] = true
		// The policy collection is heterogeneous in practice, even when its
		// request is filtered. Only data-security policies govern public links;
		// their unrelated rule encodings must not make this proof undecodable.
		if listed.Attributes.Type != "data-security" {
			continue
		}
		if listed.Attributes.Status == "draft" {
			continue
		}
		if listed.Attributes.Status != "published" {
			return refuse()
		}
		// The list may be stale or omit details. Read every published policy, so an
		// override hidden from a summary cannot be mistaken for proof of protection.
		full, err := a.cloudPolicy(ctx, listed.ID)
		if err != nil {
			return providerErrorFrom(err, "public_sharing_unverifiable")
		}
		attrs := full.Attributes
		old := listed.Attributes
		listedLinks, err := listed.publicLinks()
		if err != nil {
			return refuse()
		}
		fullLinks, err := full.publicLinks()
		if err != nil {
			return refuse()
		}
		if full.ID != listed.ID || attrs.Type != old.Type || attrs.Status != old.Status || attrs.Metadata.PolicyCoverageLevel != old.Metadata.PolicyCoverageLevel || fullLinks.present != listedLinks.present || fullLinks.Effect != listedLinks.Effect {
			return refuse()
		}
		if !fullLinks.present {
			continue
		}
		effect := fullLinks.Effect
		if effect != "allow" && effect != "block" {
			return refuse()
		}
		switch attrs.Metadata.PolicyCoverageLevel {
		case "ORG":
			if orgDefault {
				return refuse()
			}
			orgDefault = true
		case "WORKSPACE":
			if listed.ID != a.policyID || targetFound || effect != "block" {
				return refuse()
			}
			resources, err := a.cloudPolicyResources(ctx, listed.ID)
			if err != nil {
				return providerErrorFrom(err, "public_sharing_unverifiable")
			}
			exact := 0
			for _, r := range resources {
				if r.Type != "resource" || !safeIdentifier(r.resourceARI(), 1024) || r.applicationStatus() != "applied" {
					return refuse()
				}
				if r.resourceARI() == a.siteARI {
					exact++
				}
			}
			if exact != 1 {
				return refuse()
			}
			targetFound = true
		default:
			return refuse()
		}
	}
	if !orgDefault || !targetFound {
		return refuse()
	}
	return nil
}

func (a *Adapter) cloudPolicy(ctx context.Context, id string) (policy, error) {
	var out struct {
		Data policy `json:"data"`
	}
	if err := a.policyRequest(ctx, "/admin/control/v2/orgs/"+url.PathEscape(a.orgID)+"/policies/"+url.PathEscape(id), nil, &out); err != nil {
		return policy{}, err
	}
	if !safeIdentifier(out.Data.ID, 255) {
		return policy{}, errors.New("invalid policy response")
	}
	return out.Data, nil
}

func (a *Adapter) cloudPolicies(ctx context.Context) ([]policy, error) {
	var all []policy
	cursor := ""
	for n := 0; n < maxPages; n++ {
		query := url.Values{"type": {"data-security"}}
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		var out policyPage
		if err := a.policyRequest(ctx, "/admin/control/v2/orgs/"+url.PathEscape(a.orgID)+"/policies", query, &out); err != nil {
			return nil, err
		}
		if out.Meta == nil || out.Data == nil || (out.Meta.Next == "" && out.Links.Next != "") || len(out.Data) > maxPageSize {
			return nil, errors.New("policy page too large")
		}
		all = append(all, out.Data...)
		next := out.Meta.Next
		if next == "" {
			return all, nil
		}
		if next == cursor || len(next) > 4096 || strings.ContainsAny(next, "\r\n") {
			return nil, errors.New("invalid policy cursor")
		}
		cursor = next
	}
	return nil, errors.New("policy pagination incomplete")
}

func (a *Adapter) cloudPolicyResources(ctx context.Context, id string) ([]policyResource, error) {
	if !safeIdentifier(id, 255) {
		return nil, errors.New("invalid policy id")
	}
	var all []policyResource
	cursor := ""
	for n := 0; n < maxPages; n++ {
		query := url.Values{}
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		var out policyResourcePage
		if err := a.policyRequest(ctx, "/admin/control/v2/orgs/"+url.PathEscape(a.orgID)+"/policies/"+url.PathEscape(id)+"/resources", query, &out); err != nil {
			return nil, err
		}
		if out.Meta == nil || out.Data == nil || (out.Meta.Next == "" && out.Links.Next != "") || len(out.Data) > maxPageSize {
			return nil, errors.New("resource page too large")
		}
		all = append(all, out.Data...)
		next := out.Meta.Next
		if next == "" {
			return all, nil
		}
		if next == cursor || len(next) > 4096 || strings.ContainsAny(next, "\r\n") {
			return nil, errors.New("invalid resource cursor")
		}
		cursor = next
	}
	return nil, errors.New("resource pagination incomplete")
}

func (a *Adapter) policyRequest(ctx context.Context, resource string, query url.Values, out any) error {
	u := &url.URL{Scheme: "https", Host: "api.atlassian.com", Path: resource, RawQuery: query.Encode()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return errors.New("invalid policy request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.orgKey)
	res, err := a.policy.Do(req)
	if err != nil {
		return errors.New("policy unavailable")
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return errors.New("policy unavailable")
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil || len(b) > maxResponseBytes || json.Unmarshal(b, out) != nil {
		return errors.New("invalid policy response")
	}
	return nil
}

func (a *Adapter) requestJSON(ctx context.Context, method, resource string, query url.Values, value, out any, write bool, wanted ...int) error {
	return a.requestJSONPath(ctx, method, a.apiPath(resource), query, value, out, write, wanted...)
}

func (a *Adapter) requestCloudV2JSON(ctx context.Context, method, resource string, query url.Values, value, out any, write bool, wanted ...int) error {
	if !a.cloud {
		return providerError(0, "invalid_request", false)
	}
	return a.requestJSONPath(ctx, method, "/wiki/api/v2"+resource, query, value, out, write, wanted...)
}

func (a *Adapter) requestJSONPath(ctx context.Context, method, resource string, query url.Values, value, out any, write bool, wanted ...int) error {
	var data []byte
	if value != nil {
		var err error
		data, err = json.Marshal(value)
		if err != nil {
			return providerError(0, "invalid_request", false)
		}
	}
	return a.request(ctx, a.client, method, resource, query, data, out, write, wanted...)
}

func (a *Adapter) request(ctx context.Context, client *http.Client, method, resource string, query url.Values, body []byte, out any, write bool, wanted ...int) error {
	return a.requestWithHeaders(ctx, client, method, resource, query, body, out, nil, write, wanted...)
}

func (a *Adapter) requestWithHeaders(ctx context.Context, client *http.Client, method, resource string, query url.Values, body []byte, out any, headers http.Header, write bool, wanted ...int) error {
	u := *a.base
	u.Path = resource
	u.RawPath = ""
	u.RawQuery = query.Encode()
	u.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return providerError(0, "invalid_request", false)
	}
	req.Header.Set("Accept", "application/json")
	for key, values := range headers {
		req.Header.Del(key)
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.cloud {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(a.email+":"+a.token)))
	} else {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	res, err := client.Do(req)
	if err != nil {
		if errors.Is(err, safehttp.ErrBlockedDestination) {
			return providerError(0, "blocked_destination", false)
		}
		if ctx.Err() != nil && !write {
			return ctx.Err()
		}
		return providerError(0, "network", write)
	}
	defer func() { _ = res.Body.Close() }()
	ok := false
	for _, status := range wanted {
		if res.StatusCode == status {
			ok = true
			break
		}
	}
	if !ok {
		return statusProviderError(res.StatusCode, write)
	}
	if out == nil {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil || len(b) > maxResponseBytes {
		return providerError(res.StatusCode, "invalid_response", write)
	}
	if raw, ok := out.(*responseBytes); ok {
		*raw = append((*raw)[:0], b...)
		return nil
	}
	if json.Unmarshal(b, out) != nil {
		return providerError(res.StatusCode, "invalid_response", write)
	}
	return nil
}

func (a *Adapter) apiPath(resource string) string {
	prefix := "/rest/api"
	if a.cloud {
		prefix = "/wiki/rest/api"
	}
	return strings.TrimSuffix(a.base.Path, "/") + prefix + resource
}

func (a *Adapter) contentState(out contentResponse, marker string) (ports.DocumentRemoteState, error) {
	if !pageIDPattern.MatchString(out.ID) || out.Version.Number < 1 || !safeIdentifier(out.Space.Key, 255) || a.containsCredential(out.ID) || a.containsCredential(out.Space.Key) {
		return ports.DocumentRemoteState{}, providerError(200, "invalid_content_response", false)
	}
	foundMarker := markerFromStorage(out.Body.Storage.Value)
	if marker == "" {
		marker = foundMarker
	}
	if marker != "" && (!markerPattern.MatchString(marker) || foundMarker != marker) {
		return ports.DocumentRemoteState{}, providerError(200, "invalid_content_response", false)
	}
	if out.Status != "current" || !validTitle(out.Title) || len(out.Body.Storage.Value) > maxStorageBytes || !utf8.ValidString(out.Body.Storage.Value) || strings.ContainsRune(out.Body.Storage.Value, 0) || a.containsCredential(out.Title) || a.containsCredential(out.Body.Storage.Value) {
		return ports.DocumentRemoteState{}, providerError(200, "invalid_content_response", false)
	}
	pageURL, err := a.pageURL(out.Space.Key, out.ID)
	if err != nil {
		return ports.DocumentRemoteState{}, providerError(200, "invalid_content_response", false)
	}
	return ports.DocumentRemoteState{RemotePage: docpublish.RemotePage{ID: out.ID, Version: out.Version.Number, URL: pageURL}, Container: out.Space.Key, Marker: marker, Title: out.Title, Storage: out.Body.Storage.Value, Neutral: out.Title == neutralShellTitle(marker) && out.Body.Storage.Value == neutralShellStorage(marker)}, nil
}

func (a *Adapter) pageURL(container, id string) (string, error) {
	u := *a.base
	prefix := strings.TrimSuffix(a.base.Path, "/")
	if a.cloud {
		prefix = "/wiki"
	}
	u.Path = prefix + "/spaces/" + container + "/pages/" + id
	u.RawQuery = ""
	u.Fragment = ""
	u.RawPath = ""
	return docpublish.CanonicalURL(u.String())
}

func (a *Adapter) containsCredential(text string) bool {
	return redact.String(text, a.secrets()) != text
}
func (a *Adapter) secrets() []string { return []string{a.email, a.token, a.orgKey} }

func validTitle(v string) bool { return safeIdentifier(v, 255) && !strings.ContainsAny(v, "\r\n") }
func safeIdentifier(v string, limit int) bool {
	return v != "" && len(v) <= limit && utf8.ValidString(v) && !strings.ContainsRune(v, 0) && strings.TrimSpace(v) == v
}
func validAttachment(image ports.DocumentImage) bool {
	return safeIdentifier(image.Name, 255) && path.Base(image.Name) == image.Name && len(image.Data) > 0 && len(image.Data) <= maxAttachmentBytes && ((image.MediaType == "application/pdf") || (strings.HasPrefix(image.MediaType, "image/") && (image.MediaType == "image/png" || image.MediaType == "image/jpeg")))
}
func containsAny(text string, values integration.CredentialBundle) bool {
	for _, v := range values {
		if v != "" && strings.Contains(text, v) {
			return true
		}
	}
	return false
}

func markerFromStorage(storage string) string {
	markers := markerSearchPattern.FindAllString(storage, -1)
	if len(markers) != 1 {
		return ""
	}
	return markers[0]
}
func neutralShellTitle(marker string) string { return "Synapse publication in progress " + marker }

func neutralShellStorage(marker string) string {
	return "<p>Publication is being prepared.</p><p>" + marker + "</p>"
}

var allowedStorageElements = map[string]map[string]bool{
	"div": {"class": true}, "p": {"class": true}, "h1": {}, "h2": {}, "h3": {}, "h4": {}, "table": {"class": true}, "tbody": {}, "tr": {}, "th": {"colspan": true, "rowspan": true}, "td": {"colspan": true, "rowspan": true}, "ul": {}, "ol": {}, "li": {}, "strong": {}, "em": {}, "code": {}, "pre": {}, "br": {}, "span": {"class": true}, "a": {"href": true, "title": true},
	"ac:structured-macro": {"ac:name": true}, "ac:parameter": {"ac:name": true}, "ac:rich-text-body": {}, "ac:plain-text-body": {}, "ac:image": {}, "ri:attachment": {"ri:filename": true},
	"ac:link": {}, "ac:plain-text-link-body": {},
}

func validStorage(storage string) bool {
	if len(storage) == 0 || len(storage) > maxStorageBytes || !utf8.ValidString(storage) || strings.ContainsRune(storage, 0) || strings.Contains(strings.ToUpper(storage), "<!DOCTYPE") || strings.Contains(storage, "<?") {
		return false
	}
	d := xml.NewDecoder(strings.NewReader(storage))
	depth := 0
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			return depth == 0
		}
		if err != nil {
			return false
		}
		switch x := tok.(type) {
		case xml.StartElement:
			depth++
			if depth > 64 {
				return false
			}
			name := xmlName(x.Name)
			allowed, ok := allowedStorageElements[name]
			if !ok {
				return false
			}
			for _, attr := range x.Attr {
				an := xmlName(attr.Name)
				if strings.HasPrefix(an, "xmlns") {
					continue
				}
				if !allowed[an] || len(attr.Value) > 2048 || strings.ContainsRune(attr.Value, 0) {
					return false
				}
				if an == "href" && !safeHref(attr.Value) {
					return false
				}
			}
		case xml.EndElement:
			depth--
			if depth < 0 {
				return false
			}
		case xml.CharData:
			if len(x) > 16<<10 {
				return false
			}
		}
	}
}
func xmlName(n xml.Name) string {
	if n.Space == "" {
		return n.Local
	}
	return n.Space + ":" + n.Local
}
func safeHref(v string) bool {
	u, err := url.Parse(v)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}

func providerError(status int, code string, ambiguous bool) error {
	return &ports.DocumentProviderError{Status: status, Code: code, Ambiguous: ambiguous}
}
func providerErrorFrom(err error, fallback string) error {
	var p *ports.DocumentProviderError
	if errors.As(err, &p) {
		return p
	}
	return providerError(0, fallback, false)
}
func statusProviderError(status int, write bool) error {
	code := "request_failed"
	if status == 401 || status == 403 {
		code = "unauthorized"
	}
	if status == 404 || status == 400 || status == 409 {
		code = "request_rejected"
	}
	if status == 429 {
		code = "rate_limited"
	}
	if status >= 500 {
		code = "server_error"
	}
	return providerError(status, code, write && status >= 500)
}

type contentResponse struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Space  struct {
		Key string `json:"key"`
	} `json:"space"`
	Version struct {
		Number int `json:"number"`
	} `json:"version"`
	Body struct {
		Storage struct {
			Value string `json:"value"`
		} `json:"storage"`
	} `json:"body"`
	Links struct {
		WebUI string `json:"webui"`
	} `json:"_links"`
}
type searchResponse struct {
	Results []contentResponse `json:"results"`
}
type attachmentResponse struct {
	Results []struct {
		ID string `json:"id"`
	} `json:"results"`
	Size  *int `json:"size"`
	Start *int `json:"start"`
	Links struct {
		Next string `json:"next"`
	} `json:"_links"`
}
type restrictionResponse struct {
	Operation    string `json:"operation"`
	Restrictions struct {
		Group struct {
			Results []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"results"`
			Size  *int `json:"size"`
			Start int  `json:"start"`
			Total *int `json:"totalSize"`
			Links struct {
				Next string `json:"next"`
			} `json:"_links"`
		} `json:"group"`
		User struct {
			Results []json.RawMessage `json:"results"`
			Size    *int              `json:"size"`
			Start   int               `json:"start"`
			Total   *int              `json:"totalSize"`
			Links   struct {
				Next string `json:"next"`
			} `json:"_links"`
		} `json:"user"`
	} `json:"restrictions"`
}

type responseBytes []byte

type cloudRestrictionState struct {
	State string `json:"state"`
}

type cloudPermissionsResponse struct {
	Results *[]struct {
		Operation string `json:"operation"`
		Principal struct {
			Type string `json:"principalType"`
			ID   string `json:"principalId"`
		} `json:"principal"`
	} `json:"results"`
	Links *struct {
		Next string `json:"next"`
	} `json:"_links"`
}

func (r cloudPermissionsResponse) exactGroup(want string) bool {
	if r.Results == nil || r.Links == nil || r.Links.Next != "" || len(*r.Results) != 1 {
		return false
	}
	permission := (*r.Results)[0]
	return (permission.Operation == "read" || permission.Operation == "update") && permission.Principal.Type == "group" && permission.Principal.ID == want
}

func (r restrictionResponse) exactGroup(operation, want string, cloud bool) bool {
	g, u := r.Restrictions.Group, r.Restrictions.User
	if r.Operation != operation || g.Size == nil || u.Size == nil || g.Start != 0 || u.Start != 0 || g.Links.Next != "" || u.Links.Next != "" {
		return false
	}
	if *u.Size != 0 || u.Results == nil || len(u.Results) != 0 || (u.Total != nil && *u.Total != 0) {
		return false
	}
	if *g.Size == 0 && g.Results != nil && len(g.Results) == 0 && (g.Total == nil || *g.Total == 0) {
		return operation == "update"
	}
	if *g.Size != 1 || len(g.Results) != 1 || (g.Total != nil && *g.Total != 1) {
		return false
	}
	if cloud {
		return g.Results[0].ID == want
	}
	return g.Results[0].Name == want
}

type publicLinksRule struct {
	Effect  string `json:"effect"`
	present bool
}

type policy struct {
	ID         string `json:"id"`
	Attributes struct {
		Type     string          `json:"type"`
		Status   string          `json:"status"`
		Rule     json.RawMessage `json:"rule"`
		Metadata struct {
			PolicyCoverageLevel string `json:"policyCoverageLevel"`
		} `json:"metadata"`
	} `json:"attributes"`
}

func (p policy) publicLinks() (publicLinksRule, error) {
	var out publicLinksRule
	if p.Attributes.Type != "data-security" || len(p.Attributes.Rule) == 0 {
		return out, nil
	}
	rules, err := strictPolicyObject(p.Attributes.Rule, "publicLinks", "export", "anonymousAccess", "appAccess", "attachmentDownload", "mcpAccess")
	if err != nil {
		return publicLinksRule{}, err
	}
	for name, raw := range rules {
		effect, err := policyControlEffect(raw)
		if err != nil {
			return publicLinksRule{}, err
		}
		if name == "publicLinks" {
			out.Effect = effect
			out.present = true
		}
	}
	return out, nil
}

// policyControlEffect accepts known data-security controls and the audit fields
// observed in vendor responses. Every supplied field has an explicit type;
// unknown extensions and conditions cannot establish an unconditional block.
func policyControlEffect(raw json.RawMessage) (string, error) {
	control, err := strictPolicyObject(raw, "effect", "addedAt", "lastUpdatedAt", "addedBy", "lastUpdatedBy")
	if err != nil {
		return "", err
	}
	effect, ok := control["effect"]
	if !ok {
		return "", errors.New("policy control effect is required")
	}
	var value string
	if json.Unmarshal(effect, &value) != nil || (value != "allow" && value != "block") {
		return "", errors.New("invalid policy control effect")
	}
	for _, name := range []string{"addedAt", "lastUpdatedAt"} {
		raw, ok := control[name]
		if !ok {
			continue
		}
		var timestamp string
		if json.Unmarshal(raw, &timestamp) != nil || timestamp == "" {
			return "", errors.New("invalid policy audit timestamp")
		}
		if _, err := time.Parse(time.RFC3339Nano, timestamp); err != nil {
			return "", errors.New("invalid policy audit timestamp")
		}
	}
	for _, name := range []string{"addedBy", "lastUpdatedBy"} {
		raw, ok := control[name]
		if !ok {
			continue
		}
		var identity string
		if json.Unmarshal(raw, &identity) != nil || !identityARIPattern.MatchString(identity) {
			return "", errors.New("invalid policy audit identity")
		}
	}
	return value, nil
}

// strictPolicyObject rejects an ambiguous policy rule rather than silently
// accepting fields whose access semantics the provider cannot prove. Policy
// responses are untrusted admin-plane input; duplicate keys are just as
// ambiguous as unknown conditions because different consumers can retain a
// different occurrence.
func strictPolicyObject(raw json.RawMessage, allowed ...string) (map[string]json.RawMessage, error) {
	accept := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		accept[name] = struct{}{}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := start.(json.Delim)
	if !ok || delim != '{' {
		return nil, errors.New("policy rule must be an object")
	}
	values := make(map[string]json.RawMessage, len(allowed))
	for decoder.More() {
		name, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := name.(string)
		if !ok {
			return nil, errors.New("policy rule key must be a string")
		}
		if _, ok := accept[key]; !ok {
			return nil, errors.New("unknown policy rule field")
		}
		if _, exists := values[key]; exists {
			return nil, errors.New("duplicate policy rule field")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		values[key] = value
	}
	end, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := end.(json.Delim); !ok || delim != '}' {
		return nil, errors.New("invalid policy rule object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing policy rule data")
	}
	return values, nil
}

type policyPagination struct {
	Next string `json:"next"`
}
type policyLinks struct {
	Next string `json:"next"`
}
type policyPage struct {
	Data  []policy          `json:"data"`
	Meta  *policyPagination `json:"meta"`
	Links policyLinks       `json:"links"`
}
type policyResource struct {
	Type       string `json:"type"`
	Attributes struct {
		ResourceID        string `json:"resourceId"`
		ApplicationStatus string `json:"applicationStatus"`
	} `json:"attributes"`
}

func (r policyResource) resourceARI() string       { return r.Attributes.ResourceID }
func (r policyResource) applicationStatus() string { return r.Attributes.ApplicationStatus }

type policyResourcePage struct {
	Data  []policyResource  `json:"data"`
	Meta  *policyPagination `json:"meta"`
	Links policyLinks       `json:"links"`
}
