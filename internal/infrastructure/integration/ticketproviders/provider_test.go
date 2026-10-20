package ticketproviders

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scmconnector"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestTicketPayloadRejectsHexEncodedCurrentCredentials(t *testing.T) {
	for _, scm := range []bool{false, true} {
		for _, upper := range []bool{false, true} {
			name := strconv.FormatBool(scm) + "/uppercase=" + strconv.FormatBool(upper)
			t.Run(name, func(t *testing.T) {
				secret := []byte("synthetic-current-ticket-token")
				a := &Adapter{provider: LinearProvider, token: secret}
				if scm {
					a = &Adapter{provider: GitLabProvider, scm: gitLabTestSCMStore{token: secret}, credentialHost: "gitlab.example"}
					if err := a.BindTicketCredentials(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				encoded := hex.EncodeToString(secret)
				if upper {
					encoded = strings.ToUpper(encoded)
				}
				payload, err := json.Marshal(map[string]string{"description": "literal " + encoded})
				if err != nil {
					t.Fatal(err)
				}
				var providerErr *ports.TicketProviderError
				if err = a.ValidateTicketPayload(payload); !errors.As(err, &providerErr) || providerErr.Code != "payload_contains_credential" {
					t.Fatalf("recoverable credential accepted: %v", err)
				}
			})
		}
	}
}

func TestBuildTicketPayloadFreezesProviderSpecificMarkerLocation(t *testing.T) {
	for provider, want := range map[integration.Provider]ports.TicketMarkerStrategy{
		GitHubProvider: ports.TicketMarkerJSONArray, GitLabProvider: ports.TicketMarkerTag,
		AzureProvider: ports.TicketMarkerJSONPatchAdd, ServiceNowProvider: ports.TicketMarkerScalar,
		LinearProvider: ports.TicketMarkerTextSuffix,
	} {
		t.Run(string(provider), func(t *testing.T) {
			a := &Adapter{provider: provider, project: "team"}
			payload, err := a.BuildTicketPayload(context.Background(), ports.TicketPayloadInput{Summary: "finding", Description: json.RawMessage(`"literal <text>"`)})
			if err != nil {
				t.Fatal(err)
			}
			if payload.Marker.Version != 1 || payload.Marker.Strategy != want || len(payload.Marker.Path) == 0 || !json.Valid(payload.Wire) {
				t.Fatalf("unsafe marker payload: %#v %s", payload.Marker, payload.Wire)
			}
		})
	}
}

type rotatingSCMStore struct {
	mu       sync.Mutex
	token    []byte
	apiBase  string
	provider scmconnector.Provider
}

func (s *rotatingSCMStore) List(context.Context) ([]ports.SCMConnectorMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return []ports.SCMConnectorMeta{{Host: "github.com", Provider: s.provider}}, nil
}
func (s *rotatingSCMStore) ResolveGitCredential(context.Context, string) (ports.GitCredential, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ports.GitCredential{Token: append([]byte(nil), s.token...), APIBase: s.apiBase}, len(s.token) > 0, nil
}
func (s *rotatingSCMStore) Put(context.Context, scmconnector.Connector, []byte) error {
	return shared.ErrValidation
}
func (s *rotatingSCMStore) Get(context.Context, shared.ID) (ports.SCMConnectorMeta, error) {
	return ports.SCMConnectorMeta{}, shared.ErrNotFound
}
func (s *rotatingSCMStore) Delete(context.Context, shared.ID) error { return shared.ErrNotFound }
func (s *rotatingSCMStore) rotate(token []byte, provider scmconnector.Provider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = append([]byte(nil), token...)
	s.provider = provider
}

func TestRequestClassifiesRateLimitAndNeverReturnsResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("token-must-not-escape"))
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	a := &Adapter{provider: LinearProvider, base: base, client: server.Client(), token: []byte("token-must-not-escape")}
	err := a.request(context.Background(), http.MethodPost, "", nil, []byte(`{}`), &map[string]any{})
	var classified *ports.TicketProviderError
	if !errors.As(err, &classified) || classified.Code != "rate_limited" || classified.RetryAfter.Seconds() != 7 || classified.Ambiguous {
		t.Fatalf("error = %#v", err)
	}
	if err.Error() == "token-must-not-escape" {
		t.Fatal("provider response body leaked")
	}
}

func TestCreateLinearTreatsGraphQLErrorsAsFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"errors":[{"message":"denied"}]}`))
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	a := &Adapter{provider: LinearProvider, base: base, client: server.Client(), token: []byte("secret"), project: "team"}
	_, err := a.createLinear(context.Background(), json.RawMessage(`{"query":"x"}`))
	var classified *ports.TicketProviderError
	if !errors.As(err, &classified) || classified.Code != "malformed_create_response" {
		t.Fatalf("error = %#v", err)
	}
}

func TestServiceNowIdentityRequiresExactlyOneCurrentUserID(t *testing.T) {
	const userID = "0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"current user", `{"result":[{"sys_id":"` + userID + `"}]}`, userID},
		{"no visible user", `{"result":[]}`, ""},
		{"missing result", `{}`, ""},
		{"multiple users", `{"result":[{"sys_id":"` + userID + `"},{"sys_id":"fedcba9876543210fedcba9876543210"}]}`, ""},
		{"username only", `{"result":[{"user_name":"machine"}]}`, ""},
		{"malformed identifier", `{"result":[{"sys_id":"machine"}]}`, ""},
		{"nonhex identifier", `{"result":[{"sys_id":"0123456789abcdef0123456789abcdeg"}]}`, ""},
		{"uppercase identifier", `{"result":[{"sys_id":"0123456789ABCDEF0123456789ABCDEF"}]}`, ""},
		{"whitespace identifier", `{"result":[{"sys_id":" ` + userID + `"}]}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/api/now/table/sys_user" ||
					r.URL.Query().Get("sysparm_query") != "sys_id=javascript:gs.getUserID()" ||
					r.URL.Query().Get("sysparm_fields") != "sys_id" || r.URL.Query().Get("sysparm_limit") != "2" {
					t.Errorf("unexpected identity request: %s %s", r.Method, r.URL.RequestURI())
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			base, _ := url.Parse(server.URL)
			a := &Adapter{provider: ServiceNowProvider, base: base, client: server.Client(), token: []byte("synthetic-token"), project: "incident"}
			got, err := a.TicketIdentity(context.Background())
			if tc.want != "" {
				if err != nil || got != tc.want {
					t.Fatalf("identity = %q, error = %v", got, err)
				}
				return
			}
			var classified *ports.TicketProviderError
			if got != "" || !errors.As(err, &classified) || classified.Code != "invalid_identity" {
				t.Fatalf("unproven identity accepted: %q, error = %v", got, err)
			}
		})
	}
}

func TestSearchRejectsTruncatedAzureResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"workItems":[{"id":1},{"id":2},{"id":3}]}`))
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	a := &Adapter{provider: AzureProvider, base: base, client: server.Client(), project: "org/project/Bug", token: []byte("secret")}
	errResult, err := a.search(context.Background(), "synapse-intent-a")
	if errResult != nil {
		t.Fatalf("results = %#v", errResult)
	}
	var classified *ports.TicketProviderError
	if !errors.As(err, &classified) || classified.Code != "search_truncated" {
		t.Fatalf("error = %#v", err)
	}
}

func TestGetTicketReadsNativeAzureAndServiceNowShapes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/updates"):
			_, _ = w.Write([]byte(`{"count":1,"value":[{"revisedDate":"2026-10-20T01:02:02Z","revisedBy":{"id":"azure-state-user"},"fields":{"System.State":{"oldValue":"Active","newValue":"Done"}}}]}`))
		case strings.Contains(r.URL.Path, "_apis/wit/workitems"):
			_, _ = w.Write([]byte(`{"id":41,"fields":{"System.State":"Done","System.ChangedDate":"2026-10-20T01:02:03Z","System.ChangedBy":{"id":"forged-last-editor"}}}`))
		default:
			_, _ = w.Write([]byte(`{"result":{"sys_id":"abc","state":"6","sys_updated_on":"2026-10-20 01:02:03","closed_at":"2026-10-20 01:02:03","closed_by":{"value":"sn-user"}}}`))
		}
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	for _, tc := range []struct {
		name       string
		provider   integration.Provider
		project    string
		id         string
		wantAuthor string
	}{
		{"azure", AzureProvider, "org/project/Bug", "41", "azure-state-user"}, {"servicenow", ServiceNowProvider, "incident", "abc", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &Adapter{provider: tc.provider, base: base, client: server.Client(), project: tc.project, token: []byte("secret")}
			got, err := a.GetTicket(context.Background(), tc.id)
			if err != nil || got.StatusCategory != "done" || got.AuthorID != tc.wantAuthor || (tc.wantAuthor != "" && got.StatusChangedAt.IsZero()) {
				t.Fatalf("got %#v, err %v", got, err)
			}
		})
	}
}

func TestGetTicketDoesNotTreatAzureLastEditorAsStateActor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/updates") {
			_, _ = w.Write([]byte(`{"count":1,"value":[{"revisedDate":"2026-10-20T01:02:02Z","revisedBy":{"id":"last-editor"},"fields":{"System.Title":{"oldValue":"a","newValue":"b"}}}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":41,"fields":{"System.State":"Done","System.ChangedDate":"2026-10-20T01:02:03Z","System.ChangedBy":{"id":"forged-last-editor"}}}`))
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	a := &Adapter{provider: AzureProvider, base: base, client: server.Client(), project: "org/project/Bug", token: []byte("secret")}
	got, err := a.GetTicket(context.Background(), "41")
	if err != nil || got.StatusCategory != "done" || got.AuthorID != "" || !got.StatusChangedAt.IsZero() {
		t.Fatalf("got %#v, err %v", got, err)
	}
}

func TestValidateTicketPayloadRejectsEveryJSONCredentialLeaf(t *testing.T) {
	a := &Adapter{token: []byte("ticket-token")}
	for _, payload := range []json.RawMessage{
		json.RawMessage(`{"description":"ticket-token"}`),
		json.RawMessage(`{"description":"dGlja2V0LXRva2Vu"}`),
		json.RawMessage(`{"one":"safe","two":"ticket-token"}`),
	} {
		if err := a.ValidateTicketPayload(payload); err == nil {
			t.Fatalf("payload %s accepted a configured credential", payload)
		}
	}
	if err := a.ValidateTicketPayload(json.RawMessage(`{"description":"safe"}`)); err != nil {
		t.Fatalf("safe payload: %v", err)
	}
}

func TestRequestUsesNativeCredentialHeadersAndContentTypes(t *testing.T) {
	for _, tc := range []struct {
		name, path, wantAuth, wantType string
		provider                       integration.Provider
		method                         string
	}{
		{"azure-create-patch", "/org/project/_apis/wit/workitems/$Bug", "Basic OnBhdA==", "application/json-patch+json", AzureProvider, http.MethodPost},
		{"azure-wiql", "/org/project/_apis/wit/wiql", "Basic OnBhdA==", "application/json", AzureProvider, http.MethodPost},
		{"linear", "/graphql", "key", "application/json", LinearProvider, http.MethodPost},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path || r.Header.Get("Authorization") != tc.wantAuth || r.Header.Get("Content-Type") != tc.wantType {
					t.Errorf("path=%s auth=%q content-type=%q", r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type"))
				}
				_, _ = w.Write([]byte(`{}`))
			}))
			defer server.Close()
			base, _ := url.Parse(server.URL)
			a := &Adapter{provider: tc.provider, base: base, client: server.Client(), token: []byte(map[bool]string{true: "pat", false: "key"}[tc.provider == AzureProvider])}
			if err := a.request(context.Background(), tc.method, tc.path, nil, []byte(`{}`), &map[string]any{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCreateAzureUsesPostJSONPatchAndSynthesizesBrowserURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s; Azure Work Items Create requires POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json-patch+json" {
			t.Errorf("content-type = %q", r.Header.Get("Content-Type"))
		}
		if r.URL.Path != "/org/project/_apis/wit/workitems/$Bug" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"id":42,"url":"https://untrusted.example/rest/workitems/42"}`))
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	a := &Adapter{provider: AzureProvider, base: base, client: server.Client(), project: "org/project/Bug", token: []byte("pat")}
	ticket, err := a.createAzureWith(context.Background(), json.RawMessage(`[{"op":"add","path":"/fields/System.Title","value":"finding"}]`), a.request)
	if err != nil {
		t.Fatal(err)
	}
	if ticket.ID != "42" || ticket.URL != "https://dev.azure.com/org/project/_workitems/edit/42" {
		t.Fatalf("ticket = %#v", ticket)
	}
}

func TestGitHubAndGitLabSaaSAPIOriginsAreSeparateFromBrowserOrigins(t *testing.T) {
	for _, tc := range []struct {
		provider                                integration.Provider
		endpoint, project, wantAPI, wantBrowser string
	}{
		{GitHubProvider, "https://github.com", "owner/repo", "api.github.com", "github.com"},
		{GitLabProvider, "https://gitlab.com", "group/nested/project", "gitlab.com", "gitlab.com"},
	} {
		t.Run(string(tc.provider), func(t *testing.T) {
			a := &Adapter{provider: tc.provider, item: integration.Integration{Endpoint: tc.endpoint, Config: json.RawMessage(`{"` + map[integration.Provider]string{GitHubProvider: "repository", GitLabProvider: "project"}[tc.provider] + `":"` + tc.project + `"}`)}}
			if err := a.configureSCM(); err != nil {
				t.Fatal(err)
			}
			if a.base.Host != tc.wantAPI || a.browserBase.Host != tc.wantBrowser {
				t.Fatalf("api=%s browser=%s", a.base, a.browserBase)
			}
			if tc.provider == GitLabProvider && a.base.Path != "/api/v4" {
				t.Fatalf("GitLab path = %q", a.base.Path)
			}
		})
	}
}

func TestGitLabNestedProjectPathIsEscapedOnce(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/api/v4/projects/group%2Fnested%2Fproject/issues" {
			t.Fatalf("escaped path = %q", r.URL.EscapedPath())
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL + "/api/v4")
	a := &Adapter{provider: GitLabProvider, client: server.Client()}
	if err := a.requestWith(context.Background(), base, []byte("token"), http.MethodGet, "/projects/"+url.PathEscape("group/nested/project")+"/issues", nil, nil, &map[string]any{}); err != nil {
		t.Fatal(err)
	}
}

func TestResolveSelfHostedSCMEndpointReusesAdapterClient(t *testing.T) {
	hosts, err := selfhosted.ParseHostAllowlist([]string{"ghe.corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{}
	a := &Adapter{
		provider:       GitHubProvider,
		credentialHost: "ghe.corp.example",
		browserBase:    &url.URL{Scheme: "https", Host: "ghe.corp.example"},
		client:         client,
		rules:          selfhosted.Rules{Hosts: hosts},
	}
	credential := ports.GitCredential{Token: []byte("secret"), APIBase: "https://ghe.corp.example/api/v3"}
	firstBase, firstClient, _, err := a.resolveSCMEndpoint(credential)
	if err != nil {
		t.Fatal(err)
	}
	secondBase, secondClient, _, err := a.resolveSCMEndpoint(credential)
	if err != nil {
		t.Fatal(err)
	}
	if firstBase.String() != credential.APIBase || secondBase.String() != credential.APIBase || firstClient != client || secondClient != client || firstClient != secondClient {
		t.Fatalf("self-hosted SCM endpoint/client first=%s/%p second=%s/%p adapter=%p", firstBase, firstClient, secondBase, secondClient, client)
	}
}

func TestGitLabSearchRefusesAnUnconsumedNextPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Next-Page", "2")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	a := &Adapter{provider: GitLabProvider, base: base, browserBase: base, client: server.Client(), project: "group/project"}
	// Search's public method preflights SCM; exercise the response parser at its
	// request boundary with a temporary no-op credential-free adapter instead.
	page := gitLabSearchPage{}
	if err := a.requestWith(context.Background(), base, []byte("token"), http.MethodGet, "/projects/group%2Fproject/issues", nil, nil, &page); err != nil {
		t.Fatal(err)
	}
	if page.nextPage != "2" {
		t.Fatalf("next page = %q", page.nextPage)
	}
}

func TestCreateTicketFencesSCMCredentialRotationBeforePost(t *testing.T) {
	for _, tc := range []struct {
		name     string
		token    []byte
		provider scmconnector.Provider
	}{
		{"rotated-token", []byte("new-token"), scmconnector.ProviderGitHub},
		{"recreated-wrong-provider", []byte("new-token"), scmconnector.ProviderGitLab},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &rotatingSCMStore{token: []byte("old-token"), provider: scmconnector.ProviderGitHub}
			posted := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodGet:
					store.rotate(tc.token, tc.provider)
					_, _ = w.Write([]byte(`{"private":true,"visibility":"private","has_issues":true,"permissions":{"push":true}}`))
				case http.MethodPost:
					posted = true
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"number":1,"html_url":"https://github.com/owner/repo/issues/1"}`))
				}
			}))
			defer server.Close()
			base, _ := url.Parse(server.URL)
			a := &Adapter{provider: GitHubProvider, scm: store, credentialHost: "github.com", base: base, browserBase: &url.URL{Scheme: "https", Host: "github.com"}, client: server.Client(), project: "owner/repo"}
			_, err := a.CreateTicket(context.Background(), json.RawMessage(`{"title":"safe"}`))
			var classified *ports.TicketProviderError
			if !errors.As(err, &classified) || classified.Code != "credential_changed" || posted {
				t.Fatalf("err=%v posted=%v", err, posted)
			}
		})
	}
}

type gitLabTestSCMStore struct{ token []byte }

func (s gitLabTestSCMStore) List(context.Context) ([]ports.SCMConnectorMeta, error) {
	return []ports.SCMConnectorMeta{{Host: "gitlab.com", Provider: scmconnector.ProviderGitLab}}, nil
}
func (s gitLabTestSCMStore) ResolveGitCredential(context.Context, string) (ports.GitCredential, bool, error) {
	return ports.GitCredential{Token: append([]byte(nil), s.token...)}, true, nil
}
func (gitLabTestSCMStore) Put(context.Context, scmconnector.Connector, []byte) error {
	return shared.ErrValidation
}
func (gitLabTestSCMStore) Get(context.Context, shared.ID) (ports.SCMConnectorMeta, error) {
	return ports.SCMConnectorMeta{}, shared.ErrNotFound
}
func (gitLabTestSCMStore) Delete(context.Context, shared.ID) error { return shared.ErrNotFound }

func TestGitLabPreflightUsesEffectiveProjectAndGroupAccess(t *testing.T) {
	for _, tc := range []struct {
		name, permissions string
		allowed           bool
	}{
		{"missing", `{}`, false},
		{"null", `{"project_access":null,"group_access":null}`, false},
		{"direct-low", `{"project_access":{"access_level":20}}`, false},
		{"group-low", `{"group_access":{"access_level":20}}`, false},
		{"direct-developer", `{"project_access":{"access_level":30}}`, true},
		{"group-developer", `{"group_access":{"access_level":30}}`, true},
		{"inherited-owner", `{"project_access":{"access_level":10},"group_access":{"access_level":50}}`, true},
		{"direct-maintainer", `{"project_access":{"access_level":40},"group_access":{"access_level":10}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.EscapedPath() != "/projects/namespace%2Fproject" {
					t.Errorf("unexpected preflight request %s %s", r.Method, r.URL.EscapedPath())
				}
				_, _ = fmt.Fprintf(w, `{"permissions":%s}`, tc.permissions)
			}))
			defer server.Close()
			base, _ := url.Parse(server.URL)
			a := &Adapter{provider: GitLabProvider, project: "namespace/project", credentialHost: "gitlab.com", scm: gitLabTestSCMStore{token: []byte("gitlab-token")}, base: base, browserBase: base, client: server.Client()}
			request, err := a.scmPreflightRequest(context.Background())
			if request != nil {
				defer request.clear()
			}
			if tc.allowed && err != nil {
				t.Fatalf("effective access refused: %v", err)
			}
			if !tc.allowed {
				var classified *ports.TicketProviderError
				if !errors.As(err, &classified) || classified.Code != "provider_access_required" {
					t.Fatalf("insufficient access accepted: %v", err)
				}
			}
		})
	}
}

func TestForgeWriteRejectsCredentialRotatedAfterLiteralBinding(t *testing.T) {
	store := &rotatingSCMStore{token: []byte("prior-forge-secret"), provider: scmconnector.ProviderGitHub}
	posted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"private":true,"visibility":"private","has_issues":true,"permissions":{"push":true}}`))
			return
		}
		posted = true
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number":1,"html_url":"https://github.com/owner/repo/issues/1"}`))
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	a := &Adapter{provider: GitHubProvider, scm: store, credentialHost: "github.com", base: base, browserBase: &url.URL{Scheme: "https", Host: "github.com"}, client: server.Client(), project: "owner/repo"}
	if err := a.BindTicketCredentials(context.Background()); err != nil {
		t.Fatal(err)
	}
	store.rotate([]byte("current-forge-secret"), scmconnector.ProviderGitHub)
	_, err := a.CreateTicket(context.Background(), json.RawMessage(`{"title":"literal current-forge-secret"}`))
	var classified *ports.TicketProviderError
	if !errors.As(err, &classified) || classified.Code != "payload_contains_credential" || posted {
		t.Fatalf("rotated credential reached outward write: err=%v posted=%v", err, posted)
	}
}

func TestGitLabCreateAndSearchAcceptModernWorkItemURLs(t *testing.T) {
	const marker = "synapse-intent-gitlab-marker"
	var preflights, created, searched int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "gitlab-token" {
			t.Errorf("GitLab credential header = %q", r.Header.Get("PRIVATE-TOKEN"))
		}
		switch {
		case r.Method == http.MethodGet && r.URL.EscapedPath() == "/projects/namespace%2Fproject":
			preflights++
			if r.URL.RawQuery != "" {
				t.Errorf("GitLab preflight query = %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"permissions":{"project_access":{"access_level":40}}}`))
		case r.Method == http.MethodPost && r.URL.EscapedPath() == "/projects/namespace%2Fproject/issues":
			created++
			_, _ = w.Write([]byte(`{"iid":42,"web_url":"https://gitlab.example/namespace/project/-/work_items/42","confidential":true}`))
		case r.Method == http.MethodGet && r.URL.EscapedPath() == "/projects/namespace%2Fproject/issues":
			searched++
			query := r.URL.Query()
			if query.Get("labels") != marker || query.Get("scope") != "all" || query.Get("per_page") != "3" || len(query) != 3 {
				t.Errorf("GitLab marker query = %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`[{"iid":42,"web_url":"https://gitlab.example/namespace/project/-/work_items/42","confidential":true,"labels":["synapse-intent-gitlab-marker"]}]`))
		default:
			t.Errorf("unexpected GitLab request %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	a := &Adapter{
		provider:       GitLabProvider,
		scm:            gitLabTestSCMStore{token: []byte("gitlab-token")},
		credentialHost: "gitlab.com",
		base:           base,
		browserBase:    &url.URL{Scheme: "https", Host: "gitlab.example"},
		client:         server.Client(),
		project:        "namespace/project",
	}

	createdTicket, err := a.CreateTicket(context.Background(), json.RawMessage(`{"title":"finding","confidential":true}`))
	if err != nil || createdTicket.ID != "42" || createdTicket.URL != "https://gitlab.example/namespace/project/-/work_items/42" {
		t.Fatalf("GitLab create = %#v, %v", createdTicket, err)
	}
	hits, err := a.SearchTicketMarker(context.Background(), "namespace/project", "issue", marker)
	if err != nil || len(hits) != 1 || hits[0].ID != "42" || hits[0].URL != createdTicket.URL {
		t.Fatalf("GitLab marker search = %#v, %v", hits, err)
	}
	if preflights != 2 || created != 1 || searched != 1 {
		t.Fatalf("GitLab requests preflight=%d create=%d search=%d", preflights, created, searched)
	}
}

func TestGitLabTicketURLsAcceptCanonicalIssueAndWorkItemPaths(t *testing.T) {
	a := &Adapter{provider: GitLabProvider, browserBase: &url.URL{Scheme: "https", Host: "gitlab.example"}, project: "namespace/project"}
	for name, ticketURL := range map[string]string{
		"legacy issue":     "https://gitlab.example/namespace/project/-/issues/42",
		"modern work item": "https://gitlab.example/namespace/project/-/work_items/42",
	} {
		t.Run(name, func(t *testing.T) {
			if !a.ticketURLValid(ticketURL) {
				t.Fatalf("ticket URL rejected: %q", ticketURL)
			}
		})
	}
}

func TestGitLabTicketURLsRejectUnsafePathsAndOrigins(t *testing.T) {
	a := &Adapter{provider: GitLabProvider, browserBase: &url.URL{Scheme: "https", Host: "gitlab.example"}, project: "namespace/project"}
	for name, ticketURL := range map[string]string{
		"wrong path":           "https://gitlab.example/namespace/project/issues/42",
		"wrong project":        "https://gitlab.example/namespace/other/-/work_items/42",
		"wrong host":           "https://attacker.example/namespace/project/-/work_items/42",
		"credentials":          "https://token@gitlab.example/namespace/project/-/work_items/42",
		"query":                "https://gitlab.example/namespace/project/-/work_items/42?private_token=forbidden",
		"fragment":             "https://gitlab.example/namespace/project/-/work_items/42#forbidden",
		"dot path":             "https://gitlab.example/namespace/project/./-/work_items/42",
		"unexpected suffix":    "https://gitlab.example/namespace/project/-/work_items/42/notes",
		"leading zero":         "https://gitlab.example/namespace/project/-/work_items/042",
		"zero":                 "https://gitlab.example/namespace/project/-/work_items/0",
		"escaped work item":    "https://gitlab.example/namespace/project/-/%77ork_items/42",
		"non HTTPS":            "http://gitlab.example/namespace/project/-/work_items/42",
		"cross project prefix": "https://gitlab.example/namespace/project-other/-/work_items/42",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := a.createGitLabWith(context.Background(), json.RawMessage(`{"title":"finding"}`), func(_ context.Context, _ string, _ string, _ url.Values, _ []byte, out any) error {
				return json.Unmarshal([]byte(`{"iid":42,"web_url":"`+ticketURL+`","confidential":true}`), out)
			})
			var classified *ports.TicketProviderError
			if !errors.As(err, &classified) || classified.Code != "malformed_create_response" {
				t.Fatalf("GitLab create err=%v", err)
			}
		})
	}
}

func TestGitLabMarkerSearchRejectsUnsafePathsAndOrigins(t *testing.T) {
	const marker = "synapse-intent-gitlab-marker"
	for name, ticketURL := range map[string]string{
		"wrong path":        "https://gitlab.example/namespace/project/issues/42",
		"wrong project":     "https://gitlab.example/namespace/other/-/work_items/42",
		"wrong host":        "https://attacker.example/namespace/project/-/work_items/42",
		"credentials":       "https://token@gitlab.example/namespace/project/-/work_items/42",
		"query":             "https://gitlab.example/namespace/project/-/work_items/42?private_token=forbidden",
		"fragment":          "https://gitlab.example/namespace/project/-/work_items/42#forbidden",
		"dot path":          "https://gitlab.example/namespace/project/./-/work_items/42",
		"unexpected suffix": "https://gitlab.example/namespace/project/-/work_items/42/notes",
		"leading zero":      "https://gitlab.example/namespace/project/-/work_items/042",
		"zero":              "https://gitlab.example/namespace/project/-/work_items/0",
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.EscapedPath() == "/projects/namespace%2Fproject":
					_, _ = w.Write([]byte(`{"permissions":{"project_access":{"access_level":40}}}`))
				case r.Method == http.MethodGet && r.URL.EscapedPath() == "/projects/namespace%2Fproject/issues":
					_, _ = w.Write([]byte(`[{"iid":42,"web_url":"` + ticketURL + `","confidential":true,"labels":["` + marker + `"]}]`))
				default:
					t.Errorf("unexpected GitLab request %s %s", r.Method, r.URL.String())
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			base, _ := url.Parse(server.URL)
			a := &Adapter{
				provider:       GitLabProvider,
				scm:            gitLabTestSCMStore{token: []byte("gitlab-token")},
				credentialHost: "gitlab.com",
				base:           base,
				browserBase:    &url.URL{Scheme: "https", Host: "gitlab.example"},
				client:         server.Client(),
				project:        "namespace/project",
			}
			hits, err := a.SearchTicketMarker(context.Background(), "namespace/project", "issue", marker)
			var classified *ports.TicketProviderError
			if !errors.As(err, &classified) || classified.Code != "invalid_search_response" || len(hits) != 0 {
				t.Fatalf("GitLab marker search hits=%#v err=%v", hits, err)
			}
		})
	}
}

func TestLinearUsesOfficialIssueSchemaAndRecoversOnlyExactTerminalMarker(t *testing.T) {
	const marker = "synapse-intent-linear-marker"
	for _, tc := range []struct {
		name        string
		description string
		team        string
		want        bool
	}{
		{"exact terminal suffix", "summary\n\n[" + marker + "]", "team-1", true},
		{"substring", "summary " + marker + " remains", "team-1", false},
		{"prefix", "[" + marker + "]\n\nsummary", "team-1", false},
		{"embedded", "summary\n\n[" + marker + "] extra", "team-1", false},
		{"duplicate", "summary\n\n[" + marker + "]\n\n[" + marker + "]", "team-1", false},
		{"wrong team", "summary\n\n[" + marker + "]", "team-2", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					Query string `json:"query"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(request.Query, "issueSearch") || strings.Contains(request.Query, "updatedBy") {
					t.Errorf("Linear recovery query=%q", request.Query)
				}
				_, _ = w.Write([]byte(`{"data":{"issueSearch":{"nodes":[{"id":"linear-42","url":"https://linear.app/team/issue/SEC-42/title","description":` + strconv.Quote(tc.description) + `,"team":{"id":"` + tc.team + `"}}],"pageInfo":{"hasNextPage":false}}}}`))
			}))
			defer server.Close()
			base, _ := url.Parse(server.URL)
			a := &Adapter{provider: LinearProvider, base: base, client: server.Client(), token: []byte("linear-key"), project: "team-1"}
			hits, err := a.search(context.Background(), marker)
			if tc.want {
				if err != nil || len(hits) != 1 || hits[0].ID != "linear-42" {
					t.Fatalf("Linear recovery hits=%#v err=%v", hits, err)
				}
				return
			}
			var classified *ports.TicketProviderError
			if !errors.As(err, &classified) || classified.Code != "invalid_search_response" {
				t.Fatalf("Linear invalid recovery hits=%#v err=%v", hits, err)
			}
		})
	}
}

func TestLinearTicketReadDoesNotRequestUnsupportedUpdatedBy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Query string `json:"query"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(request.Query, "updatedAt") || strings.Contains(request.Query, "updatedBy") {
			t.Errorf("Linear issue query=%q", request.Query)
		}
		_, _ = w.Write([]byte(`{"data":{"issue":{"id":"linear-42","updatedAt":"2026-10-20T01:02:03Z","state":{"type":"completed"}}}}`))
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	a := &Adapter{provider: LinearProvider, base: base, client: server.Client(), token: []byte("linear-key"), project: "team-1"}
	observation, err := a.GetTicket(context.Background(), "linear-42")
	if err != nil || observation.ExternalID != "linear-42" || observation.StatusCategory != "done" || !observation.UpdatedAt.Equal(time.Date(2026, 10, 20, 1, 2, 3, 0, time.UTC)) {
		t.Fatalf("Linear observation=%#v err=%v", observation, err)
	}
}
