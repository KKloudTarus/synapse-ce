package ticketproviders

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scmconnector"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestGitHubPreflightRefusesUnprovenPrivateWriteAccess(t *testing.T) {
	for name, repository := range map[string]string{
		"public":              `{"private":false,"visibility":"public","has_issues":true,"permissions":{"push":true}}`,
		"internal":            `{"private":true,"visibility":"internal","has_issues":true,"permissions":{"push":true}}`,
		"missing visibility":  `{"private":true,"has_issues":true,"permissions":{"push":true}}`,
		"private flag false":  `{"private":false,"visibility":"private","has_issues":true,"permissions":{"push":true}}`,
		"issues disabled":     `{"private":true,"visibility":"private","has_issues":false,"permissions":{"push":true}}`,
		"missing permissions": `{"private":true,"visibility":"private","has_issues":true}`,
		"read only":           `{"private":true,"visibility":"private","has_issues":true,"permissions":{"pull":true}}`,
		"empty proof":         `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			reads, posts := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo" {
					reads++
					_, _ = w.Write([]byte(repository))
					return
				}
				if r.Method == http.MethodPost {
					posts++
				}
				t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			base, _ := url.Parse(server.URL)
			a := &Adapter{provider: GitHubProvider, scm: &rotatingSCMStore{token: []byte("synthetic-token"), provider: scmconnector.ProviderGitHub}, credentialHost: "github.com", base: base, browserBase: &url.URL{Scheme: "https", Host: "github.com"}, client: server.Client(), project: "owner/repo"}
			_, discoverErr := a.DiscoverTickets(context.Background(), "owner/repo", "issue", "")
			_, createErr := a.CreateTicket(context.Background(), json.RawMessage(`{"title":"synthetic finding"}`))
			for _, err := range []error{discoverErr, createErr} {
				var classified *ports.TicketProviderError
				if !errors.As(err, &classified) || classified.Code != "private_repository_required" || classified.Ambiguous {
					t.Fatalf("unproven destination error=%v", err)
				}
			}
			if reads != 2 || posts != 0 {
				t.Fatalf("repository reads=%d outward posts=%d", reads, posts)
			}
		})
	}
}

func TestGitHubCreateRechecksPrivacyAfterDiscovery(t *testing.T) {
	private, reads, posts := true, 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo":
			reads++
			_ = json.NewEncoder(w).Encode(map[string]any{"private": private, "visibility": map[bool]string{true: "private", false: "public"}[private], "has_issues": true, "permissions": map[string]bool{"push": true}})
		case "/user":
			_, _ = w.Write([]byte(`{"login":"synthetic-user"}`))
		default:
			if r.Method == http.MethodPost {
				posts++
			}
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	a := &Adapter{provider: GitHubProvider, scm: &rotatingSCMStore{token: []byte("synthetic-token"), provider: scmconnector.ProviderGitHub}, credentialHost: "github.com", base: base, browserBase: &url.URL{Scheme: "https", Host: "github.com"}, client: server.Client(), project: "owner/repo"}
	meta, err := a.DiscoverTickets(context.Background(), "owner/repo", "issue", "")
	if err != nil || meta.SecurityPolicy != "private_repository" {
		t.Fatalf("discovery=%#v err=%v", meta, err)
	}
	private = false
	_, err = a.CreateTicket(context.Background(), json.RawMessage(`{"title":"synthetic finding"}`))
	var classified *ports.TicketProviderError
	if !errors.As(err, &classified) || classified.Code != "private_repository_required" || reads != 2 || posts != 0 {
		t.Fatalf("error=%v repository reads=%d outward posts=%d", err, reads, posts)
	}
}
