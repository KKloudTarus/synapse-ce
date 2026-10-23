package documentproviders

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const notionContainer = "0123456789abcdef0123456789abcdef"

type notionFake struct {
	bot      string
	page     string
	botCode  int
	pageCode int
	paths    []string
	authSeen []string
	version  []string
}

func (f *notionFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.paths = append(f.paths, r.URL.Path)
	f.authSeen = append(f.authSeen, r.Header.Get("Authorization"))
	f.version = append(f.version, r.Header.Get("Notion-Version"))
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/v1/users/me":
		if f.botCode != 0 {
			w.WriteHeader(f.botCode)
			_, _ = w.Write([]byte(`{"object":"error","code":"unauthorized"}`))
			return
		}
		_, _ = w.Write([]byte(f.bot))
	case strings.HasPrefix(r.URL.Path, "/v1/pages/"):
		if f.pageCode != 0 {
			w.WriteHeader(f.pageCode)
			_, _ = w.Write([]byte(`{"object":"error","code":"object_not_found"}`))
			return
		}
		_, _ = w.Write([]byte(f.page))
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"object":"error","code":"not_found"}`))
	}
}

func newNotionAdapter(t *testing.T, fake *notionFake) *notionAdapter {
	t.Helper()
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 10 * time.Second
	base := strings.TrimPrefix(server.URL, "http://")
	client.Transport = notionRewrite{host: base, inner: client.Transport}
	return &notionAdapter{client: client, token: "secret_notion_token_value", container: notionContainer}
}

// notionRewrite sends the pinned api.notion.com URL to the test server while the
// adapter keeps building the real origin.
type notionRewrite struct {
	host  string
	inner http.RoundTripper
}

func (t notionRewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = t.host
	return t.inner.RoundTrip(clone)
}

func notionPageJSON(overrides map[string]any) string {
	page := map[string]any{
		"object": "page", "id": notionContainer, "in_trash": false, "archived": false,
		"public_url": nil, "parent": map[string]any{"type": "workspace"},
	}
	for key, value := range overrides {
		page[key] = value
	}
	raw, _ := json.Marshal(page)
	return string(raw)
}

func TestNotionConnectionTest(t *testing.T) {
	bot := `{"object":"user","type":"bot","id":"bot-1"}`
	for _, tc := range []struct {
		name           string
		fake           *notionFake
		wantCode       string
		wantRestricted bool
		wantOK         bool
	}{
		{name: "private container", fake: &notionFake{bot: bot, page: notionPageJSON(nil)}, wantOK: true},
		{name: "dashed id", fake: &notionFake{bot: bot, page: notionPageJSON(map[string]any{"id": "01234567-89ab-cdef-0123-456789abcdef"})}, wantOK: true},
		{name: "published to web", fake: &notionFake{bot: bot, page: notionPageJSON(map[string]any{"public_url": "https://example.notion.site/report"})}, wantCode: "container_published_to_web", wantRestricted: true},
		{name: "unreadable sharing state", fake: &notionFake{bot: bot, page: notionPageJSON(map[string]any{"public_url": 42})}, wantCode: "container_published_to_web", wantRestricted: true},
		{name: "container in trash", fake: &notionFake{bot: bot, page: notionPageJSON(map[string]any{"in_trash": true})}, wantCode: "container_in_trash"},
		{name: "legacy archived flag", fake: &notionFake{bot: bot, page: notionPageJSON(map[string]any{"archived": true})}, wantCode: "container_in_trash"},
		{name: "another page", fake: &notionFake{bot: bot, page: notionPageJSON(map[string]any{"id": "ffffffffffffffffffffffffffffffff"})}, wantCode: "invalid_container"},
		{name: "database instead of page", fake: &notionFake{bot: bot, page: notionPageJSON(map[string]any{"object": "database"})}, wantCode: "invalid_container"},
		{name: "parent withheld", fake: &notionFake{bot: bot, page: `{"object":"page","id":"` + notionContainer + `","in_trash":false,"public_url":null}`}, wantCode: "complete_identity_unverifiable"},
		{name: "person token", fake: &notionFake{bot: `{"object":"user","type":"person","id":"user-1"}`, page: notionPageJSON(nil)}, wantCode: "invalid_identity"},
		{name: "revoked token", fake: &notionFake{botCode: http.StatusUnauthorized, page: notionPageJSON(nil)}, wantCode: "permission_denied"},
		{name: "container not shared with the integration", fake: &notionFake{bot: bot, pageCode: http.StatusNotFound}, wantCode: "container_not_shared"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter := newNotionAdapter(t, tc.fake)
			err := adapter.TestConnection(context.Background())
			if tc.wantOK {
				if err != nil {
					t.Fatalf("expected the connection to pass, got %v", err)
				}
				if len(tc.fake.version) == 0 || tc.fake.version[0] != notionAPIVersion {
					t.Fatalf("every call must pin the API version, saw %v", tc.fake.version)
				}
				return
			}
			var refusal *ports.DocumentProviderError
			if !errors.As(err, &refusal) {
				t.Fatalf("expected a refusal, got %v", err)
			}
			if refusal.Code != tc.wantCode {
				t.Fatalf("code = %q, want %q", refusal.Code, tc.wantCode)
			}
			if refusal.RestrictionLost != tc.wantRestricted {
				t.Fatalf("RestrictionLost = %v, want %v", refusal.RestrictionLost, tc.wantRestricted)
			}
		})
	}
}

func TestNotionNeverOffersPublication(t *testing.T) {
	registry := integration.NewRegistry()
	if err := Register(registry); err != nil {
		t.Fatalf("register: %v", err)
	}
	descriptor, err := registry.Descriptor(Notion)
	if err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	for _, capability := range descriptor.Capabilities {
		if capability == integration.CapabilityDocuments {
			t.Fatalf("Notion must not advertise document publication: %v", descriptor.Capabilities)
		}
	}
	// The adapter type itself must stay off the document port, so a future
	// composition cannot wire it as a destination by accident.
	if _, ok := any(&notionAdapter{}).(ports.DocumentProvider); ok {
		t.Fatalf("the Notion adapter must not satisfy the document provider port")
	}
}

func TestNotionFactoryValidation(t *testing.T) {
	secrets := integration.CredentialBundle{"integration_token": "secret_notion_token_value"}
	config := func(overrides map[string]string) []byte {
		values := map[string]string{"space": notionContainer, "read_group": "Security reviewers", "data_class": "detail"}
		for key, value := range overrides {
			values[key] = value
		}
		raw, err := json.Marshal(values)
		if err != nil {
			t.Fatalf("marshal config: %v", err)
		}
		return raw
	}
	for _, tc := range []struct {
		name     string
		endpoint string
		config   []byte
		secrets  integration.CredentialBundle
		wantErr  bool
	}{
		{name: "pinned origin", endpoint: notionAPIOrigin, config: config(nil), secrets: secrets},
		{name: "another origin", endpoint: "https://notion.example.com", config: config(nil), secrets: secrets, wantErr: true},
		{name: "plaintext origin", endpoint: "http://api.notion.com", config: config(nil), secrets: secrets, wantErr: true},
		{name: "container is not an identifier", endpoint: notionAPIOrigin, config: config(map[string]string{"space": "my page"}), secrets: secrets, wantErr: true},
		{name: "summary data class", endpoint: notionAPIOrigin, config: config(map[string]string{"data_class": "summary"}), secrets: secrets, wantErr: true},
		{name: "missing reader group", endpoint: notionAPIOrigin, config: config(map[string]string{"read_group": " "}), secrets: secrets, wantErr: true},
		{name: "missing token", endpoint: notionAPIOrigin, config: config(nil), secrets: integration.CredentialBundle{}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter, err := newNotion(integration.Integration{Provider: Notion, Endpoint: tc.endpoint, Config: tc.config}, tc.secrets, selfhosted.Rules{})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected a rejection")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected rejection: %v", err)
			}
			built, ok := adapter.(*notionAdapter)
			if !ok {
				t.Fatalf("factory returned %T", adapter)
			}
			built.Close()
			if built.token != "" {
				t.Fatalf("Close must clear the held credential")
			}
		})
	}
}
