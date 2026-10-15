package jira

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testAdapter(t *testing.T, cloud bool, fn transport) *Adapter {
	t.Helper()
	base, err := url.Parse("https://example.atlassian.net")
	if err != nil {
		t.Fatal(err)
	}
	if !cloud {
		base, err = url.Parse("https://jira.corp.example/jira")
		if err != nil {
			t.Fatal(err)
		}
	}
	return &Adapter{base: base, cloud: cloud, token: "secret-token", email: "person@example.test", client: &http.Client{Transport: fn, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func response(status int, body string, headers http.Header) *http.Response {
	if headers == nil {
		headers = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body))}
}

func TestRegisterAndEndpointPolicy(t *testing.T) {
	registry := integration.NewRegistry()
	if err := Register(registry); err != nil {
		t.Fatal(err)
	}
	for _, provider := range []integration.Provider{CloudProvider, DCProvider} {
		d, err := registry.Descriptor(provider)
		if err != nil || !d.Supports(integration.CapabilityTestConnection) || len(d.Capabilities) != 1 {
			t.Fatalf("descriptor %q: %+v %v", provider, d, err)
		}
	}
	cloud := integration.Integration{ID: "cloud", TenantID: "tenant", Name: "cloud", Provider: CloudProvider, Version: 1, Endpoint: "https://unit.atlassian.net"}
	if _, err := New(cloud, integration.CredentialBundle{"email": "p@example.test", "api_token": "secret-token"}, selfhosted.Rules{}); err != nil {
		t.Fatalf("valid Cloud endpoint: %v", err)
	}
	cloud.Endpoint = "https://unit.atlassian.net:443"
	if _, err := New(cloud, integration.CredentialBundle{"email": "p@example.test", "api_token": "secret-token"}, selfhosted.Rules{}); err != nil {
		t.Fatalf("valid canonical Cloud port: %v", err)
	}
	for _, endpoint := range []string{"https://atlassian.net", "https://unit.atlassian.net/jira", "https://unit.atlassian.net?token=secret-token", "https://evil.example"} {
		cloud.Endpoint = endpoint
		if _, err := New(cloud, integration.CredentialBundle{"email": "p@example.test", "api_token": "secret-token"}, selfhosted.Rules{}); err == nil {
			t.Errorf("unsafe Cloud endpoint accepted: %q", endpoint)
		}
	}
	dc := integration.Integration{ID: "dc", TenantID: "tenant", Name: "dc", Provider: DCProvider, Version: 1, Endpoint: "https://jira.corp.example/jira"}
	if _, err := New(dc, integration.CredentialBundle{"pat": "secret-token"}, selfhosted.Rules{}); err == nil {
		t.Fatal("DC accepted without an operator allowlist")
	}
	hosts, err := selfhosted.ParseHostAllowlist([]string{"jira.corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(dc, integration.CredentialBundle{"pat": "secret-token"}, selfhosted.Rules{Hosts: hosts}); err != nil {
		t.Fatalf("allowlisted DC rejected: %v", err)
	}
}

func TestConnectionAndErrorsAreCredentialSafe(t *testing.T) {
	for _, tc := range []struct {
		status   int
		wantCode string
		retry    time.Duration
	}{{401, "unauthorized", 0}, {429, "rate_limited", time.Second}, {500, "server_error", 0}} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			headers := http.Header{}
			if tc.status == 429 {
				headers.Set("Retry-After", "1")
			}
			a := testAdapter(t, true, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/rest/api/3/myself" || r.Header.Get("Authorization") == "" {
					t.Error("incorrect Jira Cloud request")
				}
				return response(tc.status, `{"error":"secret-token"}`, headers), nil
			})
			err := a.TestConnection(context.Background())
			var got *ports.TicketProviderError
			if !errors.As(err, &got) || got.Code != tc.wantCode || got.RetryAfter != tc.retry || strings.Contains(err.Error(), "secret-token") {
				t.Fatalf("error = %#v", err)
			}
		})
	}
	a := testAdapter(t, true, func(*http.Request) (*http.Response, error) { return nil, errors.New("secret-token transport failure") })
	err := a.TestConnection(context.Background())
	if err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("network error leaked a secret: %v", err)
	}
	for _, body := range []string{`{}`, `{"accountId":"secret-token"}`} {
		identity := testAdapter(t, true, func(*http.Request) (*http.Response, error) { return response(http.StatusOK, body, nil), nil })
		err := identity.TestConnection(context.Background())
		var providerErr *ports.TicketProviderError
		if !errors.As(err, &providerErr) || strings.Contains(err.Error(), "secret-token") {
			t.Fatalf("Cloud identity validation body=%s err=%v", body, err)
		}
	}
}

func TestCreateAndMarkerSearchAreBoundedAndVerified(t *testing.T) {
	calls := 0
	a := testAdapter(t, true, func(r *http.Request) (*http.Response, error) {
		calls++
		switch calls {
		case 1:
			if r.Method != http.MethodPost || r.URL.Path != "/rest/api/3/issue" {
				t.Errorf("create request %s %s", r.Method, r.URL)
			}
			return response(http.StatusCreated, `{"key":"SEC_1-9"}`, nil), nil
		case 2:
			if r.URL.Path != "/rest/api/3/search/jql" || r.URL.Query().Get("maxResults") != "2" || r.URL.Query().Get("jql") != `project = "SEC" AND issuetype = "10001" AND labels = "synapse-intent-item-1"` {
				t.Errorf("search request %s", r.URL)
			}
			return response(200, `{"isLast":true,"issues":[{"key":"SEC_1-9"}]}`, nil), nil
		case 3:
			if r.URL.Path != "/rest/api/3/issue/SEC_1-9" {
				t.Errorf("candidate verification request %s", r.URL)
			}
			return response(200, `{"fields":{"labels":["synapse-intent-item-1"],"project":{"key":"SEC"},"issuetype":{"id":"10001"}}}`, nil), nil
		default:
			return response(500, "{}", nil), nil
		}
	})
	remote, err := a.CreateTicket(context.Background(), []byte(`{"fields":{}}`))
	if err != nil || remote.URL != "https://example.atlassian.net/browse/SEC_1-9" {
		t.Fatalf("create = %+v, %v", remote, err)
	}
	found, err := a.SearchTicketMarker(context.Background(), "SEC", "10001", "synapse-intent-item-1")
	if err != nil || len(found) != 1 || found[0].ID != "SEC_1-9" {
		t.Fatalf("search = %+v, %v", found, err)
	}

	bad := testAdapter(t, true, func(*http.Request) (*http.Response, error) {
		return response(201, `{"key":"untrusted-secret-token"}`, nil), nil
	})
	_, err = bad.CreateTicket(context.Background(), []byte(`{}`))
	var providerErr *ports.TicketProviderError
	if !errors.As(err, &providerErr) || !providerErr.Ambiguous || providerErr.Code != "malformed_create_response" || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("malformed create = %#v", err)
	}
	if _, err := a.SearchTicketMarker(context.Background(), "SEC", "10001", `bad" OR project = OTHER`); err == nil {
		t.Fatal("marker injection accepted")
	}
	if _, err := a.SearchTicketMarker(context.Background(), "SEC", `10001" OR project = OTHER`, "synapse-intent-item-1"); err == nil {
		t.Fatal("issue type injection accepted")
	}
	mismatchedType := testAdapter(t, true, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/rest/api/3/search/jql" {
			return response(http.StatusOK, `{"isLast":true,"issues":[{"key":"SEC-9"}]}`, nil), nil
		}
		return response(http.StatusOK, `{"fields":{"labels":["synapse-intent-item-1"],"project":{"key":"SEC"},"issuetype":{"id":"10002"}}}`, nil), nil
	})
	if _, err := mismatchedType.SearchTicketMarker(context.Background(), "SEC", "10001", "synapse-intent-item-1"); err == nil {
		t.Fatal("candidate issue type mismatch accepted")
	} else if !errors.As(err, &providerErr) || providerErr.Code != "invalid_search_response" {
		t.Fatalf("candidate issue type mismatch = %v", err)
	}
}

func TestProviderIssueKeysCannotReflectCredentials(t *testing.T) {
	for _, cloud := range []bool{true, false} {
		t.Run(map[bool]string{true: "cloud", false: "data-center"}[cloud], func(t *testing.T) {
			for _, key := range []string{"SECRET-1", "HEX534543524554-1"} {
				t.Run(key, func(t *testing.T) {
					if !issueKeyPattern.MatchString(key) {
						t.Fatal("credential reflection test requires a syntactically valid issue key")
					}
					calls := 0
					a := testAdapter(t, cloud, func(r *http.Request) (*http.Response, error) {
						calls++
						if r.Method == http.MethodPost {
							return response(http.StatusCreated, `{"key":"`+key+`"}`, nil), nil
						}
						if !strings.HasSuffix(r.URL.Path, "/search") && !strings.HasSuffix(r.URL.Path, "/search/jql") {
							t.Errorf("credential-bearing candidate reached verification: %s", r.URL.Path)
						}
						return response(http.StatusOK, `{"isLast":true,"total":1,"startAt":0,"maxResults":2,"issues":[{"key":"`+key+`"}]}`, nil), nil
					})
					a.token = "SECRET"
					remote, err := a.CreateTicket(context.Background(), json.RawMessage(`{"fields":{"summary":"safe"}}`))
					var providerErr *ports.TicketProviderError
					if !errors.As(err, &providerErr) || providerErr.Code != "malformed_create_response" || !providerErr.Ambiguous || remote.ID != "" || strings.Contains(err.Error(), key) {
						t.Fatalf("unsafe create acknowledgment: remote=%v err=%v", remote, err)
					}
					matches, err := a.SearchTicketMarker(context.Background(), "SEC", "10001", "synapse-intent-item-1")
					if !errors.As(err, &providerErr) || providerErr.Code != "invalid_search_response" || len(matches) != 0 || calls != 2 || strings.Contains(err.Error(), key) {
						t.Fatalf("unsafe search candidate: matches=%v err=%v calls=%d", matches, err, calls)
					}
				})
			}
		})
	}
}

func TestDataCenterMarkerSearchRequiresCompletePagination(t *testing.T) {
	for _, body := range []string{
		`{"total":2,"startAt":0,"maxResults":2,"issues":[{"key":"SEC-9"}]}`,
		`{"total":1,"startAt":0,"maxResults":2,"issues":[]}`,
		`{"startAt":0,"maxResults":2,"issues":[]}`,
		`{"total":0,"maxResults":2,"issues":[]}`,
		`{"total":0,"startAt":0,"issues":[]}`,
		`{"total":-1,"startAt":0,"maxResults":2,"issues":[]}`,
		`{"total":1,"startAt":1,"maxResults":2,"issues":[{"key":"SEC-9"}]}`,
		`{"total":1,"startAt":0,"maxResults":0,"issues":[{"key":"SEC-9"}]}`,
		`{"total":0,"startAt":0,"maxResults":-1,"issues":[]}`,
	} {
		t.Run(body, func(t *testing.T) {
			calls := 0
			a := testAdapter(t, false, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Path != "/jira/rest/api/2/search" {
					t.Errorf("unexpected candidate verification: %s", r.URL.Path)
				}
				return response(http.StatusOK, body, nil), nil
			})
			matches, err := a.SearchTicketMarker(context.Background(), "SEC", "10001", "synapse-intent-item-1")
			var providerErr *ports.TicketProviderError
			if !errors.As(err, &providerErr) || providerErr.Code != "search_truncated" || len(matches) != 0 || calls != 1 {
				t.Fatalf("incomplete search: matches=%v err=%v calls=%d", matches, err, calls)
			}
		})
	}
	for _, count := range []int{0, 1, 2} {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			issues := make([]map[string]string, count)
			for i := range issues {
				issues[i] = map[string]string{"key": "SEC-" + string(rune('1'+i))}
			}
			body, err := json.Marshal(map[string]any{"total": count, "startAt": 0, "maxResults": 2, "issues": issues})
			if err != nil {
				t.Fatal(err)
			}
			a := testAdapter(t, false, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/jira/rest/api/2/search" {
					return response(http.StatusOK, string(body), nil), nil
				}
				return response(http.StatusOK, `{"fields":{"labels":["synapse-intent-item-1"],"project":{"key":"SEC"},"issuetype":{"id":"10001"}}}`, nil), nil
			})
			matches, err := a.SearchTicketMarker(context.Background(), "SEC", "10001", "synapse-intent-item-1")
			if err != nil || len(matches) != count {
				t.Fatalf("complete search: matches=%v err=%v", matches, err)
			}
		})
	}
}

func TestTicketPayloadValidationBlocksCredentialsBeforeAnyPost(t *testing.T) {
	posts := 0
	a := testAdapter(t, true, func(*http.Request) (*http.Response, error) {
		posts++
		return response(http.StatusCreated, `{"key":"SEC-1"}`, nil), nil
	})
	basic := base64.StdEncoding.EncodeToString([]byte("person@example.test:secret-token"))
	for _, payload := range []json.RawMessage{
		[]byte(`{"fields":{"summary":"secret-token"}}`),
		[]byte(`{"fields":{"customfield_1":"secret\u002dtoken"}}`),
		[]byte(`{"fields":{"customfield_1":"secret%2Dtoken"}}`),
		[]byte(`{"secret-token":"safe"}`),
		[]byte(`{"fields":{"summary":"person@example.test"}}`),
		[]byte(`{"fields":{"summary":"Basic ` + basic + `"}}`),
	} {
		if err := a.ValidateTicketPayload(payload); err == nil {
			t.Fatal("credential payload passed validation")
		} else if strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), basic) {
			t.Fatalf("validation error reflected credential: %v", err)
		}
		if _, err := a.CreateTicket(context.Background(), payload); err == nil {
			t.Fatal("credential payload reached create")
		}
	}
	if posts != 0 {
		t.Fatalf("credential payloads sent %d POSTs", posts)
	}
	if err := a.ValidateTicketPayload(json.RawMessage(`{"fields":{"summary":"safe","customfield_1":"normal value"}}`)); err != nil {
		t.Fatalf("normal payload validation: %v", err)
	}
	tooLarge := json.RawMessage(`"` + strings.Repeat("x", maxTicketPayloadBytes) + `"`)
	if err := a.ValidateTicketPayload(tooLarge); err == nil {
		t.Fatal("oversized valid JSON payload passed validation")
	}
	if _, err := a.CreateTicket(context.Background(), json.RawMessage(`{"fields":{"summary":"safe"}}`)); err != nil || posts != 1 {
		t.Fatalf("normal payload post err=%v posts=%d", err, posts)
	}
}

func TestRetryAfterPreservesLongServerBackoff(t *testing.T) {
	now := time.Date(2026, time.October, 14, 0, 0, 0, 0, time.UTC)
	if got := parseRetryAfterAt("172800", now); got != 48*time.Hour {
		t.Fatalf("two-day retry-after = %s", got)
	}
	if got := parseRetryAfterAt("not-a-delay", now); got != defaultRetryAfter {
		t.Fatalf("invalid retry-after = %s", got)
	}
	if got := parseRetryAfterAt("", now); got != defaultRetryAfter {
		t.Fatalf("missing retry-after = %s", got)
	}
	if got := parseRetryAfterAt("0", now); got != 0 {
		t.Fatalf("zero retry-after = %s", got)
	}
	when := now.Add(49*time.Hour + 17*time.Second).Format(http.TimeFormat)
	if got := parseRetryAfterAt(when, now); got != 49*time.Hour+17*time.Second {
		t.Fatalf("HTTP-date retry-after = %s", got)
	}
	if got := parseRetryAfterAt("18446744073709551615", now); got != maxRetryAfter {
		t.Fatalf("overflow retry-after = %s", got)
	}
}

func TestFormatAndDCContract(t *testing.T) {
	cloud := testAdapter(t, true, func(*http.Request) (*http.Response, error) { return response(200, `{}`, nil), nil })
	if description, err := cloud.FormatTicketDescription("{macro} *literal*", nil); err != nil || !strings.Contains(string(description), `"type":"doc"`) {
		t.Fatalf("cloud format = %s, %v", description, err)
	}
	dc := testAdapter(t, false, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/jira/rest/api/2/myself" || r.Header.Get("Authorization") != "Bearer secret-token" {
			t.Errorf("DC request %s %q", r.URL, r.Header.Get("Authorization"))
		}
		return response(200, `{"name":"operator"}`, nil), nil
	})
	if err := dc.TestConnection(context.Background()); err != nil {
		t.Fatal(err)
	}
	if description, err := dc.FormatTicketDescription("{macro}", nil); err != nil || strings.Contains(string(description), "{macro}") {
		t.Fatalf("DC wiki escaped text = %s, %v", description, err)
	}
}

func TestDiscoverMetadataPaginationAndTruncation(t *testing.T) {
	calls := 0
	a := testAdapter(t, true, func(r *http.Request) (*http.Response, error) {
		calls++
		switch calls {
		case 1:
			if r.URL.Path != "/rest/api/3/project/search" {
				t.Errorf("project path %s", r.URL.Path)
			}
			return response(200, `{"values":[{"id":"10","key":"SEC","name":"Security"}],"isLast":true,"total":1}`, nil), nil
		case 2:
			if r.URL.Path != "/rest/api/3/issue/createmeta/SEC/issuetypes" {
				t.Errorf("type path %s", r.URL.Path)
			}
			if r.URL.Query().Get("startAt") != "0" {
				t.Errorf("first type page %s", r.URL)
			}
			// Cloud documents issueTypes here, rather than the older values array.
			return response(200, `{"issueTypes":[{"id":"10001","name":"Bug"}],"isLast":false,"total":2}`, nil), nil
		case 3:
			if r.URL.Query().Get("startAt") != "1" {
				t.Errorf("trailing type page %s", r.URL)
			}
			return response(200, `{"issueTypes":[{"id":"10002","name":"Task"}],"isLast":true,"total":2}`, nil), nil
		case 4:
			if r.URL.Path != "/rest/api/3/issue/createmeta/SEC/issuetypes/10001" || r.URL.Query().Get("startAt") != "0" {
				t.Errorf("first field page %s", r.URL)
			}
			return response(200, `{"fields":[{"fieldId":"security","key":"security","name":"Security Level","required":false,"hasDefaultValue":true,"schema":{"type":"option"},"allowedValues":[{"id":"7","name":"Internal"}]},{"fieldId":"priority","key":"priority","name":"Priority","required":false,"schema":{"type":"priority"},"allowedValues":[{"id":"3","name":"High"}]},{"fieldId":"components","key":"components","name":"Components","required":false,"schema":{"type":"array","items":"component"},"allowedValues":[{"id":"8","name":"Platform"}]}],"isLast":false,"total":5}`, nil), nil
		case 5:
			if r.URL.Query().Get("startAt") != "3" {
				t.Errorf("trailing field page %s", r.URL)
			}
			return response(200, `{"values":[{"fieldId":"customfield_security","key":"customfield_security","name":"Security Level","required":false,"schema":{"type":"option"},"allowedValues":[{"id":"not-security","name":"Custom"}]},{"fieldId":"customfield_1","key":"customfield_1","name":"Owning team","required":true,"hasDefaultValue":false,"schema":{"type":"array","items":"option"},"allowedValues":[{"id":"team-a","value":"Platform"}]}],"isLast":true,"total":5}`, nil), nil
		default:
			t.Fatalf("undocumented metadata request %s", r.URL)
			return nil, nil
		}
	})
	metadata, err := a.DiscoverTickets(context.Background(), "SEC", "10001", "")
	if err != nil || calls != 5 || len(metadata.Projects) != 1 || len(metadata.IssueTypes) != 2 || len(metadata.Fields) != 5 || len(metadata.SecurityLevels) != 1 || len(metadata.Priorities) != 1 || len(metadata.Components) != 1 {
		t.Fatalf("metadata=%+v calls=%d err=%v", metadata, calls, err)
	}
	if metadata.Fields[0].ID != "security" || !metadata.Fields[0].HasDefault || metadata.Fields[0].Type != "option" || metadata.Priorities[0].ID != "3" || metadata.Components[0].ID != "8" || metadata.SecurityLevels[0].ID != "7" {
		t.Fatalf("field metadata = %#v", metadata.Fields)
	}

	truncated := testAdapter(t, true, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/rest/api/3/project/search" {
			return response(500, `{}`, nil), nil
		}
		return response(200, `{"values":[],"isLast":false,"total":1001}`, nil), nil
	})
	_, err = truncated.DiscoverTickets(context.Background(), "", "", "")
	var providerErr *ports.TicketProviderError
	if !errors.As(err, &providerErr) || providerErr.Code != "metadata_truncated" {
		t.Fatalf("truncated metadata = %v", err)
	}
}

func TestDiscoverMetadataUsesCreateMetadataChoicesWithoutInventedPriorityRoute(t *testing.T) {
	inventedRoute := false
	a := testAdapter(t, true, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/rest/api/3/project/search":
			return response(http.StatusOK, `{"values":[{"id":"10","key":"SEC","name":"Security"}],"isLast":true,"total":1}`, nil), nil
		case "/rest/api/3/issue/createmeta/SEC/issuetypes":
			return response(http.StatusOK, `{"issueTypes":[{"id":"10001","name":"Bug"}],"isLast":true,"total":1}`, nil), nil
		case "/rest/api/3/issue/createmeta/SEC/issuetypes/10001":
			return response(http.StatusOK, `{"fields":[{"fieldId":"priority","name":"Priority","schema":{"type":"priority"},"allowedValues":[{"id":"3","name":"High"}]},{"fieldId":"security","name":"Security Level","schema":{"type":"option"},"allowedValues":[{"id":"7","name":"Internal"}]}],"isLast":true,"total":2}`, nil), nil
		case "/rest/api/3/project/SEC/priorities":
			inventedRoute = true
			return response(http.StatusNotFound, `{}`, nil), nil
		default:
			t.Fatalf("unexpected metadata route %s", r.URL.Path)
			return nil, nil
		}
	})
	metadata, err := a.DiscoverTickets(context.Background(), "SEC", "10001", "")
	if err != nil || inventedRoute || len(metadata.Priorities) != 1 || metadata.Priorities[0].ID != "3" || len(metadata.SecurityLevels) != 1 {
		t.Fatalf("metadata=%+v invented=%t err=%v", metadata, inventedRoute, err)
	}
}

func TestDataCenterRequiredReporterResolvesAuthenticatedIdentity(t *testing.T) {
	calls := 0
	a := testAdapter(t, false, func(r *http.Request) (*http.Response, error) {
		calls++
		switch calls {
		case 1:
			if r.URL.Path != "/jira/rest/api/2/project" {
				t.Errorf("project request %s", r.URL)
			}
			return response(http.StatusOK, `[{"id":"1","key":"SEC","name":"Security"}]`, nil), nil
		case 2:
			if r.URL.Path != "/jira/rest/api/2/issue/createmeta/SEC/issuetypes" {
				t.Errorf("issue type request %s", r.URL)
			}
			return response(http.StatusOK, `{"values":[{"id":"100","name":"Task"}],"isLast":true,"total":1}`, nil), nil
		case 3:
			if r.URL.Path != "/jira/rest/api/2/issue/createmeta/SEC/issuetypes/100" {
				t.Errorf("field request %s", r.URL)
			}
			return response(http.StatusOK, `{"values":[{"fieldId":"reporter","name":"Reporter","required":true,"hasDefaultValue":false,"schema":{"type":"user"}}],"isLast":true,"total":1}`, nil), nil
		case 4:
			if r.URL.Path != "/jira/rest/api/2/myself" || r.Header.Get("Authorization") != "Bearer secret-token" {
				t.Errorf("identity request %s %q", r.URL, r.Header.Get("Authorization"))
			}
			return response(http.StatusOK, `{"name":"sandbox-admin"}`, nil), nil
		default:
			t.Fatalf("unexpected request %s", r.URL)
			return nil, nil
		}
	})
	metadata, err := a.DiscoverTickets(context.Background(), "SEC", "100", "")
	if err != nil || calls != 4 || metadata.ResolvedReporter != "sandbox-admin" {
		t.Fatalf("metadata=%+v calls=%d err=%v", metadata, calls, err)
	}
}

func TestDataCenterReporterIdentityRefusalStopsMetadataBeforeAnyCreate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "credential_reflection", status: http.StatusOK, body: `{"name":"secret-token"}`},
		{name: "missing_name", status: http.StatusOK, body: `{}`},
		{name: "identity_request_error", status: http.StatusUnauthorized, body: `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			posts := 0
			calls := 0
			a := testAdapter(t, false, func(r *http.Request) (*http.Response, error) {
				if r.Method == http.MethodPost {
					posts++
				}
				calls++
				switch calls {
				case 1:
					return response(http.StatusOK, `[{"id":"1","key":"SEC","name":"Security"}]`, nil), nil
				case 2:
					return response(http.StatusOK, `{"values":[{"id":"100","name":"Task"}],"isLast":true,"total":1}`, nil), nil
				case 3:
					return response(http.StatusOK, `{"values":[{"fieldId":"reporter","name":"Reporter","required":true,"hasDefaultValue":false,"schema":{"type":"user"}}],"isLast":true,"total":1}`, nil), nil
				case 4:
					return response(tc.status, tc.body, nil), nil
				default:
					t.Fatalf("unexpected request %s", r.URL)
					return nil, nil
				}
			})
			_, err := a.DiscoverTickets(context.Background(), "SEC", "100", "")
			var providerErr *ports.TicketProviderError
			if !errors.As(err, &providerErr) || posts != 0 || strings.Contains(err.Error(), "secret-token") {
				t.Fatalf("err=%v posts=%d", err, posts)
			}
		})
	}
}

func TestReporterDiscoveryLeavesCloudAndDefaultedReporterUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cloud bool
		field string
	}{
		{name: "cloud", cloud: true, field: `{"fieldId":"reporter","name":"Reporter","required":true,"hasDefaultValue":false,"schema":{"type":"user"}}`},
		{name: "dc_default", field: `{"fieldId":"reporter","name":"Reporter","required":true,"hasDefaultValue":true,"schema":{"type":"user"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			myselfCalls := 0
			a := testAdapter(t, tc.cloud, func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "/myself") {
					myselfCalls++
					return response(http.StatusInternalServerError, `{}`, nil), nil
				}
				if tc.cloud {
					switch r.URL.Path {
					case "/rest/api/3/project/search":
						return response(http.StatusOK, `{"values":[{"id":"1","key":"SEC","name":"Security"}],"isLast":true,"total":1}`, nil), nil
					case "/rest/api/3/issue/createmeta/SEC/issuetypes":
						return response(http.StatusOK, `{"issueTypes":[{"id":"100","name":"Task"}],"isLast":true,"total":1}`, nil), nil
					case "/rest/api/3/issue/createmeta/SEC/issuetypes/100":
						return response(http.StatusOK, `{"fields":[`+tc.field+`],"isLast":true,"total":1}`, nil), nil
					}
				} else {
					switch r.URL.Path {
					case "/jira/rest/api/2/project":
						return response(http.StatusOK, `[{"id":"1","key":"SEC","name":"Security"}]`, nil), nil
					case "/jira/rest/api/2/issue/createmeta/SEC/issuetypes":
						return response(http.StatusOK, `{"values":[{"id":"100","name":"Task"}],"isLast":true,"total":1}`, nil), nil
					case "/jira/rest/api/2/issue/createmeta/SEC/issuetypes/100":
						return response(http.StatusOK, `{"values":[`+tc.field+`],"isLast":true,"total":1}`, nil), nil
					}
				}
				t.Fatalf("unexpected request %s", r.URL)
				return nil, nil
			})
			metadata, err := a.DiscoverTickets(context.Background(), "SEC", "100", "")
			if err != nil || myselfCalls != 0 || metadata.ResolvedReporter != "" {
				t.Fatalf("metadata=%+v myself=%d err=%v", metadata, myselfCalls, err)
			}
		})
	}
}

func TestCreateMetadataPageLimitAndCloudDoesNotUseLegacyFallback(t *testing.T) {
	calls := 0
	bounded := testAdapter(t, true, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/rest/api/3/issue/createmeta/SEC/issuetypes" {
			t.Errorf("unexpected request %s", r.URL)
		}
		return response(200, `{"issueTypes":[{"id":"100","name":"Bug"}],"isLast":false,"total":21}`, nil), nil
	})
	_, err := bounded.pagedIssueTypes(context.Background(), "SEC")
	var providerErr *ports.TicketProviderError
	if !errors.As(err, &providerErr) || providerErr.Code != "metadata_truncated" || calls != maxPages {
		t.Fatalf("unbounded pages err=%v calls=%d", err, calls)
	}

	cloudCalls := 0
	cloud := testAdapter(t, true, func(r *http.Request) (*http.Response, error) {
		cloudCalls++
		if r.URL.Path == "/rest/api/3/issue/createmeta" {
			t.Fatal("Cloud used the deprecated legacy createmeta endpoint")
		}
		return response(http.StatusNotFound, `{}`, nil), nil
	})
	_, _, err = cloud.createMetadata(context.Background(), "SEC", "100")
	if !errors.As(err, &providerErr) || providerErr.Status != http.StatusNotFound || cloudCalls != 1 {
		t.Fatalf("Cloud metadata fallback err=%v calls=%d", err, cloudCalls)
	}
}

func TestCreateTimeoutAndDuplicateSearchRemainUncertainOrRejected(t *testing.T) {
	timedOut := testAdapter(t, true, func(*http.Request) (*http.Response, error) { return nil, context.DeadlineExceeded })
	_, err := timedOut.CreateTicket(context.Background(), []byte(`{}`))
	var providerErr *ports.TicketProviderError
	if !errors.As(err, &providerErr) || !providerErr.Ambiguous || providerErr.Code != "network" {
		t.Fatalf("timeout create = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = timedOut.CreateTicket(canceled, []byte(`{}`))
	if !errors.As(err, &providerErr) || !providerErr.Ambiguous || providerErr.Code != "network" {
		t.Fatalf("canceled create = %v", err)
	}

	duplicate := testAdapter(t, true, func(*http.Request) (*http.Response, error) {
		return response(200, `{"total":3,"issues":[]}`, nil), nil
	})
	_, err = duplicate.SearchTicketMarker(context.Background(), "SEC", "10001", "synapse-intent-item-1")
	if !errors.As(err, &providerErr) || providerErr.Code != "search_truncated" {
		t.Fatalf("duplicate marker search = %v", err)
	}
}

func TestMetadataDoesNotReflectCredentials(t *testing.T) {
	a := testAdapter(t, true, func(*http.Request) (*http.Response, error) {
		return response(200, `{"values":[{"id":"SEC","key":"SEC","name":"secret-token"}],"isLast":true,"total":1}`, nil), nil
	})
	_, err := a.DiscoverTickets(context.Background(), "", "", "")
	var providerErr *ports.TicketProviderError
	if !errors.As(err, &providerErr) || providerErr.Code != "unsafe_provider_response" || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("credential reflection = %v", err)
	}
}

func TestEncodedCredentialsCannotReachPayloadOrMetadata(t *testing.T) {
	secret := []byte("secret-token")
	forms := []string{
		base64.StdEncoding.EncodeToString(secret),
		base64.RawStdEncoding.EncodeToString(secret),
		base64.URLEncoding.EncodeToString(secret),
		base64.RawURLEncoding.EncodeToString(secret),
		hex.EncodeToString(secret),
		strings.ToUpper(hex.EncodeToString(secret)),
	}
	for _, cloud := range []bool{true, false} {
		for index, form := range forms {
			posts := 0
			a := testAdapter(t, cloud, func(*http.Request) (*http.Response, error) {
				posts++
				return response(http.StatusCreated, `{"key":"SEC-1"}`, nil), nil
			})
			payload, err := json.Marshal(map[string]any{"fields": map[string]string{"summary": form}})
			if err != nil {
				t.Fatal(err)
			}
			if err = a.ValidateTicketPayload(payload); err == nil {
				t.Fatalf("cloud=%t form=%d admitted encoded credential", cloud, index)
			}
			if _, err = a.CreateTicket(context.Background(), payload); err == nil || posts != 0 {
				t.Fatalf("cloud=%t form=%d credential reached POST", cloud, index)
			}
			projects := []map[string]string{{"id": "100", "key": "SEC", "name": form}}
			var metadata []byte
			if cloud {
				metadata, err = json.Marshal(map[string]any{"values": projects, "isLast": true, "total": 1})
			} else {
				metadata, err = json.Marshal(projects)
			}
			if err != nil {
				t.Fatal(err)
			}
			a = testAdapter(t, cloud, func(*http.Request) (*http.Response, error) {
				return response(http.StatusOK, string(metadata), nil), nil
			})
			_, err = a.DiscoverTickets(context.Background(), "", "", "")
			var providerErr *ports.TicketProviderError
			if !errors.As(err, &providerErr) || providerErr.Code != "unsafe_provider_response" || strings.Contains(err.Error(), form) {
				t.Fatalf("cloud=%t form=%d unsafe metadata error=%v", cloud, index, err)
			}
		}
	}
}

func TestDataCenterCreateMetaModernThenLegacyCompatibility(t *testing.T) {
	calls := 0
	modern := testAdapter(t, false, func(r *http.Request) (*http.Response, error) {
		calls++
		switch calls {
		case 1:
			if r.URL.Path != "/jira/rest/api/2/issue/createmeta/SEC/issuetypes" {
				t.Errorf("modern type request %s", r.URL)
			}
			return response(200, `{"values":[{"id":"100","name":"Bug"}],"isLast":true,"total":1}`, nil), nil
		case 2:
			if r.URL.Path != "/jira/rest/api/2/issue/createmeta/SEC/issuetypes/100" {
				t.Errorf("modern field request %s", r.URL)
			}
			return response(200, `{"values":[{"fieldId":"customfield_1","name":"Owning team","required":true,"hasDefaultValue":true,"schema":{"type":"option"},"allowedValues":[{"id":"team-a","value":"Platform"}]}],"isLast":true,"total":1}`, nil), nil
		default:
			return response(500, `{}`, nil), nil
		}
	})
	types, fields, err := modern.createMetadata(context.Background(), "SEC", "100")
	if err != nil || calls != 2 || len(types) != 1 || len(fields) != 1 || fields[0].ID != "customfield_1" || !fields[0].HasDefault {
		t.Fatalf("modern metadata: %#v %#v %v calls=%d", types, fields, err, calls)
	}

	legacyCalls := 0
	legacy := testAdapter(t, false, func(r *http.Request) (*http.Response, error) {
		legacyCalls++
		if legacyCalls == 1 {
			return response(http.StatusNotFound, `{}`, nil), nil
		}
		if r.URL.Path != "/jira/rest/api/2/issue/createmeta" || r.URL.Query().Get("expand") != "projects.issuetypes.fields" {
			t.Errorf("legacy fallback request %s", r.URL)
		}
		return response(200, `{"projects":[{"issuetypes":[{"id":"100","name":"Bug","fields":{"customfield_1":{"name":"Owning team","required":true,"hasDefaultValue":true,"schema":{"type":"option"},"allowedValues":[{"id":"team-a","value":"Platform"}]}}}]}]}`, nil), nil
	})
	types, fields, err = legacy.createMetadata(context.Background(), "SEC", "100")
	if err != nil || legacyCalls != 2 || len(types) != 1 || len(fields) != 1 || fields[0].ID != "customfield_1" || !fields[0].HasDefault {
		t.Fatalf("legacy metadata: %#v %#v %v calls=%d", types, fields, err, legacyCalls)
	}

	mapCalls := 0
	legacyFieldMap := testAdapter(t, false, func(r *http.Request) (*http.Response, error) {
		mapCalls++
		switch mapCalls {
		case 1:
			return response(200, `{"values":[{"id":"100","name":"Bug"}],"isLast":true,"total":1}`, nil), nil
		case 2:
			// Some older DC nodes expose fields as the original field-ID map at
			// the detail path. It is unpaged, but must retain schema metadata.
			return response(200, `{"fields":{"customfield_2":{"name":"Business impact","required":true,"hasDefaultValue":true,"schema":{"type":"array","items":"string"},"allowedValues":[{"id":"critical","name":"Critical"}]}}}`, nil), nil
		default:
			return response(500, `{}`, nil), nil
		}
	})
	types, fields, err = legacyFieldMap.createMetadata(context.Background(), "SEC", "100")
	if err != nil || mapCalls != 2 || len(types) != 1 || len(fields) != 1 || fields[0].ID != "customfield_2" || fields[0].Type != "array" || fields[0].ItemType != "string" || !fields[0].HasDefault {
		t.Fatalf("legacy field map: %#v %#v %v calls=%d", types, fields, err, mapCalls)
	}
}
