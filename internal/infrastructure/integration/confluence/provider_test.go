package confluence

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testAdapter(t *testing.T, cloud bool, main, policy transport) *Adapter {
	t.Helper()
	return testAdapterWithCloudV2(t, cloud, main, policy, transport(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/restriction-state"):
			return response(200, `{"state":"VIEW_RESTRICTED"}`), nil
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/permissions"):
			return response(200, `{"results":[{"operation":"update","principal":{"principalType":"group","principalId":"synapse-readers"}}],"_links":{}}`), nil
		case r.Method == http.MethodPut:
			return response(200, `{}`), nil
		default:
			t.Fatalf("unexpected Cloud V2 request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	}))
}

func testAdapterWithCloudV2(t *testing.T, cloud bool, main, policy, cloudV2 transport) *Adapter {
	t.Helper()
	if cloud {
		mainTransport := main
		main = transport(func(r *http.Request) (*http.Response, error) {
			if strings.HasPrefix(r.URL.Path, "/wiki/api/v2/pages/") && (strings.HasSuffix(r.URL.Path, "/permissions") || strings.HasSuffix(r.URL.Path, "/restriction-state")) {
				return cloudV2(r)
			}
			return mainTransport(r)
		})
	}
	base, err := url.Parse("https://space.atlassian.net")
	if err != nil {
		t.Fatal(err)
	}
	if !cloud {
		base, err = url.Parse("https://confluence.example.test/confluence")
		if err != nil {
			t.Fatal(err)
		}
	}
	client := &http.Client{Transport: main, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	policyClient := &http.Client{Transport: policy, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Adapter{base: base, client: client, policy: policyClient, cloud: cloud, email: "person@example.test", token: "secret-token", orgKey: "org-secret", orgID: "org-1", siteARI: "ari:cloud:confluence::site/11111111-1111-1111-1111-111111111111", policyID: "policy-1", space: "SIL", readGroup: "synapse-readers"}
}

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
}

func content(id, title, storage string, version int) string {
	return `{"id":"` + id + `","title":"` + title + `","status":"current","space":{"key":"SIL"},"version":{"number":` + stringInt(version) + `},"body":{"storage":{"value":` + jsonString(storage) + `}},"_links":{"webui":"/spaces/SIL/pages/` + id + `"}}`
}
func stringInt(v int) string {
	if v == 1 {
		return "1"
	}
	if v == 2 {
		return "2"
	}
	return "3"
}
func jsonString(v string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `"`, `\"`) + `"`
}

// policyResourceResponse mirrors the documented Admin Control resource envelope.
// It deliberately includes nullable presentation fields returned by the live API.
func policyResourceResponse(resourceID, status string) string {
	return `{"type":"resource","id":"resource-1","attributes":{"resourceId":` + jsonString(resourceID) + `,"applicationStatus":` + jsonString(status) + `},"links":null,"message":null}`
}

func exactRestriction(operation, group string, cloud bool) string {
	principal := `{"name":` + jsonString(group) + `}`
	if cloud {
		principal = `{"id":` + jsonString(group) + `}`
	}
	return `{"operation":` + jsonString(operation) + `,"restrictions":{"group":{"size":1,"results":[` + principal + `]},"user":{"size":0,"results":[]}}}`
}

func emptyRestriction(operation string) string {
	return `{"operation":` + jsonString(operation) + `,"restrictions":{"group":{"size":0,"results":[]},"user":{"size":0,"results":[]}}}`
}
func providerCode(t *testing.T, err error) *ports.DocumentProviderError {
	t.Helper()
	var got *ports.DocumentProviderError
	if !errors.As(err, &got) {
		t.Fatalf("error %T %v", err, err)
	}
	return got
}

func TestRegisterAndEndpointPolicy(t *testing.T) {
	registry := integration.NewRegistry()
	if err := Register(registry); err != nil {
		t.Fatal(err)
	}
	for _, provider := range []integration.Provider{CloudProvider, DCProvider} {
		d, err := registry.Descriptor(provider)
		if err != nil || !d.Supports(integration.CapabilityTestConnection) {
			t.Fatalf("descriptor %q: %+v %v", provider, d, err)
		}
	}
	cloud := integration.Integration{ID: "cloud", TenantID: "tenant", Name: "cloud", Provider: CloudProvider, Version: 1, Endpoint: "https://unit.atlassian.net", Config: []byte(`{"space":"SIL","read_group":"synapse-readers","data_class":"detail"}`)}
	if _, err := New(cloud, integration.CredentialBundle{"email": "p@example.test", "api_token": "secret"}, selfhosted.Rules{}); err != nil {
		t.Fatalf("cloud: %v", err)
	}
	for _, endpoint := range []string{"https://atlassian.net", "https://unit.atlassian.net/wiki", "https://evil.example"} {
		cloud.Endpoint = endpoint
		if _, err := New(cloud, integration.CredentialBundle{"email": "p@example.test", "api_token": "secret"}, selfhosted.Rules{}); err == nil {
			t.Errorf("accepted cloud endpoint %q", endpoint)
		}
	}
	cloud.Endpoint = "https://unit.atlassian.net"
	cloud.Config = []byte(`{"space":"SIL","read_group":"synapse-readers","data_class":"internal"}`)
	if _, err := New(cloud, integration.CredentialBundle{"email": "p@example.test", "api_token": "secret"}, selfhosted.Rules{}); err == nil {
		t.Fatal("accepted non-detail data class")
	}
	dc := integration.Integration{ID: "dc", TenantID: "tenant", Name: "dc", Provider: DCProvider, Version: 1, Endpoint: "https://confluence.example.test/confluence", Config: []byte(`{"space":"SIL","read_group":"synapse-readers","data_class":"detail"}`)}
	if _, err := New(dc, integration.CredentialBundle{"pat": "secret"}, selfhosted.Rules{}); err == nil {
		t.Fatal("accepted unallowlisted DC")
	}
	hosts, err := selfhosted.ParseHostAllowlist([]string{"confluence.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(dc, integration.CredentialBundle{"pat": "secret"}, selfhosted.Rules{Hosts: hosts}); err != nil {
		t.Fatalf("DC: %v", err)
	}
}

func TestRestrictionWriteUsesDocumentedArrayAndProviderGroupIdentity(t *testing.T) {
	for _, cloud := range []bool{true, false} {
		t.Run(map[bool]string{true: "cloud", false: "dc"}[cloud], func(t *testing.T) {
			storage := neutralShellStorage("synapse-intent-a")
			writes := 0
			cloudWrites := 0
			main := transport(func(r *http.Request) (*http.Response, error) {
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/content/1"):
					return response(200, content("1", neutralShellTitle("synapse-intent-a"), storage, 1)), nil
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/content/1/restriction/byOperation/read"):
					return response(200, `{"operation":"read","restrictions":{"group":{"size":0,"results":[]},"user":{"size":0,"results":[]}}}`), nil
				case !strings.HasSuffix(r.URL.Path, "/content/1/restriction"):
					t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				wantMethod := http.MethodPut
				if cloud {
					wantMethod = http.MethodPost
				}
				if r.Method != wantMethod {
					t.Fatalf("method=%s want=%s", r.Method, wantMethod)
				}
				writes++
				var body []struct {
					Operation    string `json:"operation"`
					Restrictions struct {
						Group []map[string]string  `json:"group"`
						User  *[]map[string]string `json:"user"`
					} `json:"restrictions"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 1 || body[0].Operation != "read" || len(body[0].Restrictions.Group) != 1 {
					t.Fatalf("invalid restriction array: %+v %v", body, err)
				}
				key, absent := "name", "id"
				if cloud {
					key, absent = "id", "name"
				}
				group := body[0].Restrictions.Group[0]
				if group[key] != "synapse-readers" || group[absent] != "" || group["type"] != "group" {
					t.Fatalf("wrong provider group identity: %v", group)
				}
				if cloud && body[0].Restrictions.User != nil {
					t.Fatalf("Cloud body unexpectedly changes direct users: %v", *body[0].Restrictions.User)
				}
				if !cloud && (body[0].Restrictions.User == nil || len(*body[0].Restrictions.User) != 0) {
					t.Fatalf("DC body must explicitly clear direct read users: %v", body[0].Restrictions.User)
				}
				return response(200, `{}`), nil
			})
			cloudV2 := transport(func(r *http.Request) (*http.Response, error) {
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/restriction-state"):
					return response(200, `{"state":"OPEN"}`), nil
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/permissions"):
					return response(200, `{"results":[],"_links":{}}`), nil
				case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/permissions"):
					cloudWrites++
					if r.URL.RawQuery != "" {
						t.Fatalf("Cloud V2 permissions must retain default self-lockout protection: %q", r.URL.RawQuery)
					}
					var body struct {
						Permissions []struct {
							Operation  string `json:"operation"`
							Principals []struct {
								Type string `json:"principalType"`
								ID   string `json:"principalId"`
							} `json:"principals"`
						} `json:"permissions"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Permissions) != 1 || body.Permissions[0].Operation != "update" || len(body.Permissions[0].Principals) != 1 || body.Permissions[0].Principals[0].Type != "group" || body.Permissions[0].Principals[0].ID != "synapse-readers" {
						t.Fatalf("invalid Cloud V2 permission replacement: %+v %v", body, err)
					}
					return response(200, `{}`), nil
				case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/restriction-state"):
					cloudWrites++
					var body map[string]string
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["state"] != "VIEW_RESTRICTED" || len(body) != 1 {
						t.Fatalf("invalid Cloud V2 restriction state: %+v %v", body, err)
					}
					return response(200, `{}`), nil
				default:
					t.Fatalf("unexpected Cloud V2 request %s %s", r.Method, r.URL.Path)
					return nil, nil
				}
			})
			a := testAdapterWithCloudV2(t, cloud, main, transport(func(*http.Request) (*http.Response, error) {
				t.Fatal("policy consulted before exact ACL verified")
				return nil, nil
			}), cloudV2)
			if err := a.RestrictDocument(context.Background(), "1", "synapse-readers"); err != nil {
				t.Fatal(err)
			}
			if !cloud && writes != 1 {
				t.Fatalf("writes=%d", writes)
			}
			if cloud && cloudWrites != 2 {
				t.Fatalf("Cloud V2 writes=%d", cloudWrites)
			}
			if got := providerCode(t, a.VerifyDocumentRestriction(context.Background(), "1", "SIL", "synapse-readers")); got.Code != "restriction_unverified" {
				t.Fatalf("%+v", got)
			}
		})
	}
}

func TestRestrictDocumentSkipsWriteWhenCurrentACLAlreadyVerifies(t *testing.T) {
	for _, cloud := range []bool{true, false} {
		t.Run(map[bool]string{true: "cloud", false: "dc"}[cloud], func(t *testing.T) {
			storage := neutralShellStorage("synapse-intent-a")
			main := transport(func(r *http.Request) (*http.Response, error) {
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/content/1"):
					return response(200, content("1", neutralShellTitle("synapse-intent-a"), storage, 1)), nil
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/content/1/restriction/byOperation/read"):
					return response(200, exactRestriction("read", "synapse-readers", cloud)), nil
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/content/1/restriction/byOperation/update"):
					return response(200, emptyRestriction("update")), nil
				case cloud && r.Method == http.MethodGet && r.URL.Path == "/_edge/tenant_info":
					return response(200, `{"cloudId":"11111111-1111-1111-1111-111111111111"}`), nil
				case r.Method == http.MethodPost:
					t.Fatal("restriction write issued after current ACL was verified")
				}
				return response(500, "{}"), nil
			})
			policy := transport(func(*http.Request) (*http.Response, error) {
				t.Fatal("Data Center must not consult Cloud policy")
				return nil, nil
			})
			if cloud {
				org := `{"id":"org-default","attributes":{"type":"data-security","status":"published","rule":{"publicLinks":{"effect":"allow"}},"metadata":{"policyCoverageLevel":"ORG"}}}`
				block := `{"id":"policy-1","attributes":{"type":"data-security","status":"published","rule":{"publicLinks":{"effect":"block"}},"metadata":{"policyCoverageLevel":"WORKSPACE"}}}`
				policy = transport(func(r *http.Request) (*http.Response, error) {
					switch {
					case strings.HasSuffix(r.URL.Path, "/policies"):
						return response(200, `{"data":[`+org+`,`+block+`],"meta":{}}`), nil
					case strings.HasSuffix(r.URL.Path, "/policies/org-default"):
						return response(200, `{"data":`+org+`}`), nil
					case strings.HasSuffix(r.URL.Path, "/policies/policy-1"):
						return response(200, `{"data":`+block+`}`), nil
					case strings.HasSuffix(r.URL.Path, "/resources"):
						return response(200, `{"data":[`+policyResourceResponse("ari:cloud:confluence::site/11111111-1111-1111-1111-111111111111", "applied")+`],"meta":{}}`), nil
					}
					return response(500, "{}"), nil
				})
			}
			cloudV2 := transport(func(r *http.Request) (*http.Response, error) {
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/restriction-state"):
					return response(200, `{"state":"VIEW_RESTRICTED"}`), nil
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/permissions"):
					return response(200, `{"results":[{"operation":"update","principal":{"principalType":"group","principalId":"synapse-readers"}}],"_links":{}}`), nil
				case r.Method == http.MethodPut:
					t.Fatal("Cloud V2 mutation issued after current ACL was verified")
					return nil, nil
				default:
					t.Fatalf("unexpected Cloud V2 request %s %s", r.Method, r.URL.Path)
					return nil, nil
				}
			})
			if err := testAdapterWithCloudV2(t, cloud, main, policy, cloudV2).RestrictDocument(context.Background(), "1", "synapse-readers"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRestrictDocumentDoesNotBypassUnverifiableCloudSharing(t *testing.T) {
	storage := neutralShellStorage("synapse-intent-a")
	writes := 0
	main := transport(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/content/1"):
			return response(200, content("1", neutralShellTitle("synapse-intent-a"), storage, 1)), nil
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/content/1/restriction/byOperation/read"):
			return response(200, exactRestriction("read", "synapse-readers", true)), nil
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/content/1/restriction/byOperation/update"):
			return response(200, emptyRestriction("update")), nil
		case r.Method == http.MethodGet && r.URL.Path == "/_edge/tenant_info":
			return response(200, `{"cloudId":"11111111-1111-1111-1111-111111111111"}`), nil
		}
		return response(500, "{}"), nil
	})
	a := testAdapterWithCloudV2(t, true, main, transport(func(*http.Request) (*http.Response, error) {
		return response(500, "{}"), nil
	}), transport(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/restriction-state"):
			if writes == 2 {
				return response(200, `{"state":"VIEW_RESTRICTED"}`), nil
			}
			return response(200, `{"state":"OPEN"}`), nil
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/permissions"):
			if writes == 2 {
				return response(200, `{"results":[{"operation":"update","principal":{"principalType":"group","principalId":"synapse-readers"}}],"_links":{}}`), nil
			}
			return response(200, `{"results":[],"_links":{}}`), nil
		case r.Method == http.MethodPut && (strings.HasSuffix(r.URL.Path, "/permissions") || strings.HasSuffix(r.URL.Path, "/restriction-state")):
			writes++
			return response(200, `{}`), nil
		default:
			t.Fatalf("unexpected Cloud V2 request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	}))
	if err := a.RestrictDocument(context.Background(), "1", "synapse-readers"); err != nil {
		t.Fatal(err)
	}
	if writes != 2 {
		t.Fatalf("writes=%d", writes)
	}
	if got := providerCode(t, a.VerifyDocumentRestriction(context.Background(), "1", "SIL", "synapse-readers")); got.Code != "public_sharing_unverifiable" {
		t.Fatalf("%+v", got)
	}
}

func TestCloudV2RestrictionVerificationRequiresSingleConfiguredGroup(t *testing.T) {
	valid := `{"results":[{"operation":"update","principal":{"principalType":"group","principalId":"synapse-readers"}}],"_links":{}}`
	for name, test := range map[string]struct {
		state       string
		permissions string
		wantOK      bool
	}{
		"update-group":      {state: `{"state":"VIEW_RESTRICTED"}`, permissions: valid, wantOK: true},
		"read-group":        {state: `{"state":"VIEW_RESTRICTED"}`, permissions: strings.Replace(valid, `"update"`, `"read"`, 1), wantOK: true},
		"wrong-state":       {state: `{"state":"EDIT_RESTRICTED"}`, permissions: valid},
		"missing-state":     {state: `{}`, permissions: valid},
		"missing-results":   {state: `{"state":"VIEW_RESTRICTED"}`, permissions: `{}`},
		"null-results":      {state: `{"state":"VIEW_RESTRICTED"}`, permissions: `{"results":null,"_links":{}}`},
		"missing-links":     {state: `{"state":"VIEW_RESTRICTED"}`, permissions: `{"results":[]}`},
		"next-page":         {state: `{"state":"VIEW_RESTRICTED"}`, permissions: strings.Replace(valid, `"_links":{}`, `"_links":{"next":"more"}`, 1)},
		"extra-principal":   {state: `{"state":"VIEW_RESTRICTED"}`, permissions: `{"results":[{"operation":"update","principal":{"principalType":"group","principalId":"synapse-readers"}},{"operation":"read","principal":{"principalType":"user","principalId":"publisher"}}],"_links":{}}`},
		"wrong-principal":   {state: `{"state":"VIEW_RESTRICTED"}`, permissions: `{"results":[{"operation":"update","principal":{"principalType":"user","principalId":"publisher"}}],"_links":{}}`},
		"wrong-group":       {state: `{"state":"VIEW_RESTRICTED"}`, permissions: `{"results":[{"operation":"update","principal":{"principalType":"group","principalId":"other"}}],"_links":{}}`},
		"unknown-operation": {state: `{"state":"VIEW_RESTRICTED"}`, permissions: strings.Replace(valid, `"update"`, `"delete"`, 1)},
	} {
		t.Run(name, func(t *testing.T) {
			adapter := testAdapterWithCloudV2(t, true, transport(func(r *http.Request) (*http.Response, error) {
				t.Fatalf("unexpected V1 request %s %s", r.Method, r.URL.Path)
				return nil, nil
			}), nil, transport(func(r *http.Request) (*http.Response, error) {
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/restriction-state"):
					return response(200, test.state), nil
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/permissions"):
					if r.URL.Query().Get("limit") != "100" || len(r.URL.Query()) != 1 {
						t.Fatalf("permissions query=%q", r.URL.RawQuery)
					}
					return response(200, test.permissions), nil
				default:
					t.Fatalf("unexpected Cloud V2 request %s %s", r.Method, r.URL.Path)
					return nil, nil
				}
			}))
			err := adapter.verifyCloudV2Restriction(context.Background(), "1", "synapse-readers")
			if test.wantOK {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if got := providerCode(t, err); got.Code != "restriction_unverified" {
				t.Fatalf("%+v", got)
			}
		})
	}
}

func TestCloudV2RestrictionWriteFailuresStopAndRedact(t *testing.T) {
	for name, failure := range map[string]struct {
		permissionsStatus int
		stateStatus       int
		wantStateWrites   int
	}{
		"permissions": {permissionsStatus: http.StatusInternalServerError, wantStateWrites: 0},
		"state":       {permissionsStatus: http.StatusOK, stateStatus: http.StatusInternalServerError, wantStateWrites: 1},
	} {
		t.Run(name, func(t *testing.T) {
			storage := neutralShellStorage("synapse-intent-a")
			permissionWrites, stateWrites := 0, 0
			adapter := testAdapterWithCloudV2(t, true, transport(func(r *http.Request) (*http.Response, error) {
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/content/1"):
					return response(200, content("1", neutralShellTitle("synapse-intent-a"), storage, 1)), nil
				default:
					t.Fatalf("unexpected V1 request %s %s", r.Method, r.URL.Path)
					return nil, nil
				}
			}), nil, transport(func(r *http.Request) (*http.Response, error) {
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/restriction-state"):
					return response(200, `{"state":"OPEN"}`), nil
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/permissions"):
					return response(200, `{"results":[],"_links":{}}`), nil
				case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/permissions"):
					permissionWrites++
					return response(failure.permissionsStatus, "provider-secret"), nil
				case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/restriction-state"):
					stateWrites++
					return response(failure.stateStatus, "provider-secret"), nil
				default:
					t.Fatalf("unexpected Cloud V2 request %s %s", r.Method, r.URL.Path)
					return nil, nil
				}
			}))
			got := providerCode(t, adapter.RestrictDocument(context.Background(), "1", "synapse-readers"))
			if got.Code != "server_error" || !got.Ambiguous || strings.Contains(got.Error(), "provider-secret") {
				t.Fatalf("%+v", got)
			}
			if permissionWrites != 1 || stateWrites != failure.wantStateWrites {
				t.Fatalf("permissionWrites=%d stateWrites=%d", permissionWrites, stateWrites)
			}
		})
	}
}

func TestCloudV2RestrictionReadHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	adapter := testAdapterWithCloudV2(t, true, transport(func(*http.Request) (*http.Response, error) {
		t.Fatal("unexpected V1 request")
		return nil, nil
	}), nil, transport(func(r *http.Request) (*http.Response, error) {
		return nil, r.Context().Err()
	}))
	if err := adapter.verifyCloudV2Restriction(ctx, "1", "synapse-readers"); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func TestVerifyRestrictionRejectsForgedACLAndCloudWithoutProof(t *testing.T) {
	storage := neutralShellStorage("synapse-intent-a")
	main := transport(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/confluence/rest/api/content/1":
			return response(200, content("1", neutralShellTitle("synapse-intent-a"), storage, 1)), nil
		case "/confluence/rest/api/content/1/restriction/byOperation/read":
			return response(200, `{"operation":"read","restrictions":{"group":{"size":1,"results":[{"name":"other"}]},"user":{"size":0,"results":[]}}}`), nil
		}
		return response(500, "{}"), nil
	})
	dc := testAdapter(t, false, main, transport(func(*http.Request) (*http.Response, error) { return response(500, "{}"), nil }))
	if got := providerCode(t, dc.VerifyDocumentRestriction(context.Background(), "1", "SIL", "synapse-readers")); got.Code != "restriction_unverified" {
		t.Fatalf("%+v", got)
	}
	cloud := testAdapter(t, true, transport(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "restriction") {
			operation := "read"
			if strings.HasSuffix(r.URL.Path, "/update") {
				operation = "update"
			}
			return response(200, exactRestriction(operation, "synapse-readers", true)), nil
		}
		return response(200, content("1", neutralShellTitle("synapse-intent-a"), storage, 1)), nil
	}), transport(func(*http.Request) (*http.Response, error) { return response(500, "{}"), nil }))
	cloud.orgKey = ""
	if got := providerCode(t, cloud.VerifyDocumentRestriction(context.Background(), "1", "SIL", "synapse-readers")); got.Code != "public_sharing_unverifiable" {
		t.Fatalf("%+v", got)
	}
}

func TestVerifyDocumentRestrictionRejectsUnsafeUpdateACL(t *testing.T) {
	storage := neutralShellStorage("synapse-intent-a")
	updates := map[string]string{
		"explicit-user":   `{"operation":"update","restrictions":{"group":{"size":1,"results":[{"id":"synapse-readers","name":"synapse-readers"}]},"user":{"size":1,"results":[{"accountId":"publisher"}]}}}`,
		"different-group": `{"operation":"update","restrictions":{"group":{"size":1,"results":[{"id":"other-group","name":"other-group"}]},"user":{"size":0,"results":[]}}}`,
		"incomplete-page": `{"operation":"update","restrictions":{"group":{"size":1,"results":[{"id":"synapse-readers","name":"synapse-readers"}],"_links":{"next":"more"}},"user":{"size":0,"results":[]}}}`,
		"missing-results": `{"operation":"update","restrictions":{"group":{"size":0},"user":{"size":0,"results":[]}}}`,
	}
	for name, update := range updates {
		t.Run(name, func(t *testing.T) {
			for _, cloud := range []bool{true, false} {
				t.Run(map[bool]string{true: "cloud", false: "dc"}[cloud], func(t *testing.T) {
					main := transport(func(r *http.Request) (*http.Response, error) {
						switch {
						case strings.HasSuffix(r.URL.Path, "/content/1"):
							return response(200, content("1", neutralShellTitle("synapse-intent-a"), storage, 1)), nil
						case strings.HasSuffix(r.URL.Path, "/restriction/byOperation/read"):
							return response(200, exactRestriction("read", "synapse-readers", cloud)), nil
						case strings.HasSuffix(r.URL.Path, "/restriction/byOperation/update"):
							return response(200, update), nil
						}
						return response(500, "{}"), nil
					})
					policy := transport(func(*http.Request) (*http.Response, error) {
						t.Fatal("Cloud policy consulted before update ACL was proven")
						return nil, nil
					})
					if got := providerCode(t, testAdapter(t, cloud, main, policy).VerifyDocumentRestriction(context.Background(), "1", "SIL", "synapse-readers")); got.Code != "restriction_unverified" {
						t.Fatalf("%+v", got)
					}
				})
			}
		})
	}
}

func TestVerifyDocumentRestrictionAllowsGroupOnlyUpdateACL(t *testing.T) {
	storage := neutralShellStorage("synapse-intent-a")
	for name, update := range map[string]string{
		"empty":            emptyRestriction("update"),
		"configured-group": exactRestriction("update", "synapse-readers", true),
	} {
		t.Run(name, func(t *testing.T) {
			for _, cloud := range []bool{true, false} {
				t.Run(map[bool]string{true: "cloud", false: "dc"}[cloud], func(t *testing.T) {
					main := transport(func(r *http.Request) (*http.Response, error) {
						switch {
						case strings.HasSuffix(r.URL.Path, "/content/1"):
							return response(200, content("1", neutralShellTitle("synapse-intent-a"), storage, 1)), nil
						case strings.HasSuffix(r.URL.Path, "/restriction/byOperation/read"):
							return response(200, exactRestriction("read", "synapse-readers", cloud)), nil
						case strings.HasSuffix(r.URL.Path, "/restriction/byOperation/update"):
							if name == "configured-group" {
								return response(200, exactRestriction("update", "synapse-readers", cloud)), nil
							}
							return response(200, update), nil
						case cloud && r.URL.Path == "/_edge/tenant_info":
							return response(200, `{"cloudId":"11111111-1111-1111-1111-111111111111"}`), nil
						}
						return response(500, "{}"), nil
					})
					policy := transport(func(*http.Request) (*http.Response, error) {
						t.Fatal("Data Center must not consult Cloud policy")
						return nil, nil
					})
					if cloud {
						org := `{"id":"org-default","attributes":{"type":"data-security","status":"published","rule":{"publicLinks":{"effect":"allow"}},"metadata":{"policyCoverageLevel":"ORG"}}}`
						block := `{"id":"policy-1","attributes":{"type":"data-security","status":"published","rule":{"publicLinks":{"effect":"block"}},"metadata":{"policyCoverageLevel":"WORKSPACE"}}}`
						policy = transport(func(r *http.Request) (*http.Response, error) {
							switch {
							case strings.HasSuffix(r.URL.Path, "/policies"):
								return response(200, `{"data":[`+org+`,`+block+`],"meta":{}}`), nil
							case strings.HasSuffix(r.URL.Path, "/policies/org-default"):
								return response(200, `{"data":`+org+`}`), nil
							case strings.HasSuffix(r.URL.Path, "/policies/policy-1"):
								return response(200, `{"data":`+block+`}`), nil
							case strings.HasSuffix(r.URL.Path, "/resources"):
								return response(200, `{"data":[`+policyResourceResponse("ari:cloud:confluence::site/11111111-1111-1111-1111-111111111111", "applied")+`],"meta":{}}`), nil
							}
							return response(500, "{}"), nil
						})
					}
					if err := testAdapter(t, cloud, main, policy).VerifyDocumentRestriction(context.Background(), "1", "SIL", "synapse-readers"); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}

func TestCloudVerificationRejectsIncompletePolicyPagination(t *testing.T) {
	storage := neutralShellStorage("synapse-intent-a")
	main := transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/_edge/tenant_info" {
			return response(200, `{"cloudId":"11111111-1111-1111-1111-111111111111"}`), nil
		}
		if strings.Contains(r.URL.Path, "restriction") {
			operation := "read"
			if strings.HasSuffix(r.URL.Path, "/update") {
				operation = "update"
			}
			return response(200, exactRestriction(operation, "synapse-readers", true)), nil
		}
		return response(200, content("1", neutralShellTitle("synapse-intent-a"), storage, 1)), nil
	})
	calls := 0
	policy := transport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "api.atlassian.com" {
			t.Error("wrong policy host")
		}
		return response(200, `{"data":[],"meta":{"next":"again"}}`), nil
	})
	a := testAdapter(t, true, main, policy)
	got := providerCode(t, a.VerifyDocumentRestriction(context.Background(), "1", "SIL", "synapse-readers"))
	if got.Code != "public_sharing_unverifiable" || calls != 2 {
		t.Fatalf("error=%+v calls=%d", got, calls)
	}
}

func TestCloudVerificationRequiresExactPublishedPolicyAndAppliedSite(t *testing.T) {
	storage := neutralShellStorage("synapse-intent-a")
	main := transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/_edge/tenant_info" {
			return response(200, `{"cloudId":"11111111-1111-1111-1111-111111111111"}`), nil
		}
		if strings.Contains(r.URL.Path, "restriction") {
			operation := "read"
			if strings.HasSuffix(r.URL.Path, "/update") {
				operation = "update"
			}
			return response(200, exactRestriction(operation, "synapse-readers", true)), nil
		}
		return response(200, content("1", neutralShellTitle("synapse-intent-a"), storage, 1)), nil
	})
	orgData := `{"type":"policy","id":"org-default","attributes":{"type":"data-security","status":"published","rule":{"publicLinks":{"effect":"allow"}},"metadata":{"policyCoverageLevel":"ORG"}},"links":null,"message":null}`
	policyData := `{"type":"policy","id":"policy-1","attributes":{"type":"data-security","status":"published","rule":{"publicLinks":{"effect":"block"}},"metadata":{"policyCoverageLevel":"WORKSPACE"}},"links":null,"message":null}`
	// The API can return non-data-security policies even when requesting the
	// data-security collection. Their rule contract is unrelated and must not
	// make a valid public-links proof undecodable.
	unrelated := `{"type":"policy","id":"unrelated","attributes":{"type":"hipaa","status":"enabled","rule":[],"metadata":{}},"links":null,"message":null}`
	policy := transport(func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/policies"):
			return response(200, `{"data":[`+orgData+`,`+policyData+`,`+unrelated+`],"meta":{}}`), nil
		case strings.HasSuffix(r.URL.Path, "/policies/org-default"):
			return response(200, `{"data":`+orgData+`}`), nil
		case strings.HasSuffix(r.URL.Path, "/policies/policy-1"):
			return response(200, `{"data":`+policyData+`}`), nil
		case strings.HasSuffix(r.URL.Path, "/resources"):
			return response(200, `{"data":[`+policyResourceResponse("ari:cloud:confluence::site/11111111-1111-1111-1111-111111111111", "applied")+`],"meta":{}}`), nil
		}
		return response(500, "{}"), nil
	})
	if err := testAdapter(t, true, main, policy).VerifyDocumentRestriction(context.Background(), "1", "SIL", "synapse-readers"); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestCloudSharingProofAcceptsDocumentedControlsAndAuditMetadata(t *testing.T) {
	const audit = `"addedAt":"2026-10-17T01:02:03.123456789Z","lastUpdatedAt":"2026-10-17T01:02:04.123456789Z","addedBy":"ari:cloud:identity::user/00000000-0000-0000-0000-000000000001","lastUpdatedBy":"ari:cloud:identity::user/00000000-0000-0000-0000-000000000002"`
	const orgRule = `{"publicLinks":{"effect":"allow",` + audit + `},"export":{"effect":"block",` + audit + `},"anonymousAccess":{"effect":"block",` + audit + `},"appAccess":{"effect":"allow",` + audit + `},"attachmentDownload":{"effect":"block",` + audit + `},"mcpAccess":{"effect":"block",` + audit + `}}`
	const workspaceRule = `{"publicLinks":{"effect":"block",` + audit + `}}`
	org := `{"id":"org-default","attributes":{"type":"data-security","status":"published","rule":` + orgRule + `,"metadata":{"policyCoverageLevel":"ORG"}}}`
	workspace := `{"id":"policy-1","attributes":{"type":"data-security","status":"published","rule":` + workspaceRule + `,"metadata":{"policyCoverageLevel":"WORKSPACE"}}}`
	resource := policyResourceResponse("ari:cloud:confluence::site/11111111-1111-1111-1111-111111111111", "applied")

	a := testAdapter(t, true, transport(func(*http.Request) (*http.Response, error) {
		return response(200, `{"cloudId":"11111111-1111-1111-1111-111111111111"}`), nil
	}), transport(func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/policies"):
			return response(200, `{"data":[`+org+`,`+workspace+`],"meta":{}}`), nil
		case strings.HasSuffix(r.URL.Path, "/org-default"):
			return response(200, `{"data":`+org+`}`), nil
		case strings.HasSuffix(r.URL.Path, "/policy-1"):
			return response(200, `{"data":`+workspace+`}`), nil
		case strings.HasSuffix(r.URL.Path, "/resources"):
			return response(200, `{"data":[`+resource+`],"meta":{}}`), nil
		default:
			t.Fatalf("unexpected policy request %s", r.URL.Path)
			return nil, nil
		}
	}))
	if err := a.verifyCloudPublicSharing(context.Background()); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestWriteValidationRejectsSecretsHostileStorageAndUncertainWrites(t *testing.T) {
	a := testAdapter(t, false, transport(func(*http.Request) (*http.Response, error) { return response(500, "secret-token"), nil }), transport(func(*http.Request) (*http.Response, error) { return response(500, "{}"), nil }))
	if got := providerCode(t, a.ValidateDocumentText("x secret-token")); got.Code != "credential_in_document" || strings.Contains(got.Error(), "secret-token") {
		t.Fatalf("%+v", got)
	}
	for _, storage := range []string{"<script>x</script>", `<a href="javascript:alert(1)">x</a>`, `<p onclick="x">x</p>`} {
		if _, err := a.WriteDocument(context.Background(), "1", 1, "Title", storage, "synapse-intent-a"); err == nil {
			t.Fatalf("hostile storage accepted %q", storage)
		}
	}
	if !validStorage(`<h1>Report</h1><p><ac:link><ri:attachment ri:filename="report.pdf" /><ac:plain-text-link-body><![CDATA[PDF report]]></ac:plain-text-link-body></ac:link></p><ac:image><ri:attachment ri:filename="chart.png" /></ac:image><p>synapse-intent-a</p>`) {
		t.Fatal("provider rejected the storage projection it is required to accept")
	}
	_, err := a.WriteDocument(context.Background(), "1", 1, "Title", `<p>safe</p><p>synapse-intent-a</p>`, "synapse-intent-a")
	if got := providerCode(t, err); !got.Ambiguous || got.Code != "server_error" || strings.Contains(got.Error(), "secret-token") {
		t.Fatalf("%+v", got)
	}
}

func TestDocumentStateRetainsExactStorageAndRejectsVersionMismatch(t *testing.T) {
	storage := `<p>final</p><p>synapse-intent-a</p>`
	stateAdapter := testAdapter(t, false, transport(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/content/1") {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL)
		}
		return response(200, content("1", "Final report", storage, 2)), nil
	}), transport(func(*http.Request) (*http.Response, error) { return response(500, "{}"), nil }))
	state, err := stateAdapter.GetDocument(context.Background(), "1")
	if err != nil || state.Title != "Final report" || state.Storage != storage || state.Neutral || state.Marker != "synapse-intent-a" || state.Version != 2 {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	writeAdapter := testAdapter(t, false, transport(func(*http.Request) (*http.Response, error) {
		return response(200, content("1", "Final report", storage, 9)), nil
	}), transport(func(*http.Request) (*http.Response, error) { return response(500, "{}"), nil }))
	_, err = writeAdapter.WriteDocument(context.Background(), "1", 1, "Final report", storage, "synapse-intent-a")
	if got := providerCode(t, err); got.Code != "version_conflict" || !got.Ambiguous {
		t.Fatalf("%+v", got)
	}
}

func TestPurgeEnumeratesAttachmentsBeforeTrashAndPurge(t *testing.T) {
	var calls []string
	a := testAdapter(t, false, transport(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		switch {
		case r.URL.Path == "/confluence/rest/api/content/1/child/attachment":
			return response(200, `{"results":[{"id":"7"}],"size":1,"start":0}`), nil
		case r.Method == http.MethodGet && r.URL.Path == "/confluence/rest/api/content/7":
			return response(200, `{"version":{"number":2}}`), nil
		case r.Method == http.MethodDelete:
			return response(204, ""), nil
		default:
			return response(204, ""), nil
		}
	}), transport(func(*http.Request) (*http.Response, error) { return response(500, "{}"), nil }))
	guards := 0
	if err := a.PurgeDocument(context.Background(), "1", func(context.Context) error { guards++; return nil }); err != nil {
		t.Fatal(err)
	}
	want := []string{"GET /confluence/rest/api/content/1/child/attachment?expand=version&limit=100&start=0", "DELETE /confluence/rest/api/content/7?status=current", "DELETE /confluence/rest/api/content/7?status=trashed", "DELETE /confluence/rest/api/content/1?status=current", "DELETE /confluence/rest/api/content/1?status=trashed"}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls=%v", calls)
	}
	if guards != 4 {
		t.Fatalf("guards=%d", guards)
	}
}

func TestPurgeLeavesPartialDeleteAmbiguousWhenLaterDeletionIsRejected(t *testing.T) {
	calls := 0
	a := testAdapter(t, false, transport(func(r *http.Request) (*http.Response, error) {
		calls++
		switch calls {
		case 1:
			return response(200, `{"results":[{"id":"7"}],"size":1,"start":0}`), nil
		case 2:
			return response(204, ""), nil
		default:
			return response(403, "{}"), nil
		}
	}), transport(func(*http.Request) (*http.Response, error) { return response(500, "{}"), nil }))
	err := a.PurgeDocument(context.Background(), "1", func(context.Context) error { return nil })
	if got := providerCode(t, err); !got.Ambiguous || got.Code != "unauthorized" {
		t.Fatalf("%+v", got)
	}
}

func TestAttachmentBoundsAndExactResponseState(t *testing.T) {
	a := testAdapter(t, false, transport(func(*http.Request) (*http.Response, error) { t.Fatal("network called"); return nil, nil }), transport(func(*http.Request) (*http.Response, error) { return nil, nil }))
	if err := a.UploadDocumentAttachment(context.Background(), "1", ports.DocumentImage{Name: "x.svg", MediaType: "image/svg+xml", Data: []byte("x")}); err == nil {
		t.Fatal("accepted SVG")
	}
}

func TestPurgeCloudUsesPermanentAttachmentAndPageEndpoints(t *testing.T) {
	var calls []string
	a := testAdapter(t, true, transport(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		if r.Method == http.MethodGet {
			return response(200, `{"results":[{"id":"7"}],"size":1,"start":0}`), nil
		}
		return response(204, ""), nil
	}), nil)
	if err := a.PurgeDocument(context.Background(), "1", func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	want := []string{"GET /wiki/rest/api/content/1/child/attachment?expand=version&limit=100&start=0", "DELETE /wiki/api/v2/attachments/7", "DELETE /wiki/api/v2/attachments/7?purge=true", "DELETE /wiki/api/v2/pages/1", "DELETE /wiki/api/v2/pages/1?purge=true"}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls=%v", calls)
	}
}

func TestPurgeCloudNormalizesV1AttachmentPrefixesForV2(t *testing.T) {
	var calls []string
	guards := 0
	a := testAdapter(t, true, transport(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		if r.Method == http.MethodGet {
			return response(200, `{"results":[{"id":"att131320"},{"id":"att131306"},{"id":"att164115"},{"id":"att131280"},{"id":"att98536"}],"size":5,"start":0}`), nil
		}
		if r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/attachments/att") {
			t.Fatalf("v1 attachment prefix leaked into v2 path %q", r.URL.Path)
		}
		return response(204, ""), nil
	}), nil)
	if err := a.PurgeDocument(context.Background(), "1", func(context.Context) error { guards++; return nil }); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"GET /wiki/rest/api/content/1/child/attachment?expand=version&limit=100&start=0",
		"DELETE /wiki/api/v2/attachments/131280", "DELETE /wiki/api/v2/attachments/131280?purge=true",
		"DELETE /wiki/api/v2/attachments/131306", "DELETE /wiki/api/v2/attachments/131306?purge=true",
		"DELETE /wiki/api/v2/attachments/131320", "DELETE /wiki/api/v2/attachments/131320?purge=true",
		"DELETE /wiki/api/v2/attachments/164115", "DELETE /wiki/api/v2/attachments/164115?purge=true",
		"DELETE /wiki/api/v2/attachments/98536", "DELETE /wiki/api/v2/attachments/98536?purge=true",
		"DELETE /wiki/api/v2/pages/1", "DELETE /wiki/api/v2/pages/1?purge=true",
	}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls=%v", calls)
	}
	if guards != 12 {
		t.Fatalf("guards=%d", guards)
	}
}

func TestPurgeRejectsInvalidAttachmentIDsBeforeDeleting(t *testing.T) {
	for _, test := range []struct {
		name  string
		cloud bool
		id    string
	}{
		{name: "dc-v1-prefix", cloud: false, id: "att131320"},
		{name: "cloud-nonnumeric-suffix", cloud: true, id: "att131320x"},
		{name: "cloud-repeated-prefix", cloud: true, id: "attatt131320"},
	} {
		t.Run(test.name, func(t *testing.T) {
			deletes := 0
			a := testAdapter(t, test.cloud, transport(func(r *http.Request) (*http.Response, error) {
				if r.Method == http.MethodDelete {
					deletes++
					t.Fatal("delete issued for invalid attachment ID")
				}
				return response(200, `{"results":[{"id":`+jsonString(test.id)+`}],"size":1,"start":0}`), nil
			}), nil)
			if got := providerCode(t, a.PurgeDocument(context.Background(), "1", func(context.Context) error { return nil })); got.Code != "invalid_attachment_response" {
				t.Fatalf("%+v", got)
			}
			if deletes != 0 {
				t.Fatalf("deletes=%d", deletes)
			}
		})
	}
}

func TestPurgeRefusesIncompleteAttachmentEnumerationBeforeDeleting(t *testing.T) {
	for _, body := range []string{`{"results":[],"start":0}`, `{"results":[],"size":0}`, `{"results":[],"size":0,"start":1}`, `{"results":[{"id":"7"}],"size":0,"start":0}`, `{"results":[],"size":0,"start":0,"_links":{"next":"more"}}`} {
		t.Run(body, func(t *testing.T) {
			a := testAdapter(t, false, transport(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet {
					t.Fatal("deletion before complete enumeration")
				}
				return response(200, body), nil
			}), nil)
			if err := a.PurgeDocument(context.Background(), "1", func(context.Context) error { return nil }); err == nil {
				t.Fatal("accepted incomplete attachment enumeration")
			}
		})
	}
}

func TestMalformedSuccessfulWriteResponseRemainsAmbiguous(t *testing.T) {
	for _, shell := range []bool{true, false} {
		a := testAdapter(t, false, transport(func(*http.Request) (*http.Response, error) { return response(200, `{"id":"1"}`), nil }), nil)
		var err error
		if shell {
			_, err = a.CreateDocumentShell(context.Background(), "SIL", "synapse-intent-a")
		} else {
			_, err = a.WriteDocument(context.Background(), "1", 1, "Report", `<p>synapse-intent-a</p>`, "synapse-intent-a")
		}
		if got := providerCode(t, err); !got.Ambiguous {
			t.Fatalf("shell=%v got=%+v", shell, got)
		}
	}
}

func TestReadRestrictionRequiresCompleteExactPrincipals(t *testing.T) {
	for _, acl := range []string{
		`{"operation":"read","restrictions":{"group":{"size":1,"results":[{"name":"synapse-readers","id":"synapse-readers"}]}}}`,
		`{"operation":"read","restrictions":{"group":{"size":1,"results":[{"name":"synapse-readers","id":"wrong"}]},"user":{"size":0,"results":[]}}}`,
		`{"operation":"read","restrictions":{"group":{"size":1,"results":[{"id":"synapse-readers"}],"_links":{"next":"more"}},"user":{"size":0,"results":[]}}}`,
		`{"operation":"read","restrictions":{"group":{"size":1,"results":[{"id":"synapse-readers"}]},"user":{"size":0,"results":[],"totalSize":1}}}`,
	} {
		t.Run(acl, func(t *testing.T) {
			a := testAdapter(t, true, transport(func(r *http.Request) (*http.Response, error) {
				if strings.Contains(r.URL.Path, "restriction") {
					return response(200, acl), nil
				}
				return response(200, content("1", "Report", `<p>synapse-intent-a</p>`, 1)), nil
			}), transport(func(*http.Request) (*http.Response, error) {
				t.Fatal("policy consulted before exact ACL verified")
				return nil, nil
			}))
			if got := providerCode(t, a.VerifyDocumentRestriction(context.Background(), "1", "SIL", "synapse-readers")); got.Code != "restriction_unverified" {
				t.Fatalf("%+v", got)
			}
		})
	}
}

func TestCloudSharingProofRejectsStaleForeignOrUnappliedPolicies(t *testing.T) {
	const org = `{"id":"org-default","attributes":{"type":"data-security","status":"published","rule":{"publicLinks":{"effect":"allow"}},"metadata":{"policyCoverageLevel":"ORG"}}}`
	const block = `{"id":"policy-1","attributes":{"type":"data-security","status":"published","rule":{"publicLinks":{"effect":"block"}},"metadata":{"policyCoverageLevel":"WORKSPACE"}}}`
	resource := policyResourceResponse("ari:cloud:confluence::site/11111111-1111-1111-1111-111111111111", "applied")
	for _, name := range []string{"foreign-site", "missing-org", "missing-meta", "pending-resource", "unsupported-resource-shape", "stale-effect", "stale-coverage", "unknown-status", "hidden-override", "missing-type", "null-type", "empty-type", "malformed-type", "unrelated-missing-id", "unrelated-duplicate-id"} {
		t.Run(name, func(t *testing.T) {
			list, full, res, cloudID := `{"data":[`+org+`,`+block+`],"meta":{}}`, block, resource, "11111111-1111-1111-1111-111111111111"
			switch name {
			case "foreign-site":
				cloudID = "22222222-2222-2222-2222-222222222222"
			case "missing-org":
				list = `{"data":[` + block + `],"meta":{}}`
			case "missing-meta":
				list = `{"data":[` + org + `,` + block + `]}`
			case "pending-resource":
				res = strings.ReplaceAll(resource, "applied", "pending")
			case "unsupported-resource-shape":
				res = strings.ReplaceAll(resource, "resourceId", "resourceAri")
			case "stale-effect":
				full = strings.ReplaceAll(block, `"block"`, `"allow"`)
			case "stale-coverage":
				full = strings.ReplaceAll(block, "WORKSPACE", "ORG")
			case "unknown-status":
				list = strings.ReplaceAll(list, "published", "unknown")
			case "hidden-override":
				hidden := strings.ReplaceAll(strings.ReplaceAll(block, "policy-1", "hidden"), `"rule":{"publicLinks":{"effect":"block"}}`, `"rule":{}`)
				list = `{"data":[` + org + `,` + block + `,` + hidden + `],"meta":{}}`
			case "missing-type", "null-type", "empty-type", "malformed-type", "unrelated-missing-id", "unrelated-duplicate-id":
				hidden := `{"id":"hidden","attributes":{"type":"hipaa","status":"published","rule":{"publicLinks":{"effect":"allow"}}}}`
				switch name {
				case "missing-type":
					hidden = strings.ReplaceAll(hidden, `"type":"hipaa",`, "")
				case "null-type":
					hidden = strings.ReplaceAll(hidden, `"type":"hipaa"`, `"type":null`)
				case "empty-type":
					hidden = strings.ReplaceAll(hidden, `"type":"hipaa"`, `"type":""`)
				case "malformed-type":
					hidden = strings.ReplaceAll(hidden, `"type":"hipaa"`, `"type":"data security"`)
				case "unrelated-missing-id":
					hidden = strings.ReplaceAll(hidden, `"id":"hidden",`, "")
				case "unrelated-duplicate-id":
					hidden = strings.ReplaceAll(hidden, `"id":"hidden"`, `"id":"org-default"`)
				}
				list = `{"data":[` + org + `,` + block + `,` + hidden + `],"meta":{}}`
			}
			a := testAdapter(t, true, transport(func(*http.Request) (*http.Response, error) { return response(200, `{"cloudId":"`+cloudID+`"}`), nil }), transport(func(r *http.Request) (*http.Response, error) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/policies"):
					return response(200, list), nil
				case strings.HasSuffix(r.URL.Path, "/org-default"):
					return response(200, `{"data":`+org+`}`), nil
				case strings.HasSuffix(r.URL.Path, "/resources"):
					return response(200, `{"data":[`+res+`],"meta":{}}`), nil
				case strings.HasSuffix(r.URL.Path, "/hidden"):
					return response(200, `{"data":`+strings.ReplaceAll(block, "policy-1", "hidden")+`}`), nil
				default:
					return response(200, `{"data":`+full+`}`), nil
				}
			}))
			if got := providerCode(t, a.verifyCloudPublicSharing(context.Background())); got.Code != "public_sharing_unverifiable" || got.RestrictionLost != (name == "foreign-site" || name == "missing-org") {
				t.Fatalf("classification for %s: %+v", name, got)
			}
		})
	}
}

func TestCloudSharingProofFailsClosedForAmbiguousPublicLinkRules(t *testing.T) {
	const org = `{"id":"org-default","attributes":{"type":"data-security","status":"published","rule":{"publicLinks":{"effect":"allow"}},"metadata":{"policyCoverageLevel":"ORG"}}}`
	const block = `{"id":"policy-1","attributes":{"type":"data-security","status":"published","rule":{"publicLinks":{"effect":"block"}},"metadata":{"policyCoverageLevel":"WORKSPACE"}}}`
	resource := policyResourceResponse("ari:cloud:confluence::site/11111111-1111-1111-1111-111111111111", "applied")

	for _, tc := range []struct {
		name string
		rule string
	}{
		{name: "unknown rule key", rule: `{"publicLinks":{"effect":"block"},"conditions":{"actor":"admin"}}`},
		{name: "unknown nested key", rule: `{"publicLinks":{"effect":"block","conditions":[]}}`},
		{name: "null rule", rule: `null`},
		{name: "array rule", rule: `[]`},
		{name: "null public links", rule: `{"publicLinks":null}`},
		{name: "array public links", rule: `{"publicLinks":[]}`},
		{name: "unknown effect", rule: `{"publicLinks":{"effect":"audit"}}`},
		{name: "null effect", rule: `{"publicLinks":{"effect":null}}`},
		{name: "missing effect", rule: `{"publicLinks":{}}`},
		{name: "duplicate rule key", rule: `{"publicLinks":{"effect":"block"},"publicLinks":{"effect":"allow"}}`},
		{name: "duplicate nested key", rule: `{"publicLinks":{"effect":"block","effect":"allow"}}`},
		{name: "audit metadata type", rule: `{"publicLinks":{"effect":"block","addedAt":123}}`},
		{name: "null audit metadata", rule: `{"publicLinks":{"effect":"block","addedBy":null}}`},
		{name: "duplicate audit metadata", rule: `{"publicLinks":{"effect":"block","addedAt":"2026-10-17T01:02:03Z","addedAt":"2026-10-17T01:02:04Z"}}`},
		{name: "conditioned known sibling", rule: `{"publicLinks":{"effect":"block"},"export":{"effect":"block","conditions":[]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			malformed := strings.Replace(block, `{"publicLinks":{"effect":"block"}}`, tc.rule, 1)
			a := testAdapter(t, true, transport(func(*http.Request) (*http.Response, error) {
				return response(200, `{"cloudId":"11111111-1111-1111-1111-111111111111"}`), nil
			}), transport(func(r *http.Request) (*http.Response, error) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/policies"):
					return response(200, `{"data":[`+org+`,`+malformed+`],"meta":{}}`), nil
				case strings.HasSuffix(r.URL.Path, "/org-default"):
					return response(200, `{"data":`+org+`}`), nil
				case strings.HasSuffix(r.URL.Path, "/policy-1"):
					return response(200, `{"data":`+malformed+`}`), nil
				case strings.HasSuffix(r.URL.Path, "/resources"):
					return response(200, `{"data":[`+resource+`],"meta":{}}`), nil
				default:
					t.Fatalf("unexpected policy request %s", r.URL.Path)
					return nil, nil
				}
			}))
			if got := providerCode(t, a.verifyCloudPublicSharing(context.Background())); got.Code != "public_sharing_unverifiable" {
				t.Fatalf("%+v", got)
			}
		})
	}
}
