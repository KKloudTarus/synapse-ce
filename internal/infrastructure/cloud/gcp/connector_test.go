package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type vault struct {
	secret []byte
	calls  int
}

func (v *vault) Put(context.Context, shared.ID, string, []byte) error { return nil }
func (v *vault) Resolve(_ context.Context, _ shared.ID, _ string) ([]byte, error) {
	v.calls++
	return append([]byte(nil), v.secret...), nil
}
func (v *vault) List(context.Context, shared.ID) ([]ports.CredentialMeta, error) { return nil, nil }
func (v *vault) Delete(context.Context, shared.ID, string) error                 { return nil }

func TestEnumeratePaginationCategoriesCoverageAndCredentialPrivacy(t *testing.T) {
	const secret = "never-send-this-credential"
	var mu sync.Mutex
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.URL.String()+" "+r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v3/folders":
			writeJSON(t, w, map[string]any{})
		case r.URL.Path == "/v1/projects":
			if r.URL.Query().Get("pageToken") == "next" {
				writeJSON(t, w, map[string]any{"projects": []any{map[string]any{"projectId": "p2"}}})
				return
			}
			writeJSON(t, w, map[string]any{"projects": []any{map[string]any{"projectId": "p1"}}, "nextPageToken": "next"})
		case strings.Contains(r.URL.Path, "/aggregated/instances"):
			if strings.Contains(r.URL.Path, "/projects/p2/") {
				writeError(t, w, http.StatusServiceUnavailable, "project unavailable")
				return
			}
			if r.URL.Query().Get("pageToken") == "next" {
				writeJSON(t, w, map[string]any{"items": map[string]any{"zones/us-central1-b": map[string]any{"instances": []any{map[string]any{"name": "vm2", "zone": "zones/us-central1-b"}}}}})
				return
			}
			writeJSON(t, w, map[string]any{
				"items": map[string]any{
					"zones/us-central1-a": map[string]any{
						"instances": []any{map[string]any{
							"name": "vm1", "zone": "zones/us-central1-a",
							"networkInterfaces": []any{map[string]any{
								"network":       "https://x/compute/v1/projects/p1/global/networks/net1",
								"accessConfigs": []any{map[string]any{"natIP": "203.0.113.1"}},
							}},
						}},
					},
				},
				"nextPageToken": "next", "unreachables": []string{"zones/us-central1-c"},
			})
		case strings.Contains(r.URL.Path, "/global/networks"):
			writeJSON(t, w, map[string]any{"items": []any{map[string]any{"name": "net1"}}})
		case strings.Contains(r.URL.Path, "/b/bucket1/iam"):
			writeJSON(t, w, map[string]any{"bindings": []any{map[string]any{"role": "roles/storage.objectViewer", "members": []string{"allUsers"}}}})
		case strings.Contains(r.URL.Path, "/b"):
			if strings.Contains(r.URL.RawQuery, "project=p2") {
				writeError(t, w, http.StatusForbidden, "missing storage permission")
				return
			}
			writeJSON(t, w, map[string]any{"items": []any{map[string]any{"name": "bucket1", "encryption": map[string]any{"defaultKmsKeyName": "kms-key"}}}})
		case strings.Contains(r.URL.Path, ":getIamPolicy"):
			writeJSON(t, w, map[string]any{"bindings": []any{map[string]any{"role": "roles/owner", "members": []string{"allUsers"}}}})
		case strings.Contains(r.URL.Path, "/serviceAccounts"):
			project := "p1"
			if strings.Contains(r.URL.Path, "/projects/p2/") {
				project = "p2"
			}
			writeJSON(t, w, map[string]any{"accounts": []any{map[string]any{"name": "projects/" + project + "/serviceAccounts/sa@example.test", "email": "sa@example.test"}}})
		default:
			writeError(t, w, http.StatusNotFound, "unexpected path")
		}
	}))
	defer server.Close()

	v := &vault{secret: []byte(secret)}
	connector, err := New(v, Options{Endpoint: server.URL + "/", HTTPClient: server.Client(), MinRequestWait: 0})
	if err != nil {
		t.Fatal(err)
	}
	var authorized int
	inventory, gaps, err := connector.Enumerate(context.Background(), ports.CloudScope{EngagementID: "engagement", Provider: cloudposture.ProviderGCP, Root: "organizations/123", CredentialRef: "gcp", Authorize: func(context.Context, ports.CloudOperation) error { authorized++; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if !hasResource(inventory, "projects/p1") || !hasResource(inventory, "projects/p2") || !hasType(inventory, "gcp_compute_instance") || !hasType(inventory, "gcp_bucket") || !hasType(inventory, "gcp_network") || !hasType(inventory, "gcp_service_account") || !hasType(inventory, "gcp_iam_binding") {
		t.Fatalf("missing enumerated category: %#v", inventory.Resources)
	}
	if inventory.Complete {
		t.Fatal("partial GCP enumeration reported complete")
	}
	bucket := resourceByType(inventory, "gcp_bucket")
	if bucket == nil || bucket.Public != cloudposture.StateEnabled || bucket.Encrypted != cloudposture.StateEnabled {
		t.Fatalf("bucket posture = %#v", bucket)
	}
	if !hasGap(gaps, "compute", "unreachable") || !hasGap(gaps, "storage", "permission_denied") || !hasGap(gaps, "compute", "unreachable") {
		t.Fatalf("missing coverage gaps: %#v", gaps)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) < 2 || !strings.Contains(strings.Join(requests, "\n"), "pageToken=next") {
		t.Fatalf("project or compute pagination missing: %v", requests)
	}
	if strings.Contains(strings.Join(requests, "\n"), secret) {
		t.Fatalf("credential leaked in request: %v", requests)
	}
	if v.calls != 1 {
		t.Fatalf("Resolve calls = %d, want 1", v.calls)
	}
	if authorized != len(requests) {
		t.Fatalf("authorization calls = %d, requests = %d", authorized, len(requests))
	}
}

func TestEnumerateSingleProject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/aggregated/instances"), strings.Contains(r.URL.Path, "/global/networks"), strings.Contains(r.URL.Path, "/global/routes"), strings.Contains(r.URL.Path, "/global/firewalls"), strings.Contains(r.URL.Path, "/b"), strings.Contains(r.URL.Path, "/serviceAccounts"), strings.Contains(r.URL.Path, ":getIamPolicy"):
			writeJSON(t, w, map[string]any{})
		default:
			writeError(t, w, http.StatusNotFound, "project listing must not run")
		}
	}))
	defer server.Close()
	connector, err := New(&vault{secret: []byte("secret")}, Options{Endpoint: server.URL + "/", HTTPClient: server.Client(), MinRequestWait: 0})
	if err != nil {
		t.Fatal(err)
	}
	inventory, gaps, err := connector.Enumerate(context.Background(), ports.CloudScope{EngagementID: "engagement", Provider: cloudposture.ProviderGCP, Root: "projects/direct", CredentialRef: "gcp", Authorize: permit})
	if err != nil {
		t.Fatal(err)
	}
	if !inventory.Complete || len(gaps) != 0 || !hasResource(inventory, "projects/direct") {
		t.Fatalf("single project inventory = %#v, gaps = %#v", inventory, gaps)
	}
}

func TestProjectsReportsExactLimitTruncation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v3/folders" {
			writeJSON(t, w, map[string]any{})
			return
		}
		if r.URL.Path == "/v1/projects" {
			writeJSON(t, w, map[string]any{"projects": []any{map[string]any{"projectId": "p1"}}, "nextPageToken": "more"})
			return
		}
		writeJSON(t, w, map[string]any{})
	}))
	defer server.Close()
	connector, err := New(&vault{secret: []byte("secret")}, Options{Endpoint: server.URL + "/", HTTPClient: server.Client(), MaxProjects: 1})
	if err != nil {
		t.Fatal(err)
	}
	inventory, gaps, err := connector.Enumerate(context.Background(), ports.CloudScope{EngagementID: "engagement", Provider: cloudposture.ProviderGCP, Root: "organizations/123", CredentialRef: "gcp", Authorize: permit})
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Complete || !hasGap(gaps, "projects", "limit_reached") {
		t.Fatalf("inventory=%#v gaps=%#v", inventory, gaps)
	}
}

func TestEnumerateFoldersBucketACLAndReachability(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v3/folders":
			if r.URL.Query().Get("parent") == "organizations/123" {
				writeJSON(t, w, map[string]any{"folders": []any{map[string]any{"name": "folders/456", "state": "ACTIVE"}}})
				return
			}
			writeJSON(t, w, map[string]any{})
		case r.URL.Path == "/v1/projects":
			if strings.Contains(r.URL.Query().Get("filter"), "parent.id:456") {
				writeJSON(t, w, map[string]any{"projects": []any{map[string]any{"projectId": "nested"}}})
				return
			}
			writeJSON(t, w, map[string]any{})
		case strings.Contains(r.URL.Path, "/aggregated/instances"):
			writeJSON(t, w, map[string]any{"items": map[string]any{"zones/us-central1-a": map[string]any{"instances": []any{map[string]any{"name": "vm", "zone": "zones/us-central1-a", "tags": map[string]any{"items": []string{"web"}}, "networkInterfaces": []any{map[string]any{"network": "projects/nested/global/networks/default", "accessConfigs": []any{map[string]any{"natIP": "203.0.113.1"}}}}}}}}})
		case strings.Contains(r.URL.Path, "/global/routes"):
			writeJSON(t, w, map[string]any{"items": []any{map[string]any{"network": "projects/nested/global/networks/default", "destRange": "0.0.0.0/0", "nextHopGateway": "projects/nested/global/gateways/default-internet-gateway"}}})
		case strings.Contains(r.URL.Path, "/global/firewalls"):
			writeJSON(t, w, map[string]any{"items": []any{map[string]any{"network": "projects/nested/global/networks/default", "direction": "INGRESS", "sourceRanges": []string{"0.0.0.0/0"}, "targetTags": []string{"web"}, "allowed": []any{map[string]any{"IPProtocol": "tcp"}}}}})
		case strings.Contains(r.URL.Path, "/global/networks"):
			writeJSON(t, w, map[string]any{})
		case strings.Contains(r.URL.Path, "/b"):
			writeJSON(t, w, map[string]any{"items": []any{map[string]any{"name": "acl-public", "acl": []any{map[string]any{"entity": "allUsers"}}, "iamConfiguration": map[string]any{"publicAccessPrevention": "inherited"}}}})
		case strings.Contains(r.URL.Path, "/serviceAccounts"), strings.Contains(r.URL.Path, ":getIamPolicy"):
			writeJSON(t, w, map[string]any{})
		default:
			writeError(t, w, http.StatusNotFound, "unexpected path")
		}
	}))
	defer server.Close()
	connector, err := New(&vault{secret: []byte("secret")}, Options{Endpoint: server.URL + "/", HTTPClient: server.Client(), MinRequestWait: 0})
	if err != nil {
		t.Fatal(err)
	}
	inventory, gaps, err := connector.Enumerate(context.Background(), ports.CloudScope{EngagementID: "engagement", Provider: cloudposture.ProviderGCP, Root: "organizations/123", CredentialRef: "gcp", Authorize: permit})
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 0 || !inventory.Complete || !hasResource(inventory, "projects/nested") {
		t.Fatalf("inventory=%#v gaps=%#v", inventory, gaps)
	}
	bucket := resourceByType(inventory, "gcp_bucket")
	if bucket == nil || bucket.Public != cloudposture.StateEnabled {
		t.Fatalf("bucket posture = %#v", bucket)
	}
	instance := resourceByType(inventory, "gcp_compute_instance")
	if instance == nil || instance.PublicNetwork != cloudposture.StateEnabled {
		t.Fatalf("instance reachability = %#v", instance)
	}
}

func TestEnumerateFailsClosedWithoutAuthorizer(t *testing.T) {
	connector, err := New(&vault{secret: []byte("secret")}, Options{HTTPClient: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = connector.Enumerate(context.Background(), ports.CloudScope{EngagementID: "engagement", Provider: cloudposture.ProviderGCP, Root: "projects/direct", CredentialRef: "gcp"})
	if err == nil || !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("err = %v, want forbidden", err)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatal(err)
	}
}
func writeError(t *testing.T, w http.ResponseWriter, status int, message string) {
	t.Helper()
	w.WriteHeader(status)
	writeJSON(t, w, map[string]any{"error": map[string]any{"code": status, "message": message}})
}
func hasResource(inventory cloudposture.Inventory, id string) bool {
	for _, resource := range inventory.Resources {
		if resource.ID == id {
			return true
		}
	}
	return false
}
func hasType(inventory cloudposture.Inventory, resourceType string) bool {
	for _, resource := range inventory.Resources {
		if resource.ResourceType == resourceType {
			return true
		}
	}
	return false
}

func resourceByType(inventory cloudposture.Inventory, resourceType string) *cloudposture.Resource {
	for index := range inventory.Resources {
		if inventory.Resources[index].ResourceType == resourceType {
			return &inventory.Resources[index]
		}
	}
	return nil
}
func hasGap(gaps []cloudposture.CoverageIssue, category, code string) bool {
	for _, gap := range gaps {
		if gap.Category == category && gap.Code == code {
			return true
		}
	}
	return false
}

func permit(context.Context, ports.CloudOperation) error { return nil }
