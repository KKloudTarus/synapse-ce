package scmdecoration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const azureTestPath = "/acme/project/_apis/git/repositories/widget/pullRequests/7"

type azureFake struct {
	mu             sync.Mutex
	statuses       []azureStatus
	threads        []azureThread
	statusPosts    int
	threadPosts    int
	commentPatches int
	forbidStatus   bool
	forbidComment  bool
	lostStatusAck  bool
	lostThreadAck  bool
	authorization  []string
	paths          []string
}

func (f *azureFake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authorization = append(f.authorization, r.Header.Get("Authorization"))
	f.paths = append(f.paths, r.URL.EscapedPath())
	w.Header().Set("Content-Type", "application/json")
	if !strings.HasPrefix(r.URL.EscapedPath(), azureTestPath) || r.URL.Query().Get("api-version") != "7.1" {
		http.Error(w, "unexpected route", http.StatusNotFound)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == azureTestPath+"/statuses":
		_ = json.NewEncoder(w).Encode(azureStatusPage{Value: f.statuses})
	case r.Method == http.MethodPost && r.URL.Path == azureTestPath+"/statuses":
		if f.forbidStatus {
			http.Error(w, "secret PAT should never be returned", http.StatusForbidden)
			return
		}
		var status azureStatus
		if err := json.NewDecoder(r.Body).Decode(&status); err != nil {
			http.Error(w, "invalid status JSON", http.StatusBadRequest)
			return
		}
		f.statuses = append([]azureStatus{status}, f.statuses...)
		f.statusPosts++
		if f.lostStatusAck {
			f.lostStatusAck = false
			http.Error(w, "upstream accepted but response lost", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(status)
	case r.Method == http.MethodGet && r.URL.Path == azureTestPath+"/threads":
		_ = json.NewEncoder(w).Encode(azureThreadPage{Value: f.threads})
	case r.Method == http.MethodPost && r.URL.Path == azureTestPath+"/threads":
		if f.forbidComment {
			http.Error(w, "secret PAT should never be returned", http.StatusForbidden)
			return
		}
		var body struct {
			Comments []struct {
				Content         string `json:"content"`
				ParentCommentID int    `json:"parentCommentId"`
				CommentType     int    `json:"commentType"`
			} `json:"comments"`
			Status int `json:"status"`
		}
		// Match the documented *request* enum numbers, not the response's string enums.
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Comments) != 1 || body.Comments[0].CommentType != 1 || body.Comments[0].ParentCommentID != 0 || body.Status != 1 {
			http.Error(w, "invalid thread JSON", http.StatusBadRequest)
			return
		}
		f.threadPosts++
		th := azureThread{ID: int64(100 + f.threadPosts), Comments: []azureThreadComment{{
			ID: 1, Content: body.Comments[0].Content, CommentType: "text",
		}}}
		f.threads = append(f.threads, th)
		if f.lostThreadAck {
			f.lostThreadAck = false
			http.Error(w, "upstream accepted but response lost", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(th)
	case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/threads/") && strings.Contains(r.URL.Path, "/comments/"):
		if f.forbidComment {
			http.Error(w, "secret PAT should never be returned", http.StatusForbidden)
			return
		}
		var body struct {
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid comment JSON", http.StatusBadRequest)
			return
		}
		for i := range f.threads {
			if r.URL.Path == azureTestPath+"/threads/"+strconvI64(f.threads[i].ID)+"/comments/1" {
				f.threads[i].Comments[0].Content = body.Content
				f.commentPatches++
				_ = json.NewEncoder(w).Encode(f.threads[i].Comments[0])
				return
			}
		}
		http.Error(w, "comment not found", http.StatusNotFound)
	default:
		http.Error(w, "unexpected route", http.StatusNotFound)
	}
}

func strconvI64(v int64) string { return strconv.FormatInt(v, 10) }

func azureFixture(t *testing.T, f *azureFake, credentials ports.GitCredentialResolver) (*AzureDevOpsDecorator, context.Context, ports.PRDecoration) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	d, err := newAzureDevOpsDecorator(server.Client(), server.URL, azureSCMHost, credentials)
	if err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), "tenant-1")
	decoration := ports.PRDecoration{Provider: "azure-pipelines",
		Target: ports.PRDecorationTarget{Repository: "acme/project/widget", PullRequest: "7", CommitSHA: "head", TargetBranch: "main"},
		Gate:   qualitygate.Result{Passed: true}, Summary: "Quality results",
	}
	return d, ctx, decoration
}

func azureStaticCredential(t *testing.T) ports.GitCredentialResolver {
	t.Helper()
	r, err := NewStaticCredentialResolver(azureSCMHost, "pat", []byte("secret-pat"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAzureDevOpsContractCreatesUpdatesAndDedupes(t *testing.T) {
	f := &azureFake{}
	d, ctx, decoration := azureFixture(t, f, azureStaticCredential(t))
	if err := d.Decorate(ctx, decoration); err != nil {
		t.Fatal(err)
	}
	if err := d.Decorate(ctx, decoration); err != nil {
		t.Fatal(err)
	}
	if f.statusPosts != 1 || f.threadPosts != 1 || f.commentPatches != 0 {
		t.Fatalf("rerun duplicated a remote object: statuses=%d threads=%d patches=%d", f.statusPosts, f.threadPosts, f.commentPatches)
	}
	if len(f.authorization) == 0 {
		t.Fatal("the mock received no requests")
	}
	for _, header := range f.authorization {
		if header != "Basic "+base64.StdEncoding.EncodeToString([]byte(":secret-pat")) {
			t.Fatal("Azure DevOps authorization must use a PAT with empty Basic username")
		}
	}
	decoration.Summary = "Revised quality results"
	if err := d.Decorate(ctx, decoration); err != nil {
		t.Fatal(err)
	}
	if f.statusPosts != 1 || f.threadPosts != 1 || f.commentPatches != 1 {
		t.Fatalf("changed summary must patch one comment, got %d/%d/%d", f.statusPosts, f.threadPosts, f.commentPatches)
	}
	decoration.Target.CommitSHA = "different-head"
	if err := d.Decorate(ctx, decoration); err != nil {
		t.Fatal(err)
	}
	if f.statusPosts != 2 || f.threadPosts != 1 || f.commentPatches != 2 {
		t.Fatalf("changed commit must refresh status and comment, got %d/%d/%d", f.statusPosts, f.threadPosts, f.commentPatches)
	}
	decoration.Gate.Passed = false
	if err := d.Decorate(ctx, decoration); err != nil {
		t.Fatal(err)
	}
	if f.statuses[0].State != "failed" || f.statuses[0].Context.Name != azureStatusName || f.statuses[0].Context.Genre != azureStatusGenre {
		t.Fatalf("wrong Azure DevOps status contract: %+v", f.statuses[0])
	}
	if f.threadPosts != 1 || f.commentPatches != 3 || !strings.Contains(f.threads[0].Comments[0].Content, "Revised quality results") || !strings.Contains(f.threads[0].Comments[0].Content, "Gate: FAILED") {
		t.Fatal("failed rerun should update the single owned thread")
	}
}

// ADO's status list has no promised order. A stale success must never suppress a newer
// failure (or cause duplicate failure POSTs), even when another tool owns a higher ID.
func TestAzureDevOpsStatusUsesNewestOwnedIDRegardlessOfResponseOrder(t *testing.T) {
	older := azureStatus{ID: 11, State: "succeeded", Description: "old result"}
	older.Context.Name, older.Context.Genre = azureStatusName, azureStatusGenre
	current := azureStatus{ID: 15, State: "failed", Description: "latest result"}
	current.Context.Name, current.Context.Genre = azureStatusName, azureStatusGenre
	foreign := azureStatus{ID: 999, State: "succeeded", Description: "not ours"}
	foreign.Context.Name, foreign.Context.Genre = "other-provider", azureStatusGenre
	for _, statuses := range [][]azureStatus{
		{older, foreign, current},
		{current, foreign, older},
	} {
		if !azureStatusFound(statuses, "failed", "latest result") {
			t.Fatal("failed to identify newest owned Azure status")
		}
		if azureStatusFound(statuses, "succeeded", "old result") {
			t.Fatal("stale Azure status masked the newest quality-gate verdict")
		}
	}
}

func TestAzureDevOpsIndependentFailuresAndRedactedErrors(t *testing.T) {
	f := &azureFake{forbidStatus: true}
	d, ctx, decoration := azureFixture(t, f, azureStaticCredential(t))
	err := d.Decorate(ctx, decoration)
	if err == nil || f.threadPosts != 1 {
		t.Fatalf("status failure suppressed comment: %v", err)
	}
	if strings.Contains(err.Error(), "secret-pat") || strings.Contains(err.Error(), "Authorization") {
		t.Fatalf("credential disclosed by status error: %v", err)
	}
	f.forbidStatus, f.forbidComment = false, true
	decoration.Summary = "An update"
	err = d.Decorate(ctx, decoration)
	if err == nil || f.statusPosts != 1 {
		t.Fatalf("comment failure suppressed status: %v", err)
	}
	if strings.Contains(err.Error(), "secret-pat") {
		t.Fatalf("credential leaked by comment error: %v", err)
	}
}

func TestAzureDevOpsReconcilesUncertainAcceptedPOSTs(t *testing.T) {
	f := &azureFake{lostStatusAck: true, lostThreadAck: true}
	d, ctx, decoration := azureFixture(t, f, azureStaticCredential(t))
	if err := d.Decorate(ctx, decoration); err != nil {
		t.Fatal(err)
	}
	if f.statusPosts != 1 || f.threadPosts != 1 {
		t.Fatalf("uncertain accepted posts were duplicated: statuses=%d threads=%d", f.statusPosts, f.threadPosts)
	}
}

type azureTenantResolver struct {
	mu    sync.Mutex
	calls int
}

func (r *azureTenantResolver) ResolveGitCredential(ctx context.Context, host string) (ports.GitCredential, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant != "tenant-1" || host != azureSCMHost {
		return ports.GitCredential{}, false, nil
	}
	return ports.GitCredential{Username: "pat", Token: []byte("tenant-pat")}, true, nil
}

func TestAzureDevOpsRequiresTenantCredentialAndRejectsUnsafeTargets(t *testing.T) {
	f := &azureFake{}
	r := &azureTenantResolver{}
	d, ctx, decoration := azureFixture(t, f, r)
	invalidRepos := []string{"https://dev.azure.com/acme/project/_git/widget", "acme/widget", "acme/project/widget/other", "acme/../widget", "acme/%2f/widget", "acme//widget", "acme/project/wid?get"}
	for _, repository := range invalidRepos {
		bad := decoration
		bad.Target.Repository = repository
		if err := d.Decorate(ctx, bad); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("repository %q accepted: %v", repository, err)
		}
	}
	for _, pr := range []string{"0", "-1", "junk", "1?api-version=9"} {
		bad := decoration
		bad.Target.PullRequest = pr
		if err := d.Decorate(ctx, bad); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("PR %q accepted: %v", pr, err)
		}
	}
	bad := decoration
	bad.Target.CommitSHA = "head/other"
	if err := d.Decorate(ctx, bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unsafe SHA accepted: %v", err)
	}
	if r.calls != 0 || len(f.paths) != 0 {
		t.Fatal("invalid target reached credential resolver or network")
	}
	if err := d.Decorate(shared.WithTenant(context.Background(), "other-tenant"), decoration); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("cross-tenant decoration must fail closed: %v", err)
	}
	if len(f.paths) != 0 {
		t.Fatal("cross-tenant token lookup reached Azure DevOps")
	}
	if err := d.Decorate(ctx, decoration); err != nil {
		t.Fatal(err)
	}
	for _, auth := range f.authorization {
		if auth != "Basic "+base64.StdEncoding.EncodeToString([]byte(":tenant-pat")) {
			t.Fatal("wrong tenant's PAT reached Azure")
		}
	}
}

func TestAzureDevOpsDoesNotAdoptForeignOrInlineThreads(t *testing.T) {
	marker := azureCommentMarker + "\nNot ours"
	f := &azureFake{threads: []azureThread{
		{ID: 1, Comments: []azureThreadComment{{ID: 1, CommentType: "system", Content: marker}}},
		{ID: 2, Comments: []azureThreadComment{{ID: 1, CommentType: "text", Content: "foreign"}, {ID: 2, ParentCommentID: 1, CommentType: "text", Content: marker}}},
		{ID: 3, ThreadContext: map[string]any{"filePath": "/go.mod"}, Comments: []azureThreadComment{{ID: 1, CommentType: "text", Content: marker}}},
	}}
	d, ctx, decoration := azureFixture(t, f, azureStaticCredential(t))
	if err := d.Decorate(ctx, decoration); err != nil {
		t.Fatal(err)
	}
	if f.threadPosts != 1 || f.commentPatches != 0 || len(f.threads) != 4 {
		t.Fatal("the decorator adopted an inline, system or reply comment")
	}
}

func TestAzureDevOpsConcurrentRerunsCreateOneThread(t *testing.T) {
	f := &azureFake{}
	d, ctx, decoration := azureFixture(t, f, azureStaticCredential(t))
	var wg sync.WaitGroup
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); failures <- d.Decorate(ctx, decoration) }()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	if f.threadPosts != 1 || f.statusPosts != 1 {
		t.Fatalf("concurrent rerun duplicate: status=%d threads=%d", f.statusPosts, f.threadPosts)
	}
}

func TestAzureRepoPathEscapesNamesWithoutAllowingPathInjection(t *testing.T) {
	got, err := azureRepoPath("acme/Project Name/Service API")
	if err != nil {
		t.Fatal(err)
	}
	if got != "acme/Project%20Name/Service%20API" {
		t.Fatalf("escaped path = %q", got)
	}
	for _, unsafe := range []string{
		"acme/project/repo/extra",
		"acme/project/repo%2fother",
		"acme/project/../repo",
		"acme/project/repo?api-version=9",
	} {
		if _, err := azureRepoPath(unsafe); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("unsafe repository %q accepted: %v", unsafe, err)
		}
	}
}

func TestAzureDevOpsCredentialAndConstructorValidation(t *testing.T) {
	if _, err := NewAzureDevOpsDecorator(nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil credentials accepted: %v", err)
	}
	credentials := azureStaticCredential(t)
	if _, err := newAzureDevOpsDecorator(http.DefaultClient, "https://dev.azure.com/path", azureSCMHost, credentials); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("API path accepted: %v", err)
	}
	if _, err := newAzureDevOpsDecorator(http.DefaultClient, "https://dev.azure.com", "evil.example", credentials); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("credential host substitution accepted: %v", err)
	}
	d, ctx, decoration := azureFixture(t, &azureFake{}, NewStaticCredentialResolverMust(t, "github.com"))
	err := d.Decorate(ctx, decoration)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("wrong host credential accepted: %v", err)
	}
}

func NewStaticCredentialResolverMust(t *testing.T, host string) ports.GitCredentialResolver {
	t.Helper()
	r, err := NewStaticCredentialResolver(host, "pat", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAzureRenderedSummaryIncludesNewCodeDelta(t *testing.T) {
	newIssues, newCoverage := 3, 91.2
	got := azureRenderedSummary(ports.PRDecoration{
		Summary: "Azure summary",
		NewIssues: &newIssues,
		NewCoverage: &newCoverage,
	})
	for _, want := range []string{"Azure summary", "New issues: 3", "New coverage: 91.2%"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary missing %q: %q", want, got)
		}
	}
}

func TestAzureDevOpsBindsUnicodeSummaryToCommentLimit(t *testing.T) {
	decoration := ports.PRDecoration{Summary: strings.Repeat("dịch vụ ✅", 5000), Gate: qualitygate.Result{Passed: true}}
	body := azureCommentBody("0123456789abcdef", decoration)
	if len([]rune(body)) > azureCommentLimit || !strings.HasPrefix(body, azureCommentMarker) {
		t.Fatalf("comment violated limit or marker: runes=%d", len([]rune(body)))
	}
}
