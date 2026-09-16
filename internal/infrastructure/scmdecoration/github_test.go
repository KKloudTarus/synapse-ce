package scmdecoration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeGitCredentials struct {
	token []byte
	err   error
	ok    bool
}

func (f *fakeGitCredentials) ResolveGitCredential(_ context.Context, host string) (ports.GitCredential, bool, error) {
	_ = host
	if f.err != nil {
		return ports.GitCredential{}, false, f.err
	}
	return ports.GitCredential{Username: "x-access-token", Token: append([]byte(nil), f.token...)}, f.ok, nil
}

type fakeGitHubState struct {
	mu                   sync.Mutex
	statuses             []githubCommitStatus
	statusPosts          int
	checkID              int64
	checkExternalID      string
	checkPosts           int
	checkPatches         int
	checkAnnotations     int
	commentID            int64
	commentBody          string
	commentPosts         int
	commentPatches       int
	checkForbidden       bool
	partialCheckResponse bool
	authHeaders          []string
}

func (s *fakeGitHubState) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authHeaders = append(s.authHeaders, r.Header.Get("Authorization"))
	w.Header().Set("Content-Type", "application/json")

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widget/commits/head/statuses":
		_ = json.NewEncoder(w).Encode(s.statuses)
	case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/widget/statuses/head":
		var status githubCommitStatus
		_ = json.NewDecoder(r.Body).Decode(&status)
		s.statusPosts++
		s.statuses = append([]githubCommitStatus{status}, s.statuses...)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widget/commits/head/check-runs":
		response := githubCheckRuns{}
		if s.checkID != 0 {
			response.CheckRuns = []githubCheckRun{{ID: s.checkID, Name: githubCheckName, HeadSHA: "head", ExternalID: s.checkExternalID}}
		}
		_ = json.NewEncoder(w).Encode(response)
	case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/widget/check-runs":
		if s.checkForbidden {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"denied"}`))
			return
		}
		var payload githubCheckPayload
		_ = json.NewDecoder(r.Body).Decode(&payload)
		s.checkPosts++
		s.checkAnnotations += len(payload.Output.Annotations)
		if s.partialCheckResponse {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		s.checkID = 41
		s.checkExternalID = payload.ExternalID
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(githubCheckRun{ID: 41, Name: githubCheckName, HeadSHA: "head", ExternalID: payload.ExternalID})
	case r.Method == http.MethodPatch && r.URL.Path == "/repos/acme/widget/check-runs/41":
		var payload githubCheckPayload
		_ = json.NewDecoder(r.Body).Decode(&payload)
		s.checkPatches++
		s.checkAnnotations += len(payload.Output.Annotations)
		_ = json.NewEncoder(w).Encode(githubCheckRun{ID: 41, Name: githubCheckName, HeadSHA: "head", ExternalID: s.checkExternalID})
	case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widget/issues/7/comments":
		if s.commentID == 0 {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		_ = json.NewEncoder(w).Encode([]githubIssueComment{{ID: s.commentID, Body: s.commentBody}})
	case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/widget/issues/7/comments":
		var payload struct {
			Body string `json:"body"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		s.commentPosts++
		s.commentID = 51
		s.commentBody = payload.Body
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(githubIssueComment{ID: 51, Body: payload.Body})
	case r.Method == http.MethodPatch && r.URL.Path == "/repos/acme/widget/issues/comments/51":
		var payload struct {
			Body string `json:"body"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		s.commentPatches++
		s.commentBody = payload.Body
		_ = json.NewEncoder(w).Encode(githubIssueComment{ID: 51, Body: payload.Body})
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.String(), http.StatusNotFound)
	}
}

func addedFileChange(path string, first, last int) projectanalysis.FileChange {
	rows := make([]projectanalysis.DiffRow, 0, last-first+1)
	for line := first; line <= last; line++ {
		rows = append(rows, projectanalysis.DiffRow{Kind: projectanalysis.DiffRowAdded, NewLine: line})
	}
	return projectanalysis.FileChange{
		Status: projectanalysis.FileStatusAdded, NewPath: path,
		Added: []projectanalysis.LineRange{{Start: first, End: last}},
		Hunks: []projectanalysis.DiffHunk{{OldStart: 0, OldLines: 0, NewStart: first, NewLines: len(rows), Rows: rows}},
	}
}

func testDecoration(summary string) ports.PRDecoration {
	newIssues, newCoverage := 2, 83.5
	return ports.PRDecoration{
		Target: ports.PRDecorationTarget{Repository: "acme/widget", CommitSHA: "head", PullRequest: "7", TargetBranch: "main"},
		Gate:   qualitygate.Result{Passed: true}, Summary: summary, NewIssues: &newIssues, NewCoverage: &newCoverage,
		Annotations: []projectanalysis.Annotation{{
			FindingKey: "finding-1", RuleKey: "rule-1", RuleName: "Unsafe thing", Message: "details",
			Severity: shared.SeverityHigh, Location: finding.SourceLocation{File: "src/app.go", StartLine: 12, EndLine: 12},
		}},
		FileChanges: []projectanalysis.FileChange{addedFileChange("src/app.go", 1, 20)},
	}
}

func TestGitHubDecoratorCreatesThenUpdatesInPlace(t *testing.T) {
	state := &fakeGitHubState{}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	defer server.Close()
	credentials := &fakeGitCredentials{token: []byte("top-secret-token"), ok: true}
	decorator, err := newGitHubDecorator(server.Client(), server.URL, githubCredentialHost, credentials)
	if err != nil {
		t.Fatal(err)
	}

	if err := decorator.Decorate(context.Background(), testDecoration("first summary")); err != nil {
		t.Fatal(err)
	}
	rerun := testDecoration("updated summary")
	rerun.Annotations[0].Message = "updated details"
	if err := decorator.Decorate(context.Background(), rerun); err != nil {
		t.Fatal(err)
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	if state.statusPosts != 1 {
		t.Fatalf("status POSTs = %d, want 1 for unchanged state/context", state.statusPosts)
	}
	if state.checkPosts != 1 || state.checkPatches != 1 {
		t.Fatalf("check POST/PATCH = %d/%d, want 1/1 even when rerun annotation content changes", state.checkPosts, state.checkPatches)
	}
	if state.checkAnnotations != 1 {
		t.Fatalf("published annotations = %d, want rerun PATCH not to append duplicates", state.checkAnnotations)
	}
	if state.commentPosts != 1 || state.commentPatches != 1 {
		t.Fatalf("comment POST/PATCH = %d/%d, want 1/1", state.commentPosts, state.commentPatches)
	}
	if !strings.HasPrefix(state.commentBody, githubCommentMarker) || !strings.Contains(state.commentBody, "updated summary") || !strings.Contains(state.commentBody, "New issues: 2") || !strings.Contains(state.commentBody, "New coverage: 83.5%") {
		t.Fatalf("comment body = %q", state.commentBody)
	}
	for _, header := range state.authHeaders {
		if header != "Bearer top-secret-token" {
			t.Fatalf("authorization header = %q", header)
		}
	}
}

func TestGitHubDecoratorCheckPermissionFailureDoesNotBlockOtherSurfacesOrLeakToken(t *testing.T) {
	state := &fakeGitHubState{checkForbidden: true}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	defer server.Close()
	credentials := &fakeGitCredentials{token: []byte("do-not-leak-me"), ok: true}
	decorator, err := newGitHubDecorator(server.Client(), server.URL, githubCredentialHost, credentials)
	if err != nil {
		t.Fatal(err)
	}

	err = decorator.Decorate(context.Background(), testDecoration("summary"))
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("error = %v, want fail-soft provider error", err)
	}
	if strings.Contains(err.Error(), "do-not-leak-me") {
		t.Fatalf("credential leaked in error: %v", err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.statusPosts != 1 || state.commentPosts != 1 {
		t.Fatalf("status/comment POSTs = %d/%d, want both attempted despite check failure", state.statusPosts, state.commentPosts)
	}
}

func TestGitHubDecoratorRejectsPartialCheckCreateResponse(t *testing.T) {
	state := &fakeGitHubState{partialCheckResponse: true}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	defer server.Close()
	decorator, err := newGitHubDecorator(server.Client(), server.URL, githubCredentialHost, &fakeGitCredentials{token: []byte("token"), ok: true})
	if err != nil {
		t.Fatal(err)
	}

	err = decorator.Decorate(context.Background(), testDecoration("summary"))
	if err == nil || !strings.Contains(err.Error(), "returned no id") {
		t.Fatalf("error = %v, want partial check response failure", err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.statusPosts != 1 || state.commentPosts != 1 || state.checkPosts != 1 {
		t.Fatalf("status/check/comment POSTs = %d/%d/%d, want every independent surface attempted", state.statusPosts, state.checkPosts, state.commentPosts)
	}
}

func TestGitHubAnnotationsMapThroughPersistedHunksWithoutGuessingColumns(t *testing.T) {
	start, end := 0, 4
	items := []projectanalysis.Annotation{
		{
			FindingKey: "f", RuleKey: "rule", Severity: shared.SeverityHigh, Message: "message",
			Location: finding.SourceLocation{File: "src/new.go", StartLine: 39, EndLine: 43, StartColumn: &start, EndColumn: &end},
		},
		{
			FindingKey: "outside", RuleKey: "rule", Severity: shared.SeverityMedium, Message: "outside diff",
			Location: finding.SourceLocation{File: "src/new.go", StartLine: 90, EndLine: 90},
		},
	}
	changes := []projectanalysis.FileChange{{
		Status: projectanalysis.FileStatusRenamed, OldPath: "src/old.go", NewPath: "src/new.go",
		Hunks: []projectanalysis.DiffHunk{{
			OldStart: 40, OldLines: 4, NewStart: 40, NewLines: 4,
			Rows: []projectanalysis.DiffRow{
				{Kind: projectanalysis.DiffRowContext, OldLine: 40, NewLine: 40},
				{Kind: projectanalysis.DiffRowRemoved, OldLine: 41},
				{Kind: projectanalysis.DiffRowAdded, NewLine: 41},
				{Kind: projectanalysis.DiffRowContext, OldLine: 42, NewLine: 42},
				{Kind: projectanalysis.DiffRowContext, OldLine: 43, NewLine: 43},
			},
		}},
	}}

	mapped := githubAnnotations(items, changes)
	if len(mapped) != 1 {
		t.Fatalf("annotations = %d, want only the finding anchored in the persisted diff", len(mapped))
	}
	got := mapped[0]
	if got.Path != "src/new.go" || got.StartLine != 40 || got.EndLine != 43 {
		t.Fatalf("mapped location = %+v", got)
	}
	if got.AnnotationLevel != "failure" {
		t.Fatalf("annotation level = %q", got.AnnotationLevel)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "start_column") || strings.Contains(string(encoded), "end_column") {
		t.Fatalf("github annotation must stay line-only when source column units cannot be converted: %s", encoded)
	}
}

func TestGitHubCheckExternalIDOwnsLogicalTarget(t *testing.T) {
	decoration := testDecoration("summary")
	id := githubExternalID(decoration.Target)
	if !strings.HasPrefix(id, "synapse-code-quality:") {
		t.Fatalf("external id = %q", id)
	}
	changed := decoration.Target
	changed.PullRequest = "8"
	if got := githubExternalID(changed); got == id {
		t.Fatal("external id must distinguish different logical PR targets")
	}
}

func TestGitHubDecoratorDoesNotReuseForeignSameNameCheck(t *testing.T) {
	state := &fakeGitHubState{checkID: 99, checkExternalID: "someone-else"}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	defer server.Close()
	decorator, err := newGitHubDecorator(server.Client(), server.URL, githubCredentialHost, &fakeGitCredentials{token: []byte("token"), ok: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := decorator.Decorate(context.Background(), testDecoration("summary")); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.checkPosts != 1 || state.checkPatches != 0 {
		t.Fatalf("check POST/PATCH = %d/%d, want a new owned check instead of patching a foreign run", state.checkPosts, state.checkPatches)
	}
}

func TestGitHubRepoPathRejectsTraversalSegments(t *testing.T) {
	for _, slug := range []string{"../repo", "owner/..", "./repo", "owner/."} {
		if _, err := githubRepoPath(slug); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("githubRepoPath(%q) error = %v, want validation", slug, err)
		}
	}
	if got, err := githubRepoPath("acme/widget.go"); err != nil || got != "acme/widget.go" {
		t.Fatalf("valid repository path = %q, %v", got, err)
	}
}

func TestGitHubDecoratorConcurrentSameTargetCreatesOneCheckAndComment(t *testing.T) {
	state := &fakeGitHubState{}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	defer server.Close()
	decorator, err := newGitHubDecorator(server.Client(), server.URL, githubCredentialHost, &fakeGitCredentials{token: []byte("token"), ok: true})
	if err != nil {
		t.Fatal(err)
	}
	decoration := testDecoration("summary")
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- decorator.Decorate(context.Background(), decoration)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.checkPosts != 1 || state.commentPosts != 1 || state.statusPosts != 1 {
		t.Fatalf("creates status/check/comment = %d/%d/%d, want 1/1/1", state.statusPosts, state.checkPosts, state.commentPosts)
	}
}

func TestGitHubDecoratorBatchesCheckAnnotationsAtFifty(t *testing.T) {
	state := &fakeGitHubState{}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	defer server.Close()
	decorator, err := newGitHubDecorator(server.Client(), server.URL, githubCredentialHost, &fakeGitCredentials{token: []byte("token"), ok: true})
	if err != nil {
		t.Fatal(err)
	}
	decoration := testDecoration("summary")
	decoration.Annotations = make([]projectanalysis.Annotation, 105)
	for i := range decoration.Annotations {
		decoration.Annotations[i] = projectanalysis.Annotation{
			FindingKey: "finding", RuleKey: "rule", Message: "message", Severity: shared.SeverityMedium,
			Location: finding.SourceLocation{File: "src/app.go", StartLine: i + 1, EndLine: i + 1},
		}
	}
	decoration.FileChanges = []projectanalysis.FileChange{addedFileChange("src/app.go", 1, 105)}
	if err := decorator.Decorate(context.Background(), decoration); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.checkPosts != 1 || state.checkPatches != 2 || state.checkAnnotations != 105 {
		t.Fatalf("check POST/PATCH/annotations = %d/%d/%d, want 1/2/105", state.checkPosts, state.checkPatches, state.checkAnnotations)
	}
}

func TestGitHubDecoratorRequiresCredential(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	decorator, err := newGitHubDecorator(server.Client(), server.URL, githubCredentialHost, &fakeGitCredentials{ok: false})
	if err != nil {
		t.Fatal(err)
	}
	if err := decorator.Decorate(context.Background(), testDecoration("summary")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("error = %v, want validation", err)
	}
}
