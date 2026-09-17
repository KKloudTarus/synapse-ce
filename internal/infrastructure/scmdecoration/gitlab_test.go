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

const gitlabProjectPath = "/projects/acme%2Fwidget"

type fakeGitLabState struct {
	mu          sync.Mutex
	statuses    []gitlabCommitStatus
	statusPosts int
	noteID      int64
	noteBody    string
	notePosts   int
	notePuts    int
	noteForbid  bool
	tokens      []string
}

func (s *fakeGitLabState) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = append(s.tokens, r.Header.Get("PRIVATE-TOKEN"))
	w.Header().Set("Content-Type", "application/json")

	switch {
	case r.Method == http.MethodGet && r.URL.EscapedPath() == gitlabProjectPath+"/repository/commits/head/statuses":
		_ = json.NewEncoder(w).Encode(s.statuses)
	case r.Method == http.MethodPost && r.URL.EscapedPath() == gitlabProjectPath+"/statuses/head":
		var body struct {
			State       string `json:"state"`
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.statusPosts++
		s.statuses = append([]gitlabCommitStatus{{Name: body.Name, Status: body.State, Description: body.Description}}, s.statuses...)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	case r.Method == http.MethodGet && r.URL.EscapedPath() == gitlabProjectPath+"/merge_requests/7/notes":
		if s.noteID == 0 {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		_ = json.NewEncoder(w).Encode([]gitlabNote{{ID: s.noteID, Body: s.noteBody}})
	case r.Method == http.MethodPost && r.URL.EscapedPath() == gitlabProjectPath+"/merge_requests/7/notes":
		if s.noteForbid {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"denied"}`))
			return
		}
		var payload struct {
			Body string `json:"body"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		s.notePosts++
		s.noteID = 51
		s.noteBody = payload.Body
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(gitlabNote{ID: 51, Body: payload.Body})
	case r.Method == http.MethodPut && r.URL.EscapedPath() == gitlabProjectPath+"/merge_requests/7/notes/51":
		var payload struct {
			Body string `json:"body"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		s.notePuts++
		s.noteBody = payload.Body
		_ = json.NewEncoder(w).Encode(gitlabNote{ID: 51, Body: payload.Body})
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.EscapedPath(), http.StatusNotFound)
	}
}

func TestGitLabDecoratorCreatesThenUpdatesInPlace(t *testing.T) {
	state := &fakeGitLabState{}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	defer server.Close()
	credentials := &fakeGitCredentials{token: []byte("glpat-top-secret"), ok: true}
	decorator, err := newGitLabDecorator(server.Client(), server.URL, gitlabCredentialHost, credentials)
	if err != nil {
		t.Fatal(err)
	}

	if err := decorator.Decorate(context.Background(), testDecoration("first summary")); err != nil {
		t.Fatal(err)
	}
	rerun := testDecoration("updated summary")
	if err := decorator.Decorate(context.Background(), rerun); err != nil {
		t.Fatal(err)
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	if state.statusPosts != 1 {
		t.Fatalf("status POSTs = %d, want 1 for unchanged state/name", state.statusPosts)
	}
	if state.notePosts != 1 || state.notePuts != 1 {
		t.Fatalf("note POST/PUT = %d/%d, want 1/1", state.notePosts, state.notePuts)
	}
	if !strings.HasPrefix(state.noteBody, gitlabNoteMarker) || !strings.Contains(state.noteBody, "updated summary") ||
		!strings.Contains(state.noteBody, "New issues: 2") || !strings.Contains(state.noteBody, "New coverage: 83.5%") {
		t.Fatalf("note body = %q", state.noteBody)
	}
	for _, token := range state.tokens {
		if token != "glpat-top-secret" {
			t.Fatalf("PRIVATE-TOKEN header = %q", token)
		}
	}
}

func TestGitLabDecoratorNoteFailureDoesNotBlockStatusOrLeakToken(t *testing.T) {
	state := &fakeGitLabState{noteForbid: true}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	defer server.Close()
	credentials := &fakeGitCredentials{token: []byte("do-not-leak-me"), ok: true}
	decorator, err := newGitLabDecorator(server.Client(), server.URL, gitlabCredentialHost, credentials)
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
	if state.statusPosts != 1 {
		t.Fatalf("status POSTs = %d, want status attempted despite note failure", state.statusPosts)
	}
}

func TestGitLabDecoratorConcurrentSameTargetCreatesOneNote(t *testing.T) {
	state := &fakeGitLabState{}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	defer server.Close()
	decorator, err := newGitLabDecorator(server.Client(), server.URL, gitlabCredentialHost, &fakeGitCredentials{token: []byte("token"), ok: true})
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
	if state.notePosts != 1 || state.statusPosts != 1 {
		t.Fatalf("status/note POSTs = %d/%d, want 1/1", state.statusPosts, state.notePosts)
	}
}

func TestGitLabDecoratorPostsFailedStateForFailedGate(t *testing.T) {
	state := &fakeGitLabState{}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	defer server.Close()
	decorator, err := newGitLabDecorator(server.Client(), server.URL, gitlabCredentialHost, &fakeGitCredentials{token: []byte("token"), ok: true})
	if err != nil {
		t.Fatal(err)
	}
	decoration := testDecoration("summary")
	decoration.Gate = qualitygate.Result{Passed: false}
	if err := decorator.Decorate(context.Background(), decoration); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.statusPosts != 1 || len(state.statuses) == 0 || state.statuses[0].Status != "failed" {
		t.Fatalf("posted status = %+v (posts=%d), want GitLab state token \"failed\"", state.statuses, state.statusPosts)
	}
}

func TestGitLabDecoratorSkipsUnchangedFailedStatusWithoutRepost(t *testing.T) {
	state := &fakeGitLabState{statuses: []gitlabCommitStatus{{Name: gitlabStatusName, Status: "failed", Description: "Synapse quality gate failed"}}}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	defer server.Close()
	decorator, err := newGitLabDecorator(server.Client(), server.URL, gitlabCredentialHost, &fakeGitCredentials{token: []byte("token"), ok: true})
	if err != nil {
		t.Fatal(err)
	}
	decoration := testDecoration("summary")
	decoration.Gate = qualitygate.Result{Passed: false}
	if err := decorator.Decorate(context.Background(), decoration); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.statusPosts != 0 {
		t.Fatalf("status POSTs = %d, want 0 when the exact failed status already exists", state.statusPosts)
	}
}

// gitlabPaginatingHandler serves 100 filler entries on page 1 and the owned entry on page 2, so the
// page loop and the owned-on-a-later-page path are exercised end to end.
type gitlabPaginatingHandler struct {
	mu          sync.Mutex
	statusPosts int
	notePosts   int
	notePuts    int
}

func (h *gitlabPaginatingHandler) serve(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	page := r.URL.Query().Get("page")
	switch {
	case r.Method == http.MethodGet && r.URL.EscapedPath() == gitlabProjectPath+"/repository/commits/head/statuses":
		if page == "1" {
			filler := make([]gitlabCommitStatus, 100)
			for i := range filler {
				filler[i] = gitlabCommitStatus{Name: "other/check", Status: "success"}
			}
			_ = json.NewEncoder(w).Encode(filler)
			return
		}
		_ = json.NewEncoder(w).Encode([]gitlabCommitStatus{{Name: gitlabStatusName, Status: "success", Description: "Synapse quality gate passed"}})
	case r.Method == http.MethodPost && r.URL.EscapedPath() == gitlabProjectPath+"/statuses/head":
		h.statusPosts++
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	case r.Method == http.MethodGet && r.URL.EscapedPath() == gitlabProjectPath+"/merge_requests/7/notes":
		if page == "1" {
			filler := make([]gitlabNote, 100)
			for i := range filler {
				filler[i] = gitlabNote{ID: int64(i + 1000), Body: "human note"}
			}
			_ = json.NewEncoder(w).Encode(filler)
			return
		}
		_ = json.NewEncoder(w).Encode([]gitlabNote{{ID: 51, Body: gitlabNoteBody(testDecoration("summary"))}})
	case r.Method == http.MethodPut && r.URL.EscapedPath() == gitlabProjectPath+"/merge_requests/7/notes/51":
		h.notePuts++
		_, _ = w.Write([]byte(`{}`))
	case r.Method == http.MethodPost && r.URL.EscapedPath() == gitlabProjectPath+"/merge_requests/7/notes":
		h.notePosts++
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":52}`))
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.EscapedPath(), http.StatusNotFound)
	}
}

func TestGitLabDecoratorPaginatesToOwnedStatusAndNote(t *testing.T) {
	h := &gitlabPaginatingHandler{}
	server := httptest.NewServer(http.HandlerFunc(h.serve))
	defer server.Close()
	decorator, err := newGitLabDecorator(server.Client(), server.URL, gitlabCredentialHost, &fakeGitCredentials{token: []byte("token"), ok: true})
	if err != nil {
		t.Fatal(err)
	}
	// The owned status is identical (page 2) so no repost; the owned note exists (page 2) with an
	// identical body so no PUT. A broken page loop would miss both and write duplicates.
	if err := decorator.Decorate(context.Background(), testDecoration("summary")); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.statusPosts != 0 {
		t.Fatalf("status POSTs = %d, want 0 (owned status found on page 2)", h.statusPosts)
	}
	if h.notePosts != 0 || h.notePuts != 0 {
		t.Fatalf("note POST/PUT = %d/%d, want 0/0 (owned note found unchanged on page 2)", h.notePosts, h.notePuts)
	}
}

func TestGitLabDecoratorDoesNotAdoptSystemNote(t *testing.T) {
	state := &fakeGitLabState{noteID: 51, noteBody: gitlabNoteMarker + "\n\nplanted", notePosts: 0}
	// Mark the pre-existing owned-looking note as a GitLab system note; the adapter must not adopt it.
	systemNoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.EscapedPath() == gitlabProjectPath+"/repository/commits/head/statuses":
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodPost && r.URL.EscapedPath() == gitlabProjectPath+"/statuses/head":
			state.statusPosts++
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && r.URL.EscapedPath() == gitlabProjectPath+"/merge_requests/7/notes":
			_ = json.NewEncoder(w).Encode([]gitlabNote{{ID: 51, Body: gitlabNoteMarker + "\n\nplanted", System: true}})
		case r.Method == http.MethodPost && r.URL.EscapedPath() == gitlabProjectPath+"/merge_requests/7/notes":
			state.notePosts++
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(gitlabNote{ID: 60})
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.EscapedPath(), http.StatusNotFound)
		}
	}))
	defer systemNoteServer.Close()
	decorator, err := newGitLabDecorator(systemNoteServer.Client(), systemNoteServer.URL, gitlabCredentialHost, &fakeGitCredentials{token: []byte("token"), ok: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := decorator.Decorate(context.Background(), testDecoration("summary")); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.notePosts != 1 {
		t.Fatalf("note POSTs = %d, want 1: a system note carrying the marker must not be adopted", state.notePosts)
	}
}

func TestGitLabDecoratorRendersUnavailableNewCodeWithoutMisleadingZero(t *testing.T) {
	state := &fakeGitLabState{}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	defer server.Close()
	decorator, err := newGitLabDecorator(server.Client(), server.URL, gitlabCredentialHost, &fakeGitCredentials{token: []byte("token"), ok: true})
	if err != nil {
		t.Fatal(err)
	}
	decoration := testDecoration("summary")
	decoration.NewIssues = nil
	decoration.NewCoverage = nil
	decoration.NewCoverageReason = "no_coverage_report"
	if err := decorator.Decorate(context.Background(), decoration); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !strings.Contains(state.noteBody, "New issues: unavailable") || !strings.Contains(state.noteBody, "New coverage: unavailable (no_coverage_report)") {
		t.Fatalf("note body must report unavailable, never a misleading 0: %q", state.noteBody)
	}
}

func TestGitLabDecoratorRequiresCredential(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	decorator, err := newGitLabDecorator(server.Client(), server.URL, gitlabCredentialHost, &fakeGitCredentials{ok: false})
	if err != nil {
		t.Fatal(err)
	}
	if err := decorator.Decorate(context.Background(), testDecoration("summary")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("error = %v, want validation", err)
	}
}

func TestGitLabProjectIDEncodesNestedGroupsRejectsTraversal(t *testing.T) {
	for _, slug := range []string{"onlyone", "../group/project", "group/..", "group/./project", ""} {
		if _, err := gitlabProjectID(slug); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("gitlabProjectID(%q) error = %v, want validation", slug, err)
		}
	}
	got, err := gitlabProjectID("group/subgroup/project")
	if err != nil || got != "group%2Fsubgroup%2Fproject" {
		t.Fatalf("nested project id = %q, %v", got, err)
	}
}

func TestGitLabCodeQualityReportIsDeterministicAndSchemaValid(t *testing.T) {
	decoration := ports.PRDecoration{
		Target: ports.PRDecorationTarget{Repository: "acme/widget", CommitSHA: "head", PullRequest: "7", TargetBranch: "main"},
		Gate:   qualitygate.Result{Passed: false},
		Annotations: []projectanalysis.Annotation{
			{FindingKey: "f-b", RuleKey: "rule-b", Message: "second", Severity: shared.SeverityMedium, Location: finding.SourceLocation{File: "src/z.go", StartLine: 30, EndLine: 30}},
			{FindingKey: "f-a", RuleKey: "rule-a", Message: "first", Severity: shared.SeverityCritical, Location: finding.SourceLocation{File: "src/a.go", StartLine: 5, EndLine: 5}},
			// Duplicate identity must collapse to one entry.
			{FindingKey: "f-a", RuleKey: "rule-a", Message: "first", Severity: shared.SeverityCritical, Location: finding.SourceLocation{File: "src/a.go", StartLine: 5, EndLine: 5}},
			// A finding without a resolvable line must be omitted, never emitted at line 0.
			{FindingKey: "f-nolines", RuleKey: "rule-c", Message: "no line", Severity: shared.SeverityLow, Location: finding.SourceLocation{File: "src/c.go", StartLine: 0, EndLine: 0}},
		},
	}

	first, err := GitLabCodeQualityReport(decoration)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GitLabCodeQualityReport(decoration)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("report is not deterministic:\n%s\n---\n%s", first, second)
	}

	var issues []codeClimateIssue
	if err := json.Unmarshal(first, &issues); err != nil {
		t.Fatalf("report is not valid json: %v", err)
	}
	if len(issues) != 2 {
		t.Fatalf("issues = %d, want 2 (dedup + drop line-less)", len(issues))
	}
	if issues[0].Location.Path != "src/a.go" || issues[1].Location.Path != "src/z.go" {
		t.Fatalf("issues not sorted by path: %+v", issues)
	}
	if issues[0].Severity != "blocker" || issues[1].Severity != "major" {
		t.Fatalf("severity mapping = %q/%q, want blocker/major", issues[0].Severity, issues[1].Severity)
	}
	for _, issue := range issues {
		if issue.Fingerprint == "" || issue.Description == "" || issue.Location.Lines.Begin < 1 {
			t.Fatalf("code-climate entry is incomplete: %+v", issue)
		}
	}
	if issues[0].Fingerprint == issues[1].Fingerprint {
		t.Fatal("distinct findings must have distinct fingerprints")
	}
}

func TestGitLabCodeClimateSeverityMapsEveryLevel(t *testing.T) {
	cases := map[shared.Severity]string{
		shared.SeverityCritical: "blocker",
		shared.SeverityHigh:     "critical",
		shared.SeverityMedium:   "major",
		shared.SeverityLow:      "minor",
		shared.SeverityInfo:     "info",
		shared.Severity(""):     "info",
	}
	for severity, want := range cases {
		if got := gitlabCodeClimateSeverity(severity); got != want {
			t.Fatalf("gitlabCodeClimateSeverity(%q) = %q, want %q", severity, got, want)
		}
	}
}
