package scmdecoration

import (
	"context"
	"encoding/base64"
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
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	bitbucketRepoBase   = "/repositories/acme/widget"
	bitbucketBuildByKey = bitbucketRepoBase + "/commit/head/statuses/build/synapse-code-quality"
	bitbucketBuildPost  = bitbucketRepoBase + "/commit/head/statuses/build"
	bitbucketReportPut  = bitbucketRepoBase + "/commit/head/reports/synapse-code-quality"
	bitbucketAnnPost    = bitbucketRepoBase + "/commit/head/reports/synapse-code-quality/annotations"
	bitbucketComments   = bitbucketRepoBase + "/pullrequests/7/comments"
)

type fakeBitbucketState struct {
	mu              sync.Mutex
	build           *bitbucketBuildStatus
	buildPosts      int
	reportPuts      int
	annotationPosts int
	annotationCount int
	commentID       int64
	commentBody     string
	commentPosts    int
	commentPuts     int
	forbidComment   bool
	authHeaders     []string
}

func (s *fakeBitbucketState) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authHeaders = append(s.authHeaders, r.Header.Get("Authorization"))
	w.Header().Set("Content-Type", "application/json")

	switch {
	case r.Method == http.MethodGet && r.URL.Path == bitbucketBuildByKey:
		if s.build == nil {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(s.build)
	case r.Method == http.MethodPost && r.URL.Path == bitbucketBuildPost:
		var body bitbucketBuildStatus
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.buildPosts++
		s.build = &body
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(body)
	case r.Method == http.MethodPut && r.URL.Path == bitbucketReportPut:
		s.reportPuts++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	case r.Method == http.MethodPost && r.URL.Path == bitbucketAnnPost:
		var batch []bitbucketAnnotation
		_ = json.NewDecoder(r.Body).Decode(&batch)
		s.annotationPosts++
		s.annotationCount += len(batch)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	case r.Method == http.MethodGet && r.URL.Path == bitbucketComments:
		page := bitbucketCommentPage{}
		if s.commentID != 0 {
			c := bitbucketComment{ID: s.commentID}
			c.Content.Raw = s.commentBody
			page.Values = []bitbucketComment{c}
		}
		_ = json.NewEncoder(w).Encode(page)
	case r.Method == http.MethodPost && r.URL.Path == bitbucketComments:
		if s.forbidComment {
			http.Error(w, `{"error":"denied"}`, http.StatusForbidden)
			return
		}
		var payload struct {
			Content struct {
				Raw string `json:"raw"`
			} `json:"content"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		s.commentPosts++
		s.commentID = 51
		s.commentBody = payload.Content.Raw
		w.WriteHeader(http.StatusCreated)
		c := bitbucketComment{ID: 51}
		c.Content.Raw = payload.Content.Raw
		_ = json.NewEncoder(w).Encode(c)
	case r.Method == http.MethodPut && r.URL.Path == bitbucketComments+"/51":
		var payload struct {
			Content struct {
				Raw string `json:"raw"`
			} `json:"content"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		s.commentPuts++
		s.commentBody = payload.Content.Raw
		_, _ = w.Write([]byte(`{}`))
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
	}
}

func TestBitbucketDecoratorCreatesThenUpdatesInPlace(t *testing.T) {
	state := &fakeBitbucketState{}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	defer server.Close()
	credentials := &fakeGitCredentials{token: []byte("app-password-secret"), ok: true}
	decorator, err := newBitbucketDecorator(server.Client(), server.URL, bitbucketCredentialHost, credentials)
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
	if state.buildPosts != 1 {
		t.Fatalf("build POSTs = %d, want 1 for unchanged state (GET-by-key skip on rerun)", state.buildPosts)
	}
	if state.reportPuts != 2 {
		t.Fatalf("report PUTs = %d, want 2 (idempotent upsert each run)", state.reportPuts)
	}
	if state.annotationPosts != 2 || state.annotationCount != 2 {
		t.Fatalf("annotation POST/count = %d/%d, want one batch of one annotation per run", state.annotationPosts, state.annotationCount)
	}
	if state.commentPosts != 1 || state.commentPuts != 1 {
		t.Fatalf("comment POST/PUT = %d/%d, want 1/1", state.commentPosts, state.commentPuts)
	}
	if !strings.HasPrefix(state.commentBody, bitbucketCommentMarker) || !strings.Contains(state.commentBody, "updated summary") ||
		!strings.Contains(state.commentBody, "New issues: 2") || !strings.Contains(state.commentBody, "New coverage: 83.5%") {
		t.Fatalf("comment body = %q", state.commentBody)
	}
	for _, header := range state.authHeaders {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:app-password-secret"))
		if header != want {
			t.Fatalf("authorization header = %q, want basic auth", header)
		}
	}
}

func TestBitbucketDecoratorPostsFailedStatusAndReportResult(t *testing.T) {
	state := &fakeBitbucketState{}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	defer server.Close()
	decorator, err := newBitbucketDecorator(server.Client(), server.URL, bitbucketCredentialHost, &fakeGitCredentials{token: []byte("token"), ok: true})
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
	if state.build == nil || state.build.State != "FAILED" {
		t.Fatalf("build state = %+v, want FAILED", state.build)
	}
}

func TestBitbucketDecoratorCommentFailureDoesNotBlockStatusOrLeakToken(t *testing.T) {
	state := &fakeBitbucketState{forbidComment: true}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	defer server.Close()
	credentials := &fakeGitCredentials{token: []byte("do-not-leak-me"), ok: true}
	decorator, err := newBitbucketDecorator(server.Client(), server.URL, bitbucketCredentialHost, credentials)
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
	if state.buildPosts != 1 || state.reportPuts != 1 {
		t.Fatalf("build/report writes = %d/%d, want both attempted despite comment failure", state.buildPosts, state.reportPuts)
	}
}

func TestBitbucketDecoratorConcurrentSameTargetCreatesOneComment(t *testing.T) {
	state := &fakeBitbucketState{}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	defer server.Close()
	decorator, err := newBitbucketDecorator(server.Client(), server.URL, bitbucketCredentialHost, &fakeGitCredentials{token: []byte("token"), ok: true})
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
	if state.commentPosts != 1 || state.buildPosts != 1 {
		t.Fatalf("build/comment POSTs = %d/%d, want 1/1", state.buildPosts, state.commentPosts)
	}
}

func TestBitbucketDecoratorBatchesAnnotationsAtHundred(t *testing.T) {
	state := &fakeBitbucketState{}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	defer server.Close()
	decorator, err := newBitbucketDecorator(server.Client(), server.URL, bitbucketCredentialHost, &fakeGitCredentials{token: []byte("token"), ok: true})
	if err != nil {
		t.Fatal(err)
	}
	decoration := testDecoration("summary")
	decoration.Annotations = make([]projectanalysis.Annotation, 150)
	for i := range decoration.Annotations {
		decoration.Annotations[i] = projectanalysis.Annotation{
			FindingKey: "finding", RuleKey: "rule", Message: "message", Severity: shared.SeverityMedium,
			Location: finding.SourceLocation{File: "src/app.go", StartLine: i + 1, EndLine: i + 1},
		}
	}
	decoration.FileChanges = []projectanalysis.FileChange{addedFileChange("src/app.go", 1, 150)}
	if err := decorator.Decorate(context.Background(), decoration); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.annotationPosts != 2 || state.annotationCount != 150 {
		t.Fatalf("annotation POST/count = %d/%d, want 2 batches totalling 150", state.annotationPosts, state.annotationCount)
	}
}

func TestBitbucketRepoPathRejectsTraversalSegments(t *testing.T) {
	for _, slug := range []string{"../repo", "workspace/..", "./repo", "only-one", "a/b/c"} {
		if _, err := bitbucketRepoPath(slug); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("bitbucketRepoPath(%q) error = %v, want validation", slug, err)
		}
	}
	if got, err := bitbucketRepoPath("acme/widget"); err != nil || got != "acme/widget" {
		t.Fatalf("valid repository path = %q, %v", got, err)
	}
}

func TestBitbucketAnnotationTypeAndSeverityMapping(t *testing.T) {
	typeCases := map[rule.Type]string{
		rule.TypeVulnerability:   "VULNERABILITY",
		rule.TypeSecurityHotspot: "VULNERABILITY",
		rule.TypeBug:             "BUG",
		rule.TypeCodeSmell:       "CODE_SMELL",
		rule.Type(""):            "CODE_SMELL",
	}
	for ruleType, want := range typeCases {
		if got := bitbucketAnnotationType(ruleType); got != want {
			t.Fatalf("bitbucketAnnotationType(%q) = %q, want %q", ruleType, got, want)
		}
	}
	severityCases := map[shared.Severity]string{
		shared.SeverityCritical: "CRITICAL",
		shared.SeverityHigh:     "HIGH",
		shared.SeverityMedium:   "MEDIUM",
		shared.SeverityLow:      "LOW",
		shared.SeverityInfo:     "LOW",
	}
	for severity, want := range severityCases {
		if got := bitbucketAnnotationSeverity(severity); got != want {
			t.Fatalf("bitbucketAnnotationSeverity(%q) = %q, want %q", severity, got, want)
		}
	}
}

func TestBitbucketRelativeNextStaysOnHost(t *testing.T) {
	got, ok := bitbucketRelativeNext("https://api.bitbucket.org/2.0/repositories/acme/widget/pullrequests/7/comments?page=2")
	if !ok || got != "/repositories/acme/widget/pullrequests/7/comments?page=2" {
		t.Fatalf("relative next = %q ok=%v", got, ok)
	}
	for _, bad := range []string{"https://evil.example/2.0/x", "https://api.bitbucket.org/other/path", ""} {
		if _, ok := bitbucketRelativeNext(bad); ok {
			t.Fatalf("bitbucketRelativeNext(%q) accepted an off-host or non-API cursor", bad)
		}
	}
}

func TestBitbucketDecoratorRendersUnavailableNewCodeWithoutMisleadingZero(t *testing.T) {
	state := &fakeBitbucketState{}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	defer server.Close()
	decorator, err := newBitbucketDecorator(server.Client(), server.URL, bitbucketCredentialHost, &fakeGitCredentials{token: []byte("token"), ok: true})
	if err != nil {
		t.Fatal(err)
	}
	decoration := testDecoration("summary")
	decoration.NewIssues = nil
	decoration.NewCoverage = nil
	if err := decorator.Decorate(context.Background(), decoration); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !strings.Contains(state.commentBody, "New issues: unavailable") || !strings.Contains(state.commentBody, "New coverage: unavailable") {
		t.Fatalf("comment must report unavailable, never a misleading 0: %q", state.commentBody)
	}
}

type fixedUserCredentials struct {
	username string
	token    []byte
}

func (f *fixedUserCredentials) ResolveGitCredential(_ context.Context, _ string) (ports.GitCredential, bool, error) {
	return ports.GitCredential{Username: f.username, Token: append([]byte(nil), f.token...)}, true, nil
}

func TestBitbucketDecoratorDefaultsBasicUsernameForTokenAuth(t *testing.T) {
	var captured string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if captured == "" {
			captured = r.Header.Get("Authorization")
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == bitbucketBuildByKey:
			http.Error(w, `{}`, http.StatusNotFound)
		case r.URL.Path == bitbucketComments:
			_, _ = w.Write([]byte(`{"values":[]}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()
	decorator, err := newBitbucketDecorator(server.Client(), server.URL, bitbucketCredentialHost, &fixedUserCredentials{username: "", token: []byte("secret")})
	if err != nil {
		t.Fatal(err)
	}
	if err := decorator.Decorate(context.Background(), testDecoration("summary")); err != nil {
		t.Fatal(err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-token-auth:secret"))
	if captured != want {
		t.Fatalf("authorization = %q, want empty username to default to x-token-auth", captured)
	}
}

func TestBitbucketDecoratorFollowsCommentPaginationToOwnedMarker(t *testing.T) {
	var posts int
	ownedBody := bitbucketCommentBody(testDecoration("summary"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == bitbucketBuildByKey:
			http.Error(w, `{}`, http.StatusNotFound)
		case r.Method == http.MethodGet && r.URL.Path == bitbucketComments:
			if r.URL.Query().Get("page") == "2" {
				resp := map[string]any{"values": []map[string]any{{"id": 51, "content": map[string]string{"raw": ownedBody}}}}
				_ = json.NewEncoder(w).Encode(resp)
				return
			}
			// Page 1: a full page of foreign comments plus an absolute next cursor on the Bitbucket host.
			values := make([]map[string]any, 0, 3)
			for i := 0; i < 3; i++ {
				values = append(values, map[string]any{"id": i + 1, "content": map[string]string{"raw": "human note"}})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"values": values,
				"next":   "https://api.bitbucket.org/2.0/repositories/acme/widget/pullrequests/7/comments?page=2",
			})
		case r.Method == http.MethodPut && r.URL.Path == bitbucketComments+"/51":
			// Owned comment found on page 2 with an identical body, so no PUT is expected; fail if it happens.
			t.Errorf("unexpected PUT: owned comment body was unchanged")
		case r.Method == http.MethodPost && r.URL.Path == bitbucketComments:
			posts++
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":99}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()
	decorator, err := newBitbucketDecorator(server.Client(), server.URL, bitbucketCredentialHost, &fakeGitCredentials{token: []byte("token"), ok: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := decorator.Decorate(context.Background(), testDecoration("summary")); err != nil {
		t.Fatal(err)
	}
	if posts != 0 {
		t.Fatalf("comment POSTs = %d, want 0: the owned comment must be found on page 2", posts)
	}
}

func TestBitbucketAnnotationsDropFindingsOutsideDiff(t *testing.T) {
	items := []projectanalysis.Annotation{
		{FindingKey: "in", RuleKey: "rule", Message: "inside", Severity: shared.SeverityHigh, Location: finding.SourceLocation{File: "src/app.go", StartLine: 5, EndLine: 5}},
		{FindingKey: "out", RuleKey: "rule", Message: "outside", Severity: shared.SeverityHigh, Location: finding.SourceLocation{File: "src/app.go", StartLine: 900, EndLine: 900}},
	}
	changes := []projectanalysis.FileChange{addedFileChange("src/app.go", 1, 20)}
	got := bitbucketAnnotations(items, changes)
	if len(got) != 1 || got[0].Line != 5 || got[0].Path != "src/app.go" {
		t.Fatalf("annotations = %+v, want only the in-diff finding", got)
	}
}

func TestBitbucketReportDetailsTruncatedToReportLimit(t *testing.T) {
	big := strings.Repeat("x", bitbucketReportDetail+5_000)
	decoration := testDecoration(big)
	report := bitbucketReport{Details: truncateUTF8(bitbucketRenderedSummary(decoration), bitbucketReportDetail)}
	if got := len([]rune(report.Details)); got > bitbucketReportDetail {
		t.Fatalf("report details rune length = %d, want <= %d (Bitbucket Code Insights cap)", got, bitbucketReportDetail)
	}
}

func TestBitbucketDecoratorRequiresCredential(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	decorator, err := newBitbucketDecorator(server.Client(), server.URL, bitbucketCredentialHost, &fakeGitCredentials{ok: false})
	if err != nil {
		t.Fatal(err)
	}
	if err := decorator.Decorate(context.Background(), testDecoration("summary")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("error = %v, want validation", err)
	}
}
