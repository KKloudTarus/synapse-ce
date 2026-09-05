package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

// TestPushAnalysisPostsTheResultAndReadsTheVerdict pins the wire contract between the CLI and the
// import route: the path, the bearer token, the body shape, and the verdict read back.
func TestPushAnalysisPostsTheResultAndReadsTheVerdict(t *testing.T) {
	var got struct {
		method, path, auth, contentType string
		body                            map[string]json.RawMessage
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method, got.path, got.auth, got.contentType = r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got.body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"an-1","origin":"ci","created_at":"2026-09-05T12:00:00Z","gate":{"passed":false},"gate_info":{"name":"synapse-way"},"issues":{"total":7},"new_code":{"counts":{"total":3}}}`))
	}))
	defer srv.Close()

	target := pushTarget{server: srv.URL + "/", project: "my app", token: "tok", ci: projectanalysis.CIContext{Provider: "github-actions", Branch: "main", RunURL: "https://github.com/acme/app/actions/runs/1"}}
	result := &scauc.ScanResult{Target: "/work/app", SourceCommit: "abc"}
	analysis, console, err := pushAnalysis(context.Background(), srv.Client(), target, result)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	// The server sees the decoded path: a key with a space arrives as that key, escaped exactly once
	// on the wire and not twice.
	if got.method != http.MethodPost || got.path != "/api/v1/projects/my app/analyses/import" {
		t.Errorf("request = %s %s", got.method, got.path)
	}
	if got.auth != "Bearer tok" || got.contentType != "application/json" {
		t.Errorf("headers auth=%q content-type=%q", got.auth, got.contentType)
	}
	if _, ok := got.body["ci"]; !ok {
		t.Error("body has no ci block")
	}
	var sent scauc.ScanResult
	if err := json.Unmarshal(got.body["result"], &sent); err != nil || sent.Target != "/work/app" || sent.SourceCommit != "abc" {
		t.Errorf("result was not sent intact: %v %+v", err, sent)
	}
	if analysis.ID != "an-1" || analysis.Origin != "ci" || analysis.Gate.Passed || analysis.GateInfo.Name != "synapse-way" || analysis.Issues.Total != 7 || analysis.NewCode.Counts.Total != 3 {
		t.Errorf("verdict not read back: %+v", analysis)
	}
	if !strings.HasSuffix(console, "/code-quality/projects/my%20app/activity") || !strings.HasPrefix(console, srv.URL) {
		t.Errorf("console link = %q", console)
	}
}

// TestPushAnalysisSurfacesTheServersRefusal makes a refused import an error with the server's reason,
// so a pipeline log says why the record did not happen rather than only that it did not.
func TestPushAnalysisSurfacesTheServersRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}))
	defer srv.Close()
	_, _, err := pushAnalysis(context.Background(), srv.Client(), pushTarget{server: srv.URL, project: "nope", token: "tok"}, &scauc.ScanResult{})
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want the server's status and reason", err)
	}
}

// TestPushAnalysisDoesNotFollowRedirects keeps the bearer token from being re-sent wherever a server
// might point.
func TestPushAnalysisDoesNotFollowRedirects(t *testing.T) {
	leaked := false
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization") != ""
		w.WriteHeader(http.StatusCreated)
	}))
	defer sink.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	client := pushHTTPClient()
	_, _, err := pushAnalysis(context.Background(), client, pushTarget{server: srv.URL, project: "app", token: "tok"}, &scauc.ScanResult{})
	if err == nil {
		t.Fatal("a redirected import was reported as success")
	}
	if leaked {
		t.Fatal("the bearer token was re-sent to the redirect target")
	}
}

// TestPushTargetValidation fails fast on a misconfigured pipeline before a scan runs.
func TestPushTargetValidation(t *testing.T) {
	cases := []struct {
		name   string
		target pushTarget
		wantOK bool
	}{
		{"disabled is fine", pushTarget{}, true},
		{"complete", pushTarget{server: "https://synapse.example", project: "app", token: "t"}, true},
		{"missing project", pushTarget{server: "https://synapse.example", token: "t"}, false},
		{"missing token", pushTarget{server: "https://synapse.example", project: "app"}, false},
		{"relative server", pushTarget{server: "synapse.example", project: "app", token: "t"}, false},
		{"plain http to a remote host", pushTarget{server: "http://synapse.internal:8080", project: "app", token: "t"}, false},
		{"plain http accepted explicitly", pushTarget{server: "http://synapse.internal:8080", project: "app", token: "t", insecureHTTP: true}, true},
		{"plain http to loopback", pushTarget{server: "http://127.0.0.1:8080", project: "app", token: "t"}, true},
		{"plain http to localhost", pushTarget{server: "http://localhost:8080", project: "app", token: "t"}, true},
		{"project key with a slash", pushTarget{server: "https://synapse.example", project: "app/../other", token: "t"}, false},
		{"project key uppercase", pushTarget{server: "https://synapse.example", project: "App", token: "t"}, false},
		{"bad run url", pushTarget{server: "https://synapse.example", project: "app", token: "t", ci: projectanalysis.CIContext{RunURL: "ftp://x"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.target.validate(); (err == nil) != tc.wantOK {
				t.Fatalf("validate() = %v, want ok=%v", err, tc.wantOK)
			}
		})
	}
}

// TestCIContextFromEnv fills the run's identity from the provider's well-known variables, with an
// explicit flag always winning.
func TestCIContextFromEnv(t *testing.T) {
	github := map[string]string{
		"GITHUB_ACTIONS": "true", "GITHUB_REF_NAME": "feature/x", "GITHUB_RUN_ID": "99", "GITHUB_ACTOR": "octocat",
		"GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "acme/app",
	}
	got := ciContextFromEnv(projectanalysis.CIContext{Branch: "explicit"}, func(k string) string { return github[k] })
	if got.Provider != "github-actions" || got.Branch != "explicit" || got.RunID != "99" || got.Actor != "octocat" || got.RunURL != "https://github.com/acme/app/actions/runs/99" {
		t.Errorf("github context = %+v", got)
	}
	gitlab := map[string]string{"GITLAB_CI": "true", "CI_COMMIT_REF_NAME": "main", "CI_PIPELINE_ID": "5", "CI_PIPELINE_URL": "https://gitlab.example/acme/app/-/pipelines/5"}
	got = ciContextFromEnv(projectanalysis.CIContext{}, func(k string) string { return gitlab[k] })
	if got.Provider != "gitlab-ci" || got.Branch != "main" || got.RunURL != gitlab["CI_PIPELINE_URL"] {
		t.Errorf("gitlab context = %+v", got)
	}
	got = ciContextFromEnv(projectanalysis.CIContext{}, func(string) string { return "" })
	if !got.Empty() {
		t.Errorf("no provider should leave the context empty: %+v", got)
	}
}
