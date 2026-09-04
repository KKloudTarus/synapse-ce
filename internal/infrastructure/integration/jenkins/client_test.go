package jenkins

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func testAdapter(t *testing.T, transport http.RoundTripper) *Adapter {
	t.Helper()
	base, err := url.Parse("https://jenkins.example.com/jenkins")
	if err != nil {
		t.Fatal(err)
	}
	return &Adapter{descriptor: descriptor, base: base, client: &http.Client{Transport: transport}, username: "reader", token: "token"}
}

func jsonResponse(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestDiscoverPipelinesHandlesFoldersMultibranchAndEscapedNames(t *testing.T) {
	adapter := testAdapter(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if username, password, ok := request.BasicAuth(); !ok || username != "reader" || password != "token" {
			t.Fatalf("missing Jenkins basic auth")
		}
		switch request.URL.Path {
		case "/jenkins/api/json":
			return jsonResponse(`{"jobs":[{"name":"Platform","url":"https://jenkins.example.com/jenkins/job/Platform/","_class":"com.cloudbees.hudson.plugins.folder.Folder"},{"name":"Release","url":"https://jenkins.example.com/jenkins/job/Release/","_class":"hudson.model.FreeStyleProject"}]}`), nil
		case "/jenkins/job/Platform/api/json":
			return jsonResponse(`{"jobs":[{"name":"App","url":"https://jenkins.example.com/jenkins/job/Platform/job/App/","_class":"org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject"},{"name":"Deploy A B","url":"https://jenkins.example.com/jenkins/job/Platform/job/Deploy%20A%20B/","_class":"org.jenkinsci.plugins.workflow.job.WorkflowJob"}]}`), nil
		case "/jenkins/job/Platform/job/App/api/json":
			return jsonResponse(`{"jobs":[{"name":"main","url":"https://jenkins.example.com/jenkins/job/Platform/job/App/job/main/","_class":"org.jenkinsci.plugins.workflow.job.WorkflowJob"}]}`), nil
		default:
			t.Fatalf("unexpected Jenkins path %q", request.URL.Path)
			return nil, nil
		}
	}))
	pipelines, checkpoint, err := adapter.DiscoverPipelines(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint == "" || len(pipelines) != 4 {
		t.Fatalf("pipelines=%+v checkpoint=%q", pipelines, checkpoint)
	}
	want := map[string]string{
		"/job/Release": "job", "/job/Platform/job/App": "multibranch",
		"/job/Platform/job/Deploy A B": "pipeline", "/job/Platform/job/App/job/main": "pipeline",
	}
	for _, pipeline := range pipelines {
		if want[pipeline.ExternalKey] != pipeline.Kind {
			t.Errorf("pipeline %+v, want kind %q", pipeline, want[pipeline.ExternalKey])
		}
		if !strings.HasPrefix(pipeline.URL, "https://jenkins.example.com/jenkins/job/") {
			t.Errorf("pipeline URL left base path: %q", pipeline.URL)
		}
	}
}

func TestReadRunsNormalizesQueueBuildsResultsAndSCMGaps(t *testing.T) {
	adapter := testAdapter(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/jenkins/queue/api/json":
			return jsonResponse(`{"items":[{"id":42,"url":"https://jenkins.example.com/jenkins/queue/item/42/","inQueueSince":1788163200000,"task":{"url":"https://jenkins.example.com/jenkins/job/Platform/job/App/job/main/"},"executable":{"number":7,"url":"https://jenkins.example.com/jenkins/job/Platform/job/App/job/main/7/"}}]}`), nil
		case "/jenkins/job/Platform/job/App/job/main/api/json":
			return jsonResponse(`{"builds":[{"number":7,"url":"https://jenkins.example.com/jenkins/job/Platform/job/App/job/main/7/","building":false,"result":"SUCCESS","timestamp":1788163200000,"duration":1200,"queueId":42,"actions":[{"lastBuiltRevision":{"SHA1":"abc123","branch":[{"SHA1":"abc123","name":"refs/heads/main"}]}}],"changeSet":{"items":[]}},{"number":8,"url":"https://jenkins.example.com/jenkins/job/Platform/job/App/job/main/8/","building":false,"result":"UNSTABLE","timestamp":1788163300000,"duration":500,"queueId":0,"actions":[],"changeSet":{"items":[{"commitId":"one"},{"commitId":"two"}]}}]}`), nil
		default:
			t.Fatalf("unexpected Jenkins path %q", request.URL.Path)
			return nil, nil
		}
	}))
	runs, checkpoint, err := adapter.ReadRuns(context.Background(), integration.Binding{ExternalKey: "/job/Platform/job/App/job/main"}, "6")
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint != "8" || len(runs) != 2 {
		t.Fatalf("runs=%+v checkpoint=%q", runs, checkpoint)
	}
	if !strings.HasSuffix(runs[0].ProviderKey, ":queue:42") || runs[0].Lifecycle != integration.RunCompleted || runs[0].Result != integration.ResultSuccess || runs[0].Revision != "abc123" || runs[0].Branch != "refs/heads/main" {
		t.Fatalf("queue/build transition = %+v", runs[0])
	}
	if runs[1].Result != integration.ResultUnstable || runs[1].Revision != "" {
		t.Fatalf("ambiguous change-set build = %+v", runs[1])
	}
}

func TestRunProviderKeyScopesBuildNumbersToPipeline(t *testing.T) {
	first := runProviderKey("/job/platform/job/main", "build", 1)
	second := runProviderKey("/job/platform/job/release", "build", 1)
	if first == second || !strings.HasSuffix(first, ":build:1") || len(first) > 128 {
		t.Fatalf("provider keys first=%q second=%q", first, second)
	}
	if queued := runProviderKey("/job/platform/job/main", "queue", 42); queued == first || !strings.HasSuffix(queued, ":queue:42") {
		t.Fatalf("queued provider key=%q", queued)
	}
}

func TestNormalizeResultCoversJenkinsOutcomes(t *testing.T) {
	for raw, want := range map[string]integration.RunResult{
		"SUCCESS": integration.ResultSuccess, "FAILURE": integration.ResultFailure, "UNSTABLE": integration.ResultUnstable,
		"ABORTED": integration.ResultAborted, "NOT_BUILT": integration.ResultNotBuilt, "": integration.ResultUnknown, "future": integration.ResultUnknown,
	} {
		if got := normalizeResult(raw); got != want {
			t.Errorf("normalizeResult(%q)=%q, want %q", raw, got, want)
		}
	}
}

func TestJenkinsRequestsRejectTraversalCrossOriginAndOversizedResponses(t *testing.T) {
	adapter := testAdapter(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxResponseBytes+1)))}, nil
	}))
	for _, resource := range []string{"/job/a/../admin", "/job/a/%2e%2e/admin"} {
		if _, err := adapter.resourceURL(resource, nil); err == nil {
			t.Errorf("resourceURL(%q) accepted traversal", resource)
		}
	}
	if _, err := adapter.externalKey("https://attacker.example/job/a/"); err == nil {
		t.Fatal("cross-origin Jenkins job URL accepted")
	}
	var output any
	if err := adapter.get(context.Background(), "/api/json", nil, &output); err == nil || integration.IsRetryable(err) {
		t.Fatalf("oversized response error = %v, want permanent", err)
	}
}

func TestJenkinsRejectsCredentialReflectionInProviderControlledFields(t *testing.T) {
	for _, body := range []string{
		`{"jobs":[{"name":"release-token","url":"https://jenkins.example.com/jenkins/job/release/","_class":"hudson.model.FreeStyleProject"}]}`,
		`{"jobs":[{"name":"release","url":"https://jenkins.example.com/jenkins/job/reader/","_class":"hudson.model.FreeStyleProject"}]}`,
	} {
		adapter := testAdapter(t, roundTripFunc(func(*http.Request) (*http.Response, error) { return jsonResponse(body), nil }))
		if _, _, err := adapter.DiscoverPipelines(context.Background(), ""); err == nil || integration.IsRetryable(err) {
			t.Fatalf("credential-bearing Jenkins response was not rejected permanently: %v", err)
		}
	}

	adapter := testAdapter(t, http.DefaultTransport)
	if _, err := adapter.safeRunURL("https://reader:token@jenkins.example.com/jenkins/job/release/1/", "/job/release/1"); err == nil {
		t.Fatal("credential-bearing build URL was accepted")
	}
}
