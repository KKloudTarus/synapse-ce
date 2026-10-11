package azurepipelines

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type mockTransport func(*http.Request) (*http.Response, error)

func (fn mockTransport) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }
func response(status int, body, token string) *http.Response {
	h := make(http.Header)
	if token != "" {
		h.Set("x-ms-continuationtoken", token)
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body))}
}
func adapter(t *testing.T, fn mockTransport) *Adapter {
	t.Helper()
	u, err := url.Parse("https://dev.azure.com/example/My%20Project")
	if err != nil {
		t.Fatal(err)
	}
	return &Adapter{base: u, pat: "read-only-secret", client: &http.Client{Transport: fn, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func TestRegistrationAndOriginValidation(t *testing.T) {
	r := integration.NewRegistry()
	if err := Register(r); err != nil {
		t.Fatal(err)
	}
	d, err := r.Descriptor(Provider)
	if err != nil || !d.Supports(integration.CapabilityTestConnection) || !d.Supports(integration.CapabilityDiscover) || !d.Supports(integration.CapabilityReadRuns) {
		t.Fatalf("descriptor: %+v %v", d, err)
	}
	if err := Register(r); err == nil {
		t.Fatal("duplicate registration accepted")
	}
	for _, endpoint := range []string{"http://dev.azure.com/org/proj", "https://evil.example/org/proj", "https://dev.azure.com/org", "https://dev.azure.com/org/proj/extra", "https://dev.azure.com/org/proj?token=secret", "https://dev.azure.com/org/proj#fragment", "https://reader:token@dev.azure.com/org/proj", "https://dev.azure.com/org/%252e%252e", "https://dev.azure.com/org/proj/../other"} {
		item := integration.Integration{ID: "i1", TenantID: shared.ID("tenant"), Name: "Azure", Provider: Provider, Version: 1, Endpoint: endpoint}
		if _, err := New(item, integration.CredentialBundle{"pat": "read-only-secret"}, selfhosted.Rules{}); err == nil {
			t.Errorf("accepted unsafe endpoint %q", endpoint)
		}
	}
	item := integration.Integration{ID: "i1", TenantID: "tenant", Name: "Azure", Provider: Provider, Version: 1, Endpoint: "https://dev.azure.com/org/My%20Project"}
	a, err := New(item, integration.CredentialBundle{"pat": "read-only-secret"}, selfhosted.Rules{})
	if err != nil {
		t.Fatalf("safe endpoint rejected: %v", err)
	}
	a.(*Adapter).Close()
}

func TestConnectionUsesReadOnlyEndpointAndRedactedAuth(t *testing.T) {
	a := adapter(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.URL.Host != "dev.azure.com" || r.URL.EscapedPath() != "/example/My%20Project/_apis/build/definitions" || r.URL.Query().Get("$top") != "1" || r.URL.Query().Get("api-version") != "7.1" {
			t.Errorf("unexpected Azure request: %s %s", r.Method, r.URL.String())
		}
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(":read-only-secret"))
		if r.Header.Get("Authorization") != want {
			t.Error("incorrect read-only PAT auth")
		}
		return response(http.StatusOK, "{\"count\":0,\"value\":[]}", ""), nil
	})
	if err := a.TestConnection(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryContractPaginationStableKeysAndLinks(t *testing.T) {
	calls := 0
	a := adapter(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/example/My Project/_apis/build/definitions" {
			t.Errorf("path %q", r.URL.Path)
		}
		calls++
		switch r.URL.Query().Get("continuationToken") {
		case "":
			return response(200, "{\"count\":2,\"value\":[{\"id\":22,\"name\":\"Release\",\"path\":\"\\\\Platform\"},{\"id\":7,\"name\":\"Build\",\"path\":\"\\\\\"}]}", "next-page"), nil
		case "next-page":
			return response(200, "{\"count\":1,\"value\":[{\"id\":12,\"name\":\"Mobile\",\"path\":\"\\\\apps\\\\mobile\"}]}", ""), nil
		default:
			t.Errorf("unexpected continuation %q", r.URL.Query().Get("continuationToken"))
			return response(500, "{}", ""), nil
		}
	})
	pipelines, hash, err := a.DiscoverPipelines(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(pipelines) != 3 || len(hash) != 64 {
		t.Fatalf("calls=%d pipes=%+v hash=%s", calls, pipelines, hash)
	}
	want := []string{"/definitions/12", "/definitions/22", "/definitions/7"}
	for i, p := range pipelines {
		if p.ExternalKey != want[i] {
			t.Errorf("pipeline %d key=%q want=%q", i, p.ExternalKey, want[i])
		}
		if !strings.HasPrefix(p.URL, "https://dev.azure.com/example/My%20Project/_build?definitionId=") {
			t.Errorf("unsafe/malformed pipeline URL %q", p.URL)
		}
	}
	if pipelines[0].FullName != "apps/mobile/Mobile" || pipelines[1].FullName != "Platform/Release" {
		t.Fatalf("folders: %+v", pipelines)
	}
}

func TestReadRunsContractLifecycleRevisionAndCheckpoint(t *testing.T) {
	calls := 0
	a := adapter(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.URL.Query().Get("definitions") != "7" || r.URL.Query().Get("queryOrder") != "queueTimeDescending" {
			t.Errorf("request %s", r.URL.String())
		}
		calls++
		if calls == 1 {
			return response(200, "{\"count\":3,\"value\":[{\"id\":11,\"definition\":{\"id\":7},\"buildNumber\":\"2026.1\",\"status\":\"notStarted\",\"queueTime\":\"2026-09-27T00:00:00Z\"},{\"id\":12,\"definition\":{\"id\":7},\"buildNumber\":\"2026.2\",\"status\":\"inProgress\",\"sourceVersion\":\"sha-12\",\"sourceBranch\":\"refs/heads/main\",\"startTime\":\"2026-09-27T00:01:00Z\"},{\"id\":13,\"definition\":{\"id\":7},\"buildNumber\":\"2026.3\",\"status\":\"completed\",\"result\":\"partiallySucceeded\",\"sourceVersion\":\"sha-13\",\"startTime\":\"2026-09-27T00:02:00Z\",\"finishTime\":\"2026-09-27T00:03:00Z\"}]}", "second"), nil
		}
		return response(200, "{\"count\":2,\"value\":[{\"id\":14,\"definition\":{\"id\":7},\"status\":\"completed\",\"result\":\"failed\"},{\"id\":15,\"definition\":{\"id\":7},\"status\":\"completed\",\"result\":\"canceled\"}]}", ""), nil
	})
	runs, next, err := a.ReadRuns(context.Background(), integration.Binding{ExternalKey: "/definitions/7"}, "10")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || next != "15" || len(runs) != 5 {
		t.Fatalf("calls=%d checkpoint=%q runs=%+v", calls, next, runs)
	}
	wants := []struct {
		lc     integration.RunLifecycle
		result integration.RunResult
	}{
		{integration.RunQueued, integration.ResultUnknown}, {integration.RunRunning, integration.ResultUnknown},
		{integration.RunCompleted, integration.ResultUnstable}, {integration.RunCompleted, integration.ResultFailure},
		{integration.RunCompleted, integration.ResultAborted},
	}
	for i, r := range runs {
		if r.ProviderKey != strconv.Itoa(i+11) || r.PipelineKey != "/definitions/7" || r.Lifecycle != wants[i].lc || r.Result != wants[i].result {
			t.Errorf("run %d = %+v", i, r)
		}
		if !strings.HasPrefix(r.URL, "https://dev.azure.com/example/My%20Project/_build/results?buildId=") {
			t.Errorf("run URL %s", r.URL)
		}
	}
	if runs[0].QueuedAt == nil || runs[1].StartedAt == nil || runs[2].FinishedAt == nil || runs[2].Revision != "sha-13" {
		t.Fatalf("timestamp/revision loss %+v", runs)
	}
	if runs[1].FinishedAt != nil {
		t.Error("in-progress run has finish timestamp")
	}
}

func TestReadRunsCapsDeepHistoryAndAdvancesCheckpoint(t *testing.T) {
	page := func(high, low int) string {
		var body strings.Builder
		body.WriteString(`{"count":100,"value":[`)
		for id := high; id >= low; id-- {
			if id != high {
				body.WriteByte(',')
			}
			body.WriteString(`{"id":`)
			body.WriteString(strconv.Itoa(id))
			body.WriteString(`,"definition":{"id":7},"status":"completed","result":"succeeded"}`)
		}
		body.WriteString(`]}`)
		return body.String()
	}
	calls := 0
	a := adapter(t, func(r *http.Request) (*http.Response, error) {
		calls++
		switch calls {
		case 1:
			return response(200, page(300, 201), "older-1"), nil
		case 2:
			if r.URL.Query().Get("continuationToken") != "older-1" {
				t.Fatalf("second page continuation = %q", r.URL.Query().Get("continuationToken"))
			}
			return response(200, page(200, 101), "older-2"), nil
		default:
			t.Fatalf("deep history escaped the bounded poll: call %d", calls)
			return response(500, "{}", ""), nil
		}
	})
	runs, next, err := a.ReadRuns(context.Background(), integration.Binding{ExternalKey: "/definitions/7"}, "250")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(runs) != integration.MaxRunsPerPoll || next != "300" {
		t.Fatalf("calls=%d runs=%d checkpoint=%q", calls, len(runs), next)
	}
	if runs[0].ProviderKey != "300" || runs[len(runs)-1].ProviderKey != "101" {
		t.Fatalf("bounded window = first %q last %q", runs[0].ProviderKey, runs[len(runs)-1].ProviderKey)
	}
}

func TestStatusMapping(t *testing.T) {
	for _, tt := range []struct {
		status, result string
		wantLifecycle  integration.RunLifecycle
		wantResult     integration.RunResult
	}{
		{"notStarted", "", integration.RunQueued, integration.ResultUnknown}, {"postponed", "", integration.RunQueued, integration.ResultUnknown},
		{"inProgress", "", integration.RunRunning, integration.ResultUnknown}, {"cancelling", "", integration.RunRunning, integration.ResultUnknown},
		{"completed", "succeeded", integration.RunCompleted, integration.ResultSuccess}, {"completed", "partiallySucceeded", integration.RunCompleted, integration.ResultUnstable},
		{"completed", "failed", integration.RunCompleted, integration.ResultFailure}, {"completed", "canceled", integration.RunCompleted, integration.ResultAborted},
		{"completed", "future", integration.RunCompleted, integration.ResultUnknown},
	} {
		lc, result := normalizeStatus(tt.status, tt.result)
		if lc != tt.wantLifecycle || result != tt.wantResult {
			t.Errorf("%s/%s => %s/%s", tt.status, tt.result, lc, result)
		}
	}
}

func TestErrorHandlingAndCredentialSafeFailures(t *testing.T) {
	for _, tt := range []struct {
		status    int
		retryable bool
	}{
		{401, false}, {403, false}, {429, true}, {500, true}, {302, false},
	} {
		a := adapter(t, func(*http.Request) (*http.Response, error) {
			return response(tt.status, "{\"error\":\"read-only-secret\"}", ""), nil
		})
		err := a.TestConnection(context.Background())
		if err == nil || integration.IsRetryable(err) != tt.retryable || strings.Contains(err.Error(), "read-only-secret") {
			t.Errorf("HTTP %d: %v retryable=%t", tt.status, err, integration.IsRetryable(err))
		}
	}
	for _, tt := range []string{"not JSON", strings.Repeat("x", maxResponseBytes+1)} {
		a := adapter(t, func(*http.Request) (*http.Response, error) { return response(200, tt, ""), nil })
		if err := a.TestConnection(context.Background()); err == nil {
			t.Fatal("accepted malformed response")
		}
	}
	a := adapter(t, func(*http.Request) (*http.Response, error) {
		return response(200, "{\"count\":0,\"value\":[]}", "read-only-secret"), nil
	})
	if err := a.TestConnection(context.Background()); err == nil || strings.Contains(err.Error(), "read-only-secret") {
		t.Fatalf("bad continuation error: %v", err)
	}
	a = adapter(t, func(*http.Request) (*http.Response, error) {
		return nil, errors.New("read-only-secret leaked in network error")
	})
	if err := a.TestConnection(context.Background()); err == nil || strings.Contains(err.Error(), "read-only-secret") {
		t.Fatalf("credential leaked via HTTP transport: %v", err)
	}
}

func TestBoundedReadsAndHostileProviderFields(t *testing.T) {
	a := adapter(t, func(*http.Request) (*http.Response, error) {
		return response(200, "{\"count\":1,\"value\":[{\"id\":1,\"name\":\"read-only-secret\",\"path\":\"\\\\\"}]}", ""), nil
	})
	if _, _, err := a.DiscoverPipelines(context.Background(), ""); err == nil || strings.Contains(err.Error(), "read-only-secret") {
		t.Fatalf("credential echo %v", err)
	}
	a = adapter(t, func(*http.Request) (*http.Response, error) {
		return response(200, "{\"count\":1,\"value\":[{\"id\":2,\"definition\":{\"id\":9},\"status\":\"completed\",\"result\":\"succeeded\"}]}", ""), nil
	})
	if _, _, err := a.ReadRuns(context.Background(), integration.Binding{ExternalKey: "/definitions/7"}, ""); err == nil {
		t.Fatal("cross-definition build accepted")
	}
	a = adapter(t, func(*http.Request) (*http.Response, error) {
		return response(200, "{\"count\":1,\"value\":[{\"id\":2,\"definition\":{\"id\":7},\"buildNumber\":\"read-only-secret\"}]}", ""), nil
	})
	if _, _, err := a.ReadRuns(context.Background(), integration.Binding{ExternalKey: "/definitions/7"}, ""); err == nil || strings.Contains(err.Error(), "read-only-secret") {
		t.Fatalf("credential echoed in run %v", err)
	}
	a = adapter(t, func(*http.Request) (*http.Response, error) {
		return response(200, "{\"count\":1,\"value\":[{\"id\":7,\"name\":\"Build\"}]}", "same"), nil
	})
	if _, _, err := a.DiscoverPipelines(context.Background(), ""); err == nil {
		t.Fatal("repeated page accepted")
	}
	a = adapter(t, func(*http.Request) (*http.Response, error) {
		return response(200, "{\"count\":1,\"value\":[{\"id\":11,\"definition\":{\"id\":7}}]}", "same"), nil
	})
	if _, _, err := a.ReadRuns(context.Background(), integration.Binding{ExternalKey: "/definitions/7"}, ""); err == nil {
		t.Fatal("repeated run accepted")
	}
	a = adapter(t, func(*http.Request) (*http.Response, error) {
		return response(200, "{\"count\":0,\"value\":[]}", ""), nil
	})
	for _, key := range []string{"/definitions/1/../../2", "/definitions/0", "https://evil.example/definitions/7", "/definitions/not-an-int"} {
		if _, _, err := a.ReadRuns(context.Background(), integration.Binding{ExternalKey: key}, ""); err == nil {
			t.Errorf("invalid binding accepted: %q", key)
		}
	}
	if _, _, err := a.ReadRuns(context.Background(), integration.Binding{ExternalKey: "/definitions/7"}, "bad"); err == nil {
		t.Fatal("invalid checkpoint accepted")
	}
	limited := integration.WithOperationBudget(context.Background(), 1, 1)
	if err := a.TestConnection(limited); err == nil || !errors.Is(err, integration.ErrOperationBudgetExceeded) {
		t.Fatalf("operation budget not enforced: %v", err)
	}
}
