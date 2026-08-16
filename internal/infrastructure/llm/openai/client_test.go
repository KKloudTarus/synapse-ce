package openai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestChatParsesToolCalls(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k1" {
			t.Errorf("missing/wrong bearer: %q", r.Header.Get("Authorization"))
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		// OpenAI returns function.arguments as a JSON *string*.
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"get_scope","arguments":"{\"engagement_id\":\"e1\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL, "k1", "m1", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Chat(context.Background(), ports.ChatRequest{
		Messages: []agent.Message{{Role: agent.RoleUser, Content: "get scope for e1"}},
		Tools:    []agent.ToolSchema{{Name: "get_scope", Description: "scope", Parameters: json.RawMessage(`{"type":"object"}`)}},
	})
	if err != nil {
		t.Fatalf("chat: %v", err)
	}
	if len(resp.ToolCalls) != 1 || resp.ToolCalls[0].Name != "get_scope" {
		t.Fatalf("expected 1 get_scope tool call, got %+v", resp.ToolCalls)
	}
	// Arguments must be the raw JSON (the string was unwrapped), unmarshalable to typed params.
	var args struct {
		EngagementID string `json:"engagement_id"`
	}
	if err := json.Unmarshal(resp.ToolCalls[0].Arguments, &args); err != nil || args.EngagementID != "e1" {
		t.Fatalf("tool args not typed-decodable: %s err=%v", resp.ToolCalls[0].Arguments, err)
	}
	if resp.FinishReason != "tool_calls" || resp.Usage.TotalTokens != 15 {
		t.Errorf("finish/usage wrong: %q %+v", resp.FinishReason, resp.Usage)
	}
	// The request advertised the tool with tool_choice=auto + the default model.
	if gotBody["model"] != "m1" || gotBody["tool_choice"] != "auto" {
		t.Errorf("request body wrong: model=%v tool_choice=%v", gotBody["model"], gotBody["tool_choice"])
	}
	if _, ok := gotBody["tools"]; !ok {
		t.Error("tools not sent in request")
	}
}

func TestChatRetriesTransientThenSucceeds(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable) // 5xx → transient → retried
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{}}`))
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "", "m", time.Second)
	resp, err := c.Chat(context.Background(), ports.ChatRequest{Messages: []agent.Message{{Role: agent.RoleUser, Content: "hi"}}})
	if err != nil {
		t.Fatalf("should succeed after a transient 503: %v", err)
	}
	if resp.Content != "OK" || atomic.LoadInt32(&n) != 2 {
		t.Errorf("want 1 retry then OK, got content=%q calls=%d", resp.Content, n)
	}
}

func TestChatTerminalOnBadRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest) // 400 → terminal, NOT retried
		_, _ = w.Write([]byte(`{"error":{"message":"bad"}}`))
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "", "m", time.Second)
	_, err := c.Chat(context.Background(), ports.ChatRequest{Messages: []agent.Message{{Role: agent.RoleUser, Content: "hi"}}})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("400 must be a terminal ErrValidation, got %v", err)
	}
}

// TestChatSendsExplicitTemperatureZero pins the wire contract deterministic callers depend on: an
// explicit temperature 0 (greedy decoding) must reach the provider. Dropping it silently falls back to
// the provider default (~1.0), which is the difference between a reproducible verdict and a sampled one
// — the FP-triage proposer/verifier and the judgment verifier all ask for 0.
// TestChatRequestsNonStreamingResponse pins that the adapter always sends stream:false.
// This client decodes ONE non-streaming JSON body, but several OpenAI-compatible gateways
// default to text/event-stream when the field is absent. Omitting it made every LLM call fail
// with "decode provider response: invalid character 'd' looking for beginning of value"
// (the 'd' of the SSE "data:" prefix), which halted agent sessions and AI triage.
func TestChatRequestsNonStreamingResponse(t *testing.T) {
	body := captureChatBody(t, ports.ChatRequest{
		Messages: []agent.Message{{Role: agent.RoleUser, Content: "hi"}},
	})
	got, ok := body["stream"]
	if !ok {
		t.Fatal("stream omitted; a gateway defaulting to SSE returns an undecodable body")
	}
	if got != false {
		t.Errorf("stream = %v, want false (this client cannot parse an SSE stream)", got)
	}
}

func TestChatSendsExplicitTemperatureZero(t *testing.T) {
	body := captureChatBody(t, ports.ChatRequest{
		Temperature: ports.Temp(0),
		Messages:    []agent.Message{{Role: agent.RoleUser, Content: "hi"}},
	})
	got, ok := body["temperature"]
	if !ok {
		t.Fatal("temperature omitted from the request – the provider default applies")
	}
	if got != float64(0) {
		t.Errorf("temperature = %v, want 0", got)
	}
}

// TestChatOmitsTemperatureWhenUnset is the other half of that contract: a caller expressing no
// preference must not be forced onto 0 – the provider default still applies.
func TestChatOmitsTemperatureWhenUnset(t *testing.T) {
	body := captureChatBody(t, ports.ChatRequest{
		Messages: []agent.Message{{Role: agent.RoleUser, Content: "hi"}},
	})
	if v, ok := body["temperature"]; ok {
		t.Errorf("temperature sent (%v) although the caller expressed no preference", v)
	}
}

// TestChatSendsCurrentOutputTokenLimit pins the current OpenAI Chat Completions contract:
// MaxTokens is a provider-neutral port field, and the adapter spells it max_completion_tokens.
func TestChatSendsCurrentOutputTokenLimit(t *testing.T) {
	body := captureChatBody(t, ports.ChatRequest{
		MaxTokens: 512,
		Messages:  []agent.Message{{Role: agent.RoleUser, Content: "hi"}},
	})
	if got := body["max_completion_tokens"]; got != float64(512) {
		t.Errorf("max_completion_tokens = %v, want 512", got)
	}
	if got, ok := body["max_tokens"]; ok {
		t.Errorf("deprecated max_tokens also sent: %v", got)
	}
}

func TestChatOmitsNonPositiveOutputTokenLimit(t *testing.T) {
	for _, limit := range []int{0, -1} {
		body := captureChatBody(t, ports.ChatRequest{
			MaxTokens: limit,
			Messages:  []agent.Message{{Role: agent.RoleUser, Content: "hi"}},
		})
		if got, ok := body["max_completion_tokens"]; ok {
			t.Errorf("limit %d sent max_completion_tokens=%v", limit, got)
		}
		if got, ok := body["max_tokens"]; ok {
			t.Errorf("limit %d sent max_tokens=%v", limit, got)
		}
	}
}

func TestChatFallsBackToLegacyOutputTokenLimitAndCachesDialect(t *testing.T) {
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		bodies = append(bodies, body)
		if _, modern := body["max_completion_tokens"]; modern && body["model"] == "m" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"unknown field max_completion_tokens; use max_tokens"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{}}`))
	}))
	defer srv.Close()

	c, _ := New(srv.URL, "", "m", time.Second)
	req := ports.ChatRequest{MaxTokens: 64, Messages: []agent.Message{{Role: agent.RoleUser, Content: "hi"}}}
	for i := 0; i < 2; i++ {
		resp, err := c.Chat(context.Background(), req)
		if err != nil || resp.Content != "OK" {
			t.Fatalf("call %d: resp=%+v err=%v", i+1, resp, err)
		}
	}
	// Dialect learning is per model. A current model routed through the same gateway must still start
	// with max_completion_tokens rather than inheriting the legacy model's max_tokens spelling.
	modernReq := req
	modernReq.Model = "current-model"
	if _, err := c.Chat(context.Background(), modernReq); err != nil {
		t.Fatalf("current model after legacy negotiation: %v", err)
	}
	if len(bodies) != 4 {
		t.Fatalf("requests = %d, want modern probe + legacy retry + cached legacy call + current-model call", len(bodies))
	}
	if got := bodies[0]["max_completion_tokens"]; got != float64(64) {
		t.Errorf("modern probe max_completion_tokens = %v, want 64", got)
	}
	for i := 1; i < len(bodies); i++ {
		if i == 3 {
			if got := bodies[i]["max_completion_tokens"]; got != float64(64) {
				t.Errorf("current model max_completion_tokens = %v, want 64", got)
			}
			if got, ok := bodies[i]["max_tokens"]; ok {
				t.Errorf("current model inherited legacy max_tokens=%v", got)
			}
			continue
		}
		if got := bodies[i]["max_tokens"]; got != float64(64) {
			t.Errorf("legacy request %d max_tokens = %v, want 64", i, got)
		}
		if got, ok := bodies[i]["max_completion_tokens"]; ok {
			t.Errorf("legacy request %d also sent max_completion_tokens=%v", i, got)
		}
	}
}

func TestChatDoesNotFallbackOnUnrelatedBadRequest(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"messages are invalid"}}`))
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "", "m", time.Second)

	_, err := c.Chat(context.Background(), ports.ChatRequest{
		MaxTokens: 64,
		Messages:  []agent.Message{{Role: agent.RoleUser, Content: "hi"}},
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unrelated 400 must remain terminal validation error, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("unrelated 400 was retried %d time(s)", got)
	}
}

func TestChatFailsClosedOnTruncatedOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"score\": 90"},"finish_reason":"length"}],"usage":{"completion_tokens":16}}`))
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "", "m", time.Second)

	resp, err := c.Chat(context.Background(), ports.ChatRequest{
		MaxTokens: 16,
		Messages:  []agent.Message{{Role: agent.RoleUser, Content: "hi"}},
	})
	if !errors.Is(err, ErrOutputTruncated) {
		t.Fatalf("finish_reason=length error = %v, want ErrOutputTruncated", err)
	}
	if resp.FinishReason != "length" || resp.Usage.CompletionTokens != 16 {
		t.Errorf("truncated response metadata lost: %+v", resp)
	}
}

// captureChatBody runs one Chat against a stub gateway and returns the decoded request body.
func captureChatBody(t *testing.T, req ports.ChatRequest) map[string]any {
	t.Helper()
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &body); err != nil {
			t.Errorf("request body is not JSON: %v", err)
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{}"},"finish_reason":"stop"}],"usage":{}}`))
	}))
	defer srv.Close()
	c, err := New(srv.URL, "", "m", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Chat(context.Background(), req); err != nil {
		t.Fatalf("chat: %v", err)
	}
	return body
}

func TestNewValidates(t *testing.T) {
	if _, err := New("", "k", "m", 0); !errors.Is(err, shared.ErrValidation) {
		t.Error("empty base must fail validation")
	}
}

// TestLiveAgainstGateway is a manual/host smoke test against a real OpenAI-compatible LLM
// gateway. Gated on SYNAPSE_LLM_BASE_URL so CI + dev skip it; run with the gateway env set.
func TestLiveAgainstGateway(t *testing.T) {
	base := os.Getenv("SYNAPSE_LLM_BASE_URL")
	if base == "" {
		t.Skip("set SYNAPSE_LLM_BASE_URL (+ _API_KEY, _MODEL) to run the live gateway smoke")
	}
	c, err := New(base, os.Getenv("SYNAPSE_LLM_API_KEY"), os.Getenv("SYNAPSE_LLM_MODEL"), 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	req := ports.ChatRequest{
		Messages: []agent.Message{
			{Role: agent.RoleSystem, Content: "You may only call the provided tool. Do not answer in prose."},
			{Role: agent.RoleUser, Content: "Get the scope for engagement e1."},
		},
		Tools: []agent.ToolSchema{{Name: "get_scope", Description: "Return the scope for an engagement", Parameters: json.RawMessage(`{"type":"object","properties":{"engagement_id":{"type":"string"}},"required":["engagement_id"]}`)}},
	}
	// The gateway upstream rate-limits with an intermittent ~1-2min token cooldown, so ride
	// it out: retry a handful of times before giving up. A persistent failure → skip (an
	// upstream outage is not an adapter fault); a success → assert the tool-call round-trip.
	var resp ports.ChatResponse
	for attempt := 1; attempt <= 10; attempt++ {
		resp, err = c.Chat(context.Background(), req)
		if err == nil {
			break
		}
		t.Logf("attempt %d: provider not ready (%v) – waiting out the cooldown", attempt, err)
		time.Sleep(20 * time.Second)
	}
	if err != nil {
		t.Skipf("gateway upstream stayed unhealthy across retries – skipping: %v", err)
	}
	t.Logf("live: finish=%s tool_calls=%d usage=%+v content=%q", resp.FinishReason, len(resp.ToolCalls), resp.Usage, strings.TrimSpace(resp.Content))
	if len(resp.ToolCalls) == 0 {
		t.Logf("NOTE: model returned prose, not a tool_call – prompt/model may need tuning for tool-use")
	} else if resp.ToolCalls[0].Name != "get_scope" {
		t.Errorf("unexpected tool call: %s", resp.ToolCalls[0].Name)
	}
}
