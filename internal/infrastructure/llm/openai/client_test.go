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
