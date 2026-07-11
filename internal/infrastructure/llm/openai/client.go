// Package openai implements ports.LLM against an OpenAI-compatible Chat Completions API
// – the reference provider, tested against the LLM gateway. It is
// the ONLY thing that knows the wire shape; the orchestrator depends only on ports.LLM, so
// other providers can slot in later with no orchestrator change. The model only
// PROPOSES tool-calls here; this adapter never decides what runs. The API
// key is held in memory and NEVER logged.
package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ErrUnavailable is a TRANSIENT provider failure (timeout / 429 / 5xx / upstream cooldown):
// the orchestrator may back off + retry. A malformed request maps to shared.ErrValidation.
var ErrUnavailable = errors.New("llm provider unavailable")

const (
	defaultTimeout = 60 * time.Second
	maxRespBytes   = 8 << 20 // cap the provider response we read
	retries        = 2       // bounded retries on transient errors
)

// Client is an OpenAI-compatible Chat Completions client.
type Client struct {
	base  string // e.g. http://localhost:20128/v1 (no trailing slash)
	key   string // bearer token; never logged
	model string // default model id (a ChatRequest.Model overrides)
	http  *http.Client
}

var _ ports.LLM = (*Client)(nil)

// New validates and builds the client. base is the API root (…/v1); a non-positive timeout
// uses the package default. key may be empty for a local gateway that needs no auth.
func New(base, key, model string, timeout time.Duration) (*Client, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		return nil, fmt.Errorf("%w: llm base URL is required", shared.ErrValidation)
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{base: base, key: strings.TrimSpace(key), model: strings.TrimSpace(model), http: &http.Client{Timeout: timeout}}, nil
}

// BaseURL is the configured endpoint (safe to log – never returns the key).
func (c *Client) BaseURL() string { return c.base }

// --- wire types (OpenAI Chat Completions shape) ---

type wireReq struct {
	Model          string       `json:"model"`
	Messages       []wireMsg    `json:"messages"`
	Tools          []wireTool   `json:"tools,omitempty"`
	ToolChoice     string       `json:"tool_choice,omitempty"`
	ResponseFormat *wireRespFmt `json:"response_format,omitempty"`
	Temperature    *float64     `json:"temperature,omitempty"`
}
type wireMsg struct {
	Role       string         `json:"role"`
	Content    string         `json:"content,omitempty"`
	ToolCalls  []wireToolCall `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
}
type wireTool struct {
	Type     string       `json:"type"` // "function"
	Function wireToolFunc `json:"function"`
}
type wireToolFunc struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}
type wireToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"` // OpenAI sends args as a JSON *string*
	} `json:"function"`
}
type wireRespFmt struct {
	Type       string          `json:"type"` // "json_schema"
	JSONSchema json.RawMessage `json:"json_schema,omitempty"`
}
type wireResp struct {
	Choices []struct {
		Message      wireMsg `json:"message"`
		FinishReason string  `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Chat issues one turn and returns the model's response (incl. any PROPOSED tool-calls).
func (c *Client) Chat(ctx context.Context, req ports.ChatRequest) (ports.ChatResponse, error) {
	model := req.Model
	if model == "" {
		model = c.model
	}
	body := wireReq{Model: model, Messages: toWireMessages(req.Messages)}
	if len(req.Tools) > 0 {
		body.Tools = toWireTools(req.Tools)
		body.ToolChoice = "auto"
	}
	if len(req.ResponseSchema) > 0 {
		// Optional schema-constrained output. A gateway that doesn't support it returns a
		// 400; the orchestrator may retry without the schema (tool-calling still works).
		body.ResponseFormat = &wireRespFmt{Type: "json_schema", JSONSchema: req.ResponseSchema}
	}
	if req.Temperature > 0 {
		t := req.Temperature
		body.Temperature = &t
	}
	// NOTE: no max_tokens/max_completion_tokens – the field name differs across OpenAI model
	// generations (the upstream is a large model). The agent budget is enforced on OUR side
	// (max-steps + token accounting), so we don't risk a provider-specific field here.

	raw, err := json.Marshal(body)
	if err != nil {
		return ports.ChatResponse{}, fmt.Errorf("%w: marshal chat request: %v", shared.ErrValidation, err)
	}

	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		resp, rerr := c.do(ctx, raw)
		if rerr == nil {
			return resp, nil
		}
		lastErr = rerr
		if !errors.Is(rerr, ErrUnavailable) || ctx.Err() != nil {
			return ports.ChatResponse{}, rerr // terminal (bad request/auth) or cancelled
		}
		// transient: brief backoff, then retry
		select {
		case <-ctx.Done():
			return ports.ChatResponse{}, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 500 * time.Millisecond):
		}
	}
	return ports.ChatResponse{}, lastErr
}

func (c *Client) do(ctx context.Context, raw []byte) (ports.ChatResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/chat/completions", bytes.NewReader(raw))
	if err != nil {
		return ports.ChatResponse{}, fmt.Errorf("%w: build request: %v", shared.ErrValidation, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.key != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.key)
	}
	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return ports.ChatResponse{}, fmt.Errorf("%w: %v", ErrUnavailable, err) // timeout / conn refused → transient
	}
	defer func() { _ = httpResp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(httpResp.Body, maxRespBytes))

	if httpResp.StatusCode == http.StatusTooManyRequests || httpResp.StatusCode >= 500 {
		return ports.ChatResponse{}, fmt.Errorf("%w: provider status %d: %s", ErrUnavailable, httpResp.StatusCode, snippet(data))
	}
	if httpResp.StatusCode != http.StatusOK {
		// 400/401/403 etc. – surface the provider message (which may carry a cooldown hint),
		// but NEVER echo the request (it never contains secrets anyway). Treat as terminal.
		return ports.ChatResponse{}, fmt.Errorf("%w: provider status %d: %s", shared.ErrValidation, httpResp.StatusCode, snippet(data))
	}
	var wr wireResp
	if err := json.Unmarshal(data, &wr); err != nil {
		return ports.ChatResponse{}, fmt.Errorf("%w: decode provider response: %v", ErrUnavailable, err)
	}
	if wr.Error != nil {
		return ports.ChatResponse{}, fmt.Errorf("%w: provider error: %s", ErrUnavailable, wr.Error.Message)
	}
	if len(wr.Choices) == 0 {
		return ports.ChatResponse{}, fmt.Errorf("%w: provider returned no choices", ErrUnavailable)
	}
	msg := wr.Choices[0].Message
	out := ports.ChatResponse{
		Content:      msg.Content,
		FinishReason: wr.Choices[0].FinishReason,
		Usage:        agent.Usage{PromptTokens: wr.Usage.PromptTokens, CompletionTokens: wr.Usage.CompletionTokens, TotalTokens: wr.Usage.TotalTokens},
	}
	for _, tc := range msg.ToolCalls {
		// OpenAI sends function.arguments as a JSON string; store its raw JSON bytes so the
		// orchestrator can unmarshal directly into the tool's typed params.
		out.ToolCalls = append(out.ToolCalls, agent.ToolCall{ID: tc.ID, Name: tc.Function.Name, Arguments: json.RawMessage(tc.Function.Arguments)})
	}
	return out, nil
}

func toWireMessages(msgs []agent.Message) []wireMsg {
	out := make([]wireMsg, 0, len(msgs))
	for _, m := range msgs {
		w := wireMsg{Role: string(m.Role), Content: m.Content, ToolCallID: m.ToolCallID}
		for _, tc := range m.ToolCalls {
			wc := wireToolCall{ID: tc.ID, Type: "function"}
			wc.Function.Name = tc.Name
			wc.Function.Arguments = string(tc.Arguments) // back out as a JSON string
			w.ToolCalls = append(w.ToolCalls, wc)
		}
		out = append(out, w)
	}
	return out
}

func toWireTools(tools []agent.ToolSchema) []wireTool {
	out := make([]wireTool, 0, len(tools))
	for _, t := range tools {
		out = append(out, wireTool{Type: "function", Function: wireToolFunc{Name: t.Name, Description: t.Description, Parameters: t.Parameters}})
	}
	return out
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
