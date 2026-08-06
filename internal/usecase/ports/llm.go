package ports

import (
	"context"
	"encoding/json"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
)

// LLM is the model provider the orchestrator proposes through.
// The model only PROPOSES tool-calls; Go validates + executes. The first/reference adapter
// is OpenAI-compatible Chat Completions (tested against gateway); other providers are
// future adapters behind THIS interface – the orchestrator never branches on provider.
// Implementations must never log the API key and must honor ctx + a
// per-request timeout, returning a transient error (not a panic) on a 5xx/timeout.
type LLM interface {
	Chat(ctx context.Context, req ChatRequest) (ChatResponse, error)
}

// ChatRequest is one model turn: the transcript so far + the tool contract. ResponseSchema,
// when set, asks the provider for schema-constrained JSON (OpenAI response_format=json_schema);
// providers that only support tool-calling ignore it and the adapter falls back to tools.
type ChatRequest struct {
	Model          string
	Messages       []agent.Message
	Tools          []agent.ToolSchema // the catalog advertised as function-calling tools
	ResponseSchema json.RawMessage    // optional JSON Schema for a constrained response
	// Temperature is a pointer so an explicit 0 is distinguishable from "unset": nil leaves the
	// choice to the provider default, non-nil is sent verbatim – and 0 means greedy decoding, which
	// is what a caller whose verdict must be reproducible asks for. Use Temp.
	Temperature *float64
	MaxTokens   int
}

// Temp returns a pointer to v for ChatRequest.Temperature, so a deterministic caller can ask for an
// explicit 0 without declaring a local variable at every call site.
func Temp(v float64) *float64 { return &v }

// ChatResponse is the model's turn. ToolCalls are PROPOSALS – the orchestrator decides what
// (if anything) runs. FinishReason is the provider's stop reason ("stop"|"tool_calls"|"length").
type ChatResponse struct {
	Content      string
	ToolCalls    []agent.ToolCall
	FinishReason string
	Usage        agent.Usage
}
