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
	Temperature    float64
	MaxTokens      int
}

// ChatResponse is the model's turn. ToolCalls are PROPOSALS – the orchestrator decides what
// (if anything) runs. FinishReason is the provider's stop reason ("stop"|"tool_calls"|"length").
type ChatResponse struct {
	Content      string
	ToolCalls    []agent.ToolCall
	FinishReason string
	Usage        agent.Usage
}
