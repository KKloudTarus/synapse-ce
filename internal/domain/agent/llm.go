// Package agent holds the pure domain types for AI orchestration: the LLM
// conversation values (messages, tool-calls, usage) and the orchestration state (session,
// proposed action, risk class, approval decision). It imports only other domain packages
// + stdlib. The LLM only ever PROPOSES typed tool-calls here; whether any of them runs is
// decided by the typed Go state machine + the safety gate (usecase layer) – never by the
// model. These types carry NO secrets: resolved credentials live only
// inside the sandboxed child at exec time and never enter a Message.
package agent

import "encoding/json"

// Role is a chat message author. Mirrors the OpenAI-compatible roles so the provider
// adapter is a thin mapping, but it is provider-agnostic domain vocabulary.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool" // a turn carrying a tool's result back to the model
)

// Message is one turn in the agent transcript.
type Message struct {
	Role    Role   `json:"role"`
	Content string `json:"content,omitempty"`
	// ToolCalls is set on an assistant turn that PROPOSES tool invocations. They are
	// proposals only – the orchestrator validates + gates each before anything executes.
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	// ToolCallID links a RoleTool turn back to the ToolCall it answers.
	ToolCallID string `json:"tool_call_id,omitempty"`
}

// ToolCall is a single proposed invocation: a catalog tool name + JSON arguments the Go
// side unmarshals into that tool's TYPED params (never executed as a shell string).
type ToolCall struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// ToolSchema is the function-calling contract advertised to the model for one tool: its
// name, a description, and a JSON-Schema for its parameters. The catalog (usecase layer)
// produces these from the typed tools so the model can only propose registered calls.
type ToolSchema struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"` // JSON Schema object
}

// Usage is the token accounting for a turn – fed into the per-session budget guard.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}
