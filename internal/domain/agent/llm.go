// Package agent holds the pure domain types for AI orchestration: the LLM
// conversation values (messages, tool-calls, usage) and the orchestration state (session,
// proposed action, risk class, approval decision). It imports only other domain packages
// + stdlib. The LLM only ever PROPOSES typed tool-calls here; whether any of them runs is
// decided by the typed Go state machine + the safety gate (usecase layer) – never by the
// model. These types carry NO secrets: resolved credentials live only
// inside the sandboxed child at exec time and never enter a Message.
package agent

import (
	"encoding/json"
	"strings"
)

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

// CanonicalModelID normalizes a configured model identity for separation-of-duties checks.
// Routers commonly accept both "provider/model" and "model", and model identifiers are
// case-insensitive in the supported OpenAI-compatible APIs. Treating those spellings as distinct
// would let one model verify its own proposal.
func CanonicalModelID(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	if slash := strings.LastIndexByte(id, '/'); slash >= 0 {
		id = strings.TrimSpace(id[slash+1:])
	}
	// Amazon Bedrock cross-Region inference profiles prepend a geographic scope (for example
	// "us." or "global.") to the underlying foundation-model ID. Bedrock model IDs then prepend a
	// provider namespace with a dot, while OpenAI-compatible routers commonly spell that namespace
	// with a slash (already removed above). Collapse both representations so a profile or provider
	// spelling cannot make one model look like an independent verifier.
	// Strip a leading geographic scope. Enumerating scopes alone FAILS OPEN as AWS adds regions: an
	// unlisted prefix leaves "ca.anthropic.claude-x" looking distinct from "anthropic.claude-x", so the
	// same model would pass a separation-of-duties check as an independent verifier (verified: us/eu/
	// apac/global collapsed, ca/jp/au/sa did not). So also treat ANY leading segment as a scope when
	// what follows it starts with a known provider namespace -- the provider set is what a Bedrock model
	// ID is built from, and it drifts far more slowly than the region list.
	if prefix, rest, ok := strings.Cut(id, "."); ok && (bedrockScope(prefix) || startsWithBedrockProvider(rest)) {
		id = rest
	}
	if prefix, rest, ok := strings.Cut(id, "."); ok && bedrockProvider(prefix) {
		id = rest
	}
	// Bedrock's trailing -vN:M identifies a provider deployment revision, not an independent model
	// family. Separation of duties therefore fails closed across those revisions as it does across
	// OpenAI dated aliases below.
	if rev := strings.LastIndex(id, "-v"); rev > 0 && bedrockRevision(id[rev+2:]) {
		id = id[:rev]
	}
	// Bedrock model IDs commonly carry an undelimited YYYYMMDD release date. Treat that snapshot as
	// the same family as its rolling shorthand; correlated revisions are not independent reviewers.
	if n := len(id); n > 9 && id[n-9] == '-' && allASCIIDigits(id[n-8:]) {
		id = id[:n-9]
	}
	// OpenAI-style dated aliases (model-YYYY-MM-DD) often point at the same weights as the
	// corresponding rolling model name. Conservatively collapse that spelling too.
	if n := len(id); n > 11 && id[n-11] == '-' &&
		allASCIIDigits(id[n-10:n-6]) && id[n-6] == '-' &&
		allASCIIDigits(id[n-5:n-3]) && id[n-3] == '-' &&
		allASCIIDigits(id[n-2:]) {
		id = id[:n-11]
	}
	return id
}

// startsWithBedrockProvider reports whether s begins with a known Bedrock provider namespace, which
// makes whatever preceded it a scope rather than part of the model identity.
func startsWithBedrockProvider(s string) bool {
	prefix, _, ok := strings.Cut(s, ".")
	return ok && bedrockProvider(prefix)
}

func bedrockScope(s string) bool {
	switch s {
	case "us", "eu", "apac", "global":
		return true
	default:
		return false
	}
}

func bedrockProvider(s string) bool {
	switch s {
	case "ai21", "amazon", "anthropic", "cohere", "deepseek", "luma", "meta", "mistral", "moonshot", "nvidia", "openai", "qwen", "stability":
		return true
	default:
		return false
	}
}

func bedrockRevision(s string) bool {
	major, minor, ok := strings.Cut(s, ":")
	return ok && allASCIIDigits(major) && allASCIIDigits(minor)
}

func allASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// SameModel reports whether two non-empty configured identifiers resolve to the same canonical model.
func SameModel(a, b string) bool {
	a, b = CanonicalModelID(a), CanonicalModelID(b)
	return a != "" && b != "" && a == b
}

// CanonicalProviderID normalizes an operator-supplied provider identity for audit and
// separation-of-duties comparisons. Provider identity is deliberately explicit rather than inferred
// from a gateway URL: one OpenAI-compatible router may front several providers, while two URLs may be
// aliases for the same provider.
func CanonicalProviderID(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}

// IndependentLLMs validates the configured proposer/verifier identities against a deterministic
// policy. Every mode requires complete provider and model-family metadata and distinct model families.
// Provider mode additionally requires distinct provider identities. Unknown policies fail closed.
func IndependentLLMs(proposerProvider, proposerModel, verifierProvider, verifierModel string, policy string) bool {
	proposerProvider = CanonicalProviderID(proposerProvider)
	verifierProvider = CanonicalProviderID(verifierProvider)
	proposerFamily := CanonicalModelID(proposerModel)
	verifierFamily := CanonicalModelID(verifierModel)
	if proposerProvider == "" || verifierProvider == "" || proposerFamily == "" || verifierFamily == "" || proposerFamily == verifierFamily {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case "model_family":
		return true
	case "provider":
		return proposerProvider != verifierProvider
	default:
		return false
	}
}
