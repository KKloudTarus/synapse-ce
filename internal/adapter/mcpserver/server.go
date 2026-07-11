// Package mcpserver exposes Synapse's agent tool catalog to external AI clients over the Model
// Context Protocol. It is a hand-rolled MCP core – JSON-RPC 2.0 over the
// Streamable-HTTP transport (a single POST endpoint) implementing initialize / tools/list /
// tools/call – so it needs no third-party SDK and is fully testable offline. (The SDK can be
// swapped in later behind the same Catalog seam.)
//
// Safety: the server is bearer-locked (role "mcp") and pinned to ONE engagement, so it can
// never reach another engagement's data (the catalog is engagement-locked per session and an
// engagement id is never accepted from the client). It dispatches through the SAME
// agenttools.Catalog the in-process orchestrator uses, so read tools return data and an
// execute proposal (start_recon) is returned as an approval-required envelope – the MCP path
// has no executor and no gate, so it can never RUN a tool (it can only read + propose). All
// dispatches are audited by the catalog under the agent id.
package mcpserver

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/agenttools"
)

// protocolVersion is the MCP revision this server speaks.
const protocolVersion = "2024-11-05"

// Server is an MCP endpoint over a fixed engagement.
type Server struct {
	catalog      *agenttools.Catalog
	engagementID shared.ID
	sessionID    shared.ID // synthetic session id used for catalog dispatch + audit attribution
	token        string    // bearer token (role-locked "mcp"); never logged
	serverName   string
	version      string
	log          *slog.Logger
}

// New validates dependencies and returns an MCP server bound to one engagement.
func New(catalog *agenttools.Catalog, engagementID shared.ID, token, version string, log *slog.Logger) (*Server, error) {
	if catalog == nil {
		return nil, fmt.Errorf("%w: mcp server needs a catalog", shared.ErrValidation)
	}
	if engagementID == "" {
		return nil, fmt.Errorf("%w: mcp server needs an engagement id (SYNAPSE_MCP_ENGAGEMENT_ID)", shared.ErrValidation)
	}
	if token == "" {
		return nil, fmt.Errorf("%w: mcp server needs a bearer token (SYNAPSE_MCP_TOKEN)", shared.ErrValidation)
	}
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		catalog: catalog, engagementID: engagementID,
		sessionID: shared.ID("mcp-" + engagementID.String()),
		token:     token, serverName: "synapse-mcp", version: version, log: log,
	}, nil
}

// --- JSON-RPC 2.0 wire types ---

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // absent ⇒ notification
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// JSON-RPC error codes (subset).
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
)

// Handler returns the MCP HTTP handler. Bearer-token auth gates every request.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "synapse-mcp"})
	})
	mux.HandleFunc("POST /mcp", s.authed(s.handleRPC))
	return mux
}

// authed enforces the bearer token (constant-time) before the handler runs.
func (s *Server) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		h := r.Header.Get("Authorization")
		tok := ""
		if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
			tok = strings.TrimSpace(h[len(prefix):])
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid MCP token"})
			return
		}
		next(w, r)
	}
}

func (s *Server) handleRPC(w http.ResponseWriter, r *http.Request) {
	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusOK, errResp(nil, codeParseError, "parse error"))
		return
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		writeJSON(w, http.StatusOK, errResp(req.ID, codeInvalidRequest, "invalid JSON-RPC request"))
		return
	}
	// Notifications (no id) get no response body.
	if len(req.ID) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch req.Method {
	case "initialize":
		writeJSON(w, http.StatusOK, okResp(req.ID, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": s.serverName, "version": s.version},
		}))
	case "tools/list":
		writeJSON(w, http.StatusOK, okResp(req.ID, map[string]any{"tools": s.toolDescriptors()}))
	case "tools/call":
		s.handleToolCall(r.Context(), w, req)
	default:
		writeJSON(w, http.StatusOK, errResp(req.ID, codeMethodNotFound, "method not found: "+req.Method))
	}
}

// mcpTool is an MCP tool descriptor (name + JSON-Schema input).
type mcpTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

func (s *Server) toolDescriptors() []mcpTool {
	schemas := s.catalog.Tools()
	out := make([]mcpTool, 0, len(schemas))
	for _, t := range schemas {
		out = append(out, mcpTool{Name: t.Name, Description: t.Description, InputSchema: t.Parameters})
	}
	return out
}

func (s *Server) handleToolCall(ctx context.Context, w http.ResponseWriter, req rpcRequest) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
		writeJSON(w, http.StatusOK, errResp(req.ID, codeInvalidRequest, "tools/call needs a tool name"))
		return
	}
	sess := agent.Session{ID: s.sessionID, EngagementID: s.engagementID, InitiatedBy: "mcp"}
	res, err := s.catalog.Dispatch(ctx, sess, agent.ToolCall{ID: "mcp", Name: p.Name, Arguments: p.Arguments})
	if err != nil {
		// A tool/argument error is reported as an MCP tool error (isError), not a transport error.
		writeJSON(w, http.StatusOK, okResp(req.ID, toolResult(err.Error(), true)))
		return
	}
	var text string
	switch {
	case res.Proposal != nil:
		// An execute proposal is NOT run over MCP (no gate/executor here). Return the envelope so
		// the client sees the diff-before-run; execution requires the orchestrator + HITL.
		env, _ := json.Marshal(map[string]any{
			"proposal_requires_human_approval": true,
			"tool":                             res.Proposal.Tool,
			"action":                           res.Proposal.Action,
			"target":                           res.Proposal.Target.Value,
			"argv":                             res.Proposal.Argv,
			"risk":                             string(res.Proposal.Risk),
		})
		text = string(env)
	default:
		text = string(res.Data)
	}
	writeJSON(w, http.StatusOK, okResp(req.ID, toolResult(text, false)))
}

// toolResult builds an MCP tools/call result (a single text content block).
func toolResult(text string, isErr bool) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isErr,
	}
}

func okResp(id json.RawMessage, result any) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func errResp(id json.RawMessage, code int, msg string) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
