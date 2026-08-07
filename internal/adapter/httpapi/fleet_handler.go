package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetagentuc"
)

// FleetProtoVersion is the only agent protocol version this server supports. An agent must send it
// in X-Synapse-Fleet-Proto; a different value is refused rather than handled best-effort.
const FleetProtoVersion = "1"

const (
	fleetBodyCap    = 1 << 20 // 1 MiB agent request cap
	fleetMaxClaim   = 20      // maximum work orders per claim
	fleetRatePerMin = 120     // per-agent requests per minute
)

// fleetAgentService is the narrow view of fleet agent identity the transport needs.
type fleetAgentService interface {
	Enrol(ctx context.Context, enrolToken string, in fleetagentuc.EnrolInput) (*fleetagent.Agent, string, error)
	Authenticate(ctx context.Context, token string) (*fleetagent.Agent, error)
	Heartbeat(ctx context.Context, agent *fleetagent.Agent, in fleetagentuc.HeartbeatInput) error
}

// fleetWorkService is the narrow view of the work order lifecycle the transport needs.
type fleetWorkService interface {
	Claim(ctx context.Context, actor string, tenantID, agentID shared.ID, max int) ([]*workorder.WorkOrder, error)
	Transition(ctx context.Context, actor string, tenantID, id shared.ID, to workorder.State, reason string) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*workorder.WorkOrder, error)
}

type fleetRouter struct {
	agents  fleetAgentService
	work    fleetWorkService
	log     *slog.Logger
	limiter *agentRateLimiter
}

// SetFleet wires the untrusted agent transport plane. When nil, /api/v1/fleet is not served.
func (rt *Router) SetFleet(agents fleetAgentService, work fleetWorkService, now func() time.Time) {
	rt.fleet = &fleetRouter{
		agents:  agents,
		work:    work,
		log:     rt.log,
		limiter: newAgentRateLimiter(fleetRatePerMin, now),
	}
}

// fleetAdminService is the operator-facing (human, RBAC-gated) view of fleet agent management.
type fleetAdminService interface {
	MintEnrolToken(ctx context.Context, actor string, tenantID shared.ID, ttl time.Duration) (string, error)
	Revoke(ctx context.Context, actor string, tenantID, id shared.ID) error
	ListAgents(ctx context.Context, tenantID shared.ID) ([]*fleetagent.Agent, error)
}

// SetFleetAdmin wires the operator agent-admin routes (mint enrolment token, list, revoke).
func (rt *Router) SetFleetAdmin(s fleetAdminService) { rt.fleetAdmin = s }

const defaultEnrolTTL = 15 * time.Minute

func (rt *Router) mintEnrolToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TTLSeconds int `json:"ttl_seconds"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, assetBodyCap)).Decode(&req)
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = defaultEnrolTTL
	}
	tok, err := rt.fleetAdmin.MintEnrolToken(r.Context(), PrincipalFrom(r.Context()), fleetTenant(r.Context()), ttl)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	// The enrolment token is returned exactly once; it is never stored in the clear or logged.
	writeJSON(w, http.StatusCreated, map[string]string{"enrolment_token": tok})
}

func (rt *Router) listFleetAgents(w http.ResponseWriter, r *http.Request) {
	list, err := rt.fleetAdmin.ListAgents(r.Context(), fleetTenant(r.Context()))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if list == nil {
		list = []*fleetagent.Agent{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (rt *Router) revokeFleetAgent(w http.ResponseWriter, r *http.Request) {
	id := shared.ID(r.PathValue("id"))
	if err := rt.fleetAdmin.Revoke(r.Context(), PrincipalFrom(r.Context()), fleetTenant(r.Context()), id); err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"agent_id": id.String(), "state": "revoked"})
}

type agentCtxKey int

const agentKeyCtx agentCtxKey = iota

func agentFrom(ctx context.Context) (*fleetagent.Agent, bool) {
	a, ok := ctx.Value(agentKeyCtx).(*fleetagent.Agent)
	return a, ok
}

// handler builds the agent-plane mux. Every route checks the protocol version; every route except
// enrol requires a valid agent bearer credential (agent-auth, NOT the human RBAC plane).
func (f *fleetRouter) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/fleet/enrol", f.version(f.enrol))
	mux.HandleFunc("POST /api/v1/fleet/heartbeat", f.version(f.authed(f.heartbeat)))
	mux.HandleFunc("POST /api/v1/fleet/work/claim", f.version(f.authed(f.claim)))
	mux.HandleFunc("POST /api/v1/fleet/work/{id}/progress", f.version(f.authed(f.progress)))
	mux.HandleFunc("POST /api/v1/fleet/work/{id}/result", f.version(f.authed(f.result)))
	return mux
}

// version enforces the supported protocol version, returning 400 unsupported_version otherwise.
func (f *fleetRouter) version(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Synapse-Fleet-Proto") != FleetProtoVersion {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "unsupported_version"})
			return
		}
		next(w, r)
	}
}

// authed resolves the agent bearer credential, rate-limits per agent, and stamps the agent into
// the context. The tenant comes from the authenticated agent, never from the request.
func (f *fleetRouter) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthenticated"})
			return
		}
		agent, err := f.agents.Authenticate(r.Context(), token)
		if err != nil {
			switch {
			case errors.Is(err, fleetagentuc.ErrRevoked):
				writeJSON(w, http.StatusForbidden, errorBody{Error: "revoked"})
			case errors.Is(err, fleetagentuc.ErrUnauthenticated):
				writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthenticated"})
			default:
				writeError(w, f.log, err)
			}
			return
		}
		if !f.limiter.allow(agent.ID.String()) {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, errorBody{Error: "rate_limited"})
			return
		}
		ctx := context.WithValue(r.Context(), agentKeyCtx, agent)
		next(w, r.WithContext(ctx))
	}
}

func (f *fleetRouter) enrol(w http.ResponseWriter, r *http.Request) {
	token, ok := bearerToken(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthenticated"})
		return
	}
	var req struct {
		Name         string   `json:"name"`
		Platform     string   `json:"platform"`
		OSVersion    string   `json:"os_version"`
		AgentVersion string   `json:"agent_version"`
		Capabilities []string `json:"capabilities"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, fleetBodyCap)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid enrol body"})
		return
	}
	agent, agentToken, err := f.agents.Enrol(r.Context(), token, fleetagentuc.EnrolInput{
		Name: req.Name, Platform: req.Platform, OSVersion: req.OSVersion,
		AgentVersion: req.AgentVersion, Capabilities: req.Capabilities,
	})
	if err != nil {
		if errors.Is(err, fleetagentuc.ErrUnauthenticated) {
			writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthenticated"})
			return
		}
		writeError(w, f.log, err)
		return
	}
	// The agent token is returned exactly once here; it is never stored in the clear or logged.
	writeJSON(w, http.StatusCreated, map[string]string{"agent_id": agent.ID.String(), "token": agentToken})
}

func (f *fleetRouter) heartbeat(w http.ResponseWriter, r *http.Request) {
	agent, _ := agentFrom(r.Context())
	var req struct {
		Platform     string   `json:"platform"`
		OSVersion    string   `json:"os_version"`
		AgentVersion string   `json:"agent_version"`
		Capabilities []string `json:"capabilities"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, fleetBodyCap)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid heartbeat body"})
		return
	}
	if err := f.agents.Heartbeat(r.Context(), agent, fleetagentuc.HeartbeatInput{
		Platform: req.Platform, OSVersion: req.OSVersion, AgentVersion: req.AgentVersion, Capabilities: req.Capabilities,
	}); err != nil {
		writeError(w, f.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"proto": FleetProtoVersion})
}

func (f *fleetRouter) claim(w http.ResponseWriter, r *http.Request) {
	agent, _ := agentFrom(r.Context())
	var req struct {
		Max int `json:"max"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, fleetBodyCap)).Decode(&req)
	max := req.Max
	if max <= 0 || max > fleetMaxClaim {
		max = fleetMaxClaim
	}
	orders, err := f.work.Claim(r.Context(), agent.ID.String(), agent.TenantID, agent.ID, max)
	if err != nil {
		writeError(w, f.log, err)
		return
	}
	if orders == nil {
		orders = []*workorder.WorkOrder{}
	}
	writeJSON(w, http.StatusOK, orders)
}

func (f *fleetRouter) progress(w http.ResponseWriter, r *http.Request) {
	f.transitionTo(w, r, workorder.StateRunning, "")
}

func (f *fleetRouter) result(w http.ResponseWriter, r *http.Request) {
	agent, _ := agentFrom(r.Context())
	id := shared.ID(r.PathValue("id"))
	var req struct {
		Status string `json:"status"` // "succeeded" | "failed"
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, fleetBodyCap)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid result body"})
		return
	}
	to := workorder.State(req.Status)
	if to != workorder.StateSucceeded && to != workorder.StateFailed {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "result status must be succeeded or failed"})
		return
	}
	f.applyTransition(w, r, agent, id, to, req.Reason)
}

func (f *fleetRouter) transitionTo(w http.ResponseWriter, r *http.Request, to workorder.State, reason string) {
	agent, _ := agentFrom(r.Context())
	id := shared.ID(r.PathValue("id"))
	f.applyTransition(w, r, agent, id, to, reason)
}

// applyTransition enforces that the order is addressed to the calling agent (cross-tenant or
// mis-addressed => not_found, never leaking existence) and is idempotent: a transition to a state
// the order is already in is a no-op 200.
func (f *fleetRouter) applyTransition(w http.ResponseWriter, r *http.Request, agent *fleetagent.Agent, id shared.ID, to workorder.State, reason string) {
	wo, err := f.work.GetByID(r.Context(), agent.TenantID, id)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, errorBody{Error: "not_found"})
			return
		}
		writeError(w, f.log, err)
		return
	}
	if wo.AgentID != agent.ID {
		// Not addressed to this agent: 404, do not leak that it exists.
		writeJSON(w, http.StatusNotFound, errorBody{Error: "not_found"})
		return
	}
	if wo.State == to {
		writeJSON(w, http.StatusOK, map[string]string{"state": string(to)})
		return
	}
	if err := f.work.Transition(r.Context(), agent.ID.String(), agent.TenantID, id, to, reason); err != nil {
		if errors.Is(err, shared.ErrValidation) {
			writeJSON(w, http.StatusConflict, errorBody{Error: "illegal_transition"})
			return
		}
		writeError(w, f.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"state": string(to)})
}

// agentRateLimiter is a minimal per-agent fixed-window limiter with an injectable clock.
type agentRateLimiter struct {
	mu      sync.Mutex
	perMin  int
	now     func() time.Time
	windows map[string]*rateWindow
}

type rateWindow struct {
	start time.Time
	count int
}

func newAgentRateLimiter(perMin int, now func() time.Time) *agentRateLimiter {
	if now == nil {
		now = time.Now
	}
	return &agentRateLimiter{perMin: perMin, now: now, windows: map[string]*rateWindow{}}
}

func (l *agentRateLimiter) allow(agentID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	win, ok := l.windows[agentID]
	if !ok || t.Sub(win.start) >= time.Minute {
		l.windows[agentID] = &rateWindow{start: t, count: 1}
		return true
	}
	if win.count >= l.perMin {
		return false
	}
	win.count++
	return true
}
