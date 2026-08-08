package httpapi

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	dci "github.com/KKloudTarus/synapse-ce/internal/domain/clusterinventory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	clusterinventoryuc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/clusterinventory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetagentuc"
)

// FleetProtoVersion is the only agent protocol version this server supports. An agent must send it
// in X-Synapse-Fleet-Proto; a different value is refused rather than handled best-effort.
const FleetProtoVersion = "1"

const (
	fleetBodyCap      = 1 << 20  // 1 MiB agent request cap (enrol/heartbeat/claim/result)
	fleetInventoryCap = 16 << 20 // 16 MiB cap for an inventory snapshot — generous for a large cluster
	//                             (replicas dedupe to controllers) while bounding decode cost per request
	fleetMaxClaim     = 20  // maximum work orders per claim
	fleetRatePerMin   = 120 // per-agent requests per minute (post-auth)
	fleetIPRatePerMin = 60  // per-client-IP requests per minute (pre-auth: enrol + failed auth)
)

// fleetAgentService is the narrow view of fleet agent identity the transport needs.
type fleetAgentService interface {
	Enrol(ctx context.Context, enrolToken string, in fleetagentuc.EnrolInput) (*fleetagent.Agent, string, []byte, error)
	Authenticate(ctx context.Context, token string) (*fleetagent.Agent, error)
	AuthenticateCertificate(ctx context.Context, tenantID, agentID shared.ID, fingerprint string) (*fleetagent.Agent, error)
	Heartbeat(ctx context.Context, agent *fleetagent.Agent, in fleetagentuc.HeartbeatInput) error
}

// fleetWorkService is the narrow view of the work order lifecycle the transport needs.
type fleetWorkService interface {
	Claim(ctx context.Context, actor string, tenantID, agentID shared.ID, max int) ([]*workorder.WorkOrder, error)
	Transition(ctx context.Context, actor string, tenantID, id shared.ID, to workorder.State, reason string) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*workorder.WorkOrder, error)
}

// fleetClusterInventory persists a Kubernetes cluster snapshot an agent reports (#446). The
// cluster-inventory use case implements it; nil means the ingest route is not served.
type fleetClusterInventory interface {
	Sync(ctx context.Context, actor string, in clusterinventoryuc.SyncInput) (*clusterinventoryuc.SyncResult, error)
}

type fleetRouter struct {
	agents           fleetAgentService
	work             fleetWorkService
	clusterInv       fleetClusterInventory // optional; nil ⇒ cluster inventory ingest is not served
	log              *slog.Logger
	agentLim         *keyedLimiter // post-auth, keyed by agent id
	ipLim            *keyedLimiter // pre-auth, keyed by client IP (throttles enrol + failed auth)
	clientCertHeader string        // when set, a trusted proxy passes the verified client cert here
}

// SetFleet wires the untrusted agent transport plane. When nil, /api/v1/fleet is not served.
// clientCertHeader, when non-empty, is the header a trusted mutual-TLS-terminating proxy uses to
// pass the verified client certificate; empty disables certificate auth and uses the bearer token.
func (rt *Router) SetFleet(agents fleetAgentService, work fleetWorkService, now func() time.Time, clientCertHeader string) {
	rt.fleet = &fleetRouter{
		agents:           agents,
		work:             work,
		log:              rt.log,
		agentLim:         newKeyedLimiter(fleetRatePerMin, now),
		ipLim:            newKeyedLimiter(fleetIPRatePerMin, now),
		clientCertHeader: clientCertHeader,
	}
}

// authByClientCert authenticates an agent from a verified client certificate the trusted proxy
// passed in a header. It reads the tenant (OU) and agent id (CN) from the certificate subject and
// verifies the fingerprint against the stored one. Parsing failure is an unauthenticated result,
// never a 500, so a malformed header cannot be distinguished from a wrong credential.
func (f *fleetRouter) authByClientCert(ctx context.Context, headerVal string) (*fleetagent.Agent, error) {
	raw := headerVal
	// A raw PEM already contains the literal header; only URL-unescape when it does not (some proxies
	// pass the certificate URL-escaped). Unescaping a raw PEM would corrupt its base64 '+' bytes.
	if !strings.Contains(raw, "BEGIN CERTIFICATE") {
		if unesc, err := url.QueryUnescape(headerVal); err == nil {
			raw = unesc
		}
	}
	block, _ := pem.Decode([]byte(raw))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fleetagentuc.ErrUnauthenticated
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fleetagentuc.ErrUnauthenticated
	}
	// Enforce the certificate validity window at the app layer too, not only at the proxy handshake:
	// a stored fingerprint outlives the cert, so an expired certificate must not authenticate.
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fleetagentuc.ErrUnauthenticated
	}
	agentID := cert.Subject.CommonName
	if agentID == "" || len(cert.Subject.OrganizationalUnit) == 0 || cert.Subject.OrganizationalUnit[0] == "" {
		return nil, fleetagentuc.ErrUnauthenticated
	}
	tenant := cert.Subject.OrganizationalUnit[0]
	fingerprint := fleetagent.CertFingerprint(cert.Raw)
	return f.agents.AuthenticateCertificate(ctx, shared.ID(tenant), shared.ID(agentID), fingerprint)
}

// fleetAdminService is the operator-facing (human, RBAC-gated) view of fleet agent management.
type fleetAdminService interface {
	MintEnrolToken(ctx context.Context, actor string, tenantID shared.ID, ttl time.Duration) (string, error)
	Revoke(ctx context.Context, actor string, tenantID, id shared.ID, reason string) error
	ListAgents(ctx context.Context, tenantID shared.ID) ([]*fleetagent.Agent, error)
}

// SetFleetAdmin wires the operator agent-admin routes (mint enrolment token, list, revoke).
func (rt *Router) SetFleetAdmin(s fleetAdminService) { rt.fleetAdmin = s }

// SetFleetClusterInventory wires the cluster snapshot ingest use case onto the agent transport plane.
// It must be called after SetFleet; a nil fleet (transport disabled) makes it a no-op.
func (rt *Router) SetFleetClusterInventory(s fleetClusterInventory) {
	if rt.fleet != nil {
		rt.fleet.clusterInv = s
	}
}

const defaultEnrolTTL = 15 * time.Minute

func (rt *Router) mintEnrolToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TTLSeconds int `json:"ttl_seconds"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, fleetBodyCap)).Decode(&req)
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

// agentView is the transport DTO for an agent. It deliberately OMITS TokenHash: the credential
// verifier material must never leave the server, even though its preimage is infeasible.
type agentView struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Name         string    `json:"name"`
	Platform     string    `json:"platform"`
	OSVersion    string    `json:"os_version"`
	AgentVersion string    `json:"agent_version"`
	Capabilities []string  `json:"capabilities"`
	State        string    `json:"state"`
	LastSeenAt   time.Time `json:"last_seen_at"`
}

func toAgentView(a *fleetagent.Agent) agentView {
	caps := a.Capabilities
	if caps == nil {
		caps = []string{}
	}
	return agentView{
		ID: a.ID.String(), TenantID: a.TenantID.String(), Name: a.Name, Platform: a.Platform,
		OSVersion: a.OSVersion, AgentVersion: a.AgentVersion, Capabilities: caps,
		State: string(a.State), LastSeenAt: a.LastSeenAt,
	}
}

func (rt *Router) listFleetAgents(w http.ResponseWriter, r *http.Request) {
	list, err := rt.fleetAdmin.ListAgents(r.Context(), fleetTenant(r.Context()))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	views := make([]agentView, 0, len(list))
	for _, a := range list {
		views = append(views, toAgentView(a))
	}
	writeJSON(w, http.StatusOK, views)
}

func (rt *Router) revokeFleetAgent(w http.ResponseWriter, r *http.Request) {
	id := shared.ID(r.PathValue("id"))
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, fleetBodyCap)).Decode(&req)
	if err := rt.fleetAdmin.Revoke(r.Context(), PrincipalFrom(r.Context()), fleetTenant(r.Context()), id, req.Reason); err != nil {
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
	mux.HandleFunc("POST /api/v1/fleet/enrol", f.entry(f.enrol))
	mux.HandleFunc("POST /api/v1/fleet/heartbeat", f.entry(f.authed(f.heartbeat)))
	mux.HandleFunc("POST /api/v1/fleet/work/claim", f.entry(f.authed(f.claim)))
	mux.HandleFunc("POST /api/v1/fleet/work/{id}/progress", f.entry(f.authed(f.progress)))
	mux.HandleFunc("POST /api/v1/fleet/work/{id}/result", f.entry(f.authed(f.result)))
	mux.HandleFunc("POST /api/v1/fleet/inventory/cluster", f.entry(f.authed(f.clusterInventory)))
	return mux
}

// entry is the outermost wrapper on every fleet route. It throttles per client IP BEFORE any
// database work (so unauthenticated enrol and failed-auth attempts cannot amplify into unbounded
// DB lookups on this untrusted plane), then enforces the supported protocol version.
func (f *fleetRouter) entry(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !f.ipLim.allow(clientIP(r)) {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, errorBody{Error: "rate_limited"})
			return
		}
		if r.Header.Get("X-Synapse-Fleet-Proto") != FleetProtoVersion {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "unsupported_version"})
			return
		}
		next(w, r)
	}
}

// clientIP returns the request's source host (no port). RemoteAddr is used rather than a spoofable
// X-Forwarded-For header, because this is a throttling key, not an authorization input.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// authed resolves the agent bearer credential, rate-limits per agent, and stamps the agent into
// the context. The tenant comes from the authenticated agent, never from the request.
func (f *fleetRouter) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			agent *fleetagent.Agent
			err   error
		)
		// Certificate identity takes precedence when the mutual-TLS-terminating proxy is configured
		// to pass the verified client certificate in clientCertHeader. SECURITY: this header is
		// trusted only because the operator asserts (via config) that a trusted proxy verifies mTLS
		// and STRIPS any client-supplied value; the app must not be directly reachable. When the
		// header is absent we fall back to the bearer credential.
		// When the cert header is configured but absent, we fall back to the bearer token (a
		// reasonable migration posture). A strict certificate-required mode that refuses the bearer
		// fallback is a documented follow-up for deployments where mTLS supersedes the token.
		if f.clientCertHeader != "" && r.Header.Get(f.clientCertHeader) != "" {
			agent, err = f.authByClientCert(r.Context(), r.Header.Get(f.clientCertHeader))
		} else {
			token, ok := bearerToken(r)
			if !ok {
				writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthenticated"})
				return
			}
			agent, err = f.agents.Authenticate(r.Context(), token)
		}
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
		if !f.agentLim.allow(agent.ID.String()) {
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
		CSRPEM       string   `json:"csr_pem"` // optional PEM CSR for certificate identity (#408)
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, fleetBodyCap)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid enrol body"})
		return
	}
	agent, agentToken, certPEM, err := f.agents.Enrol(r.Context(), token, fleetagentuc.EnrolInput{
		Name: req.Name, Platform: req.Platform, OSVersion: req.OSVersion,
		AgentVersion: req.AgentVersion, Capabilities: req.Capabilities, CSRPEM: []byte(req.CSRPEM),
	})
	if err != nil {
		if errors.Is(err, fleetagentuc.ErrUnauthenticated) {
			writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthenticated"})
			return
		}
		writeError(w, f.log, err)
		return
	}
	// The agent token and certificate are returned exactly once here; never stored in the clear or logged.
	resp := map[string]string{"agent_id": agent.ID.String(), "token": agentToken}
	if len(certPEM) > 0 {
		resp["certificate_pem"] = string(certPEM)
	}
	writeJSON(w, http.StatusCreated, resp)
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

// clusterInventory ingests a Kubernetes cluster snapshot the agent collected and persists it into the
// asset model via the cluster-inventory use case. The tenant and actor come from the authenticated
// agent (never the request body), and provenance is the agent id — stable across resyncs, so the
// persisted edge set converges instead of churning. The coverage gaps are returned so a partial
// inventory is visible, never silently treated as clean.
func (f *fleetRouter) clusterInventory(w http.ResponseWriter, r *http.Request) {
	if f.clusterInv == nil {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "cluster inventory ingest not enabled"})
		return
	}
	agent, ok := agentFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthenticated"})
		return
	}
	var snap dci.Snapshot
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, fleetInventoryCap)).Decode(&snap); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid cluster snapshot body"})
		return
	}
	res, err := f.clusterInv.Sync(r.Context(), agent.ID.String(), clusterinventoryuc.SyncInput{
		TenantID: agent.TenantID,
		Snapshot: snap,
		// Provenance is the agent id: stable across resyncs while one agent owns a cluster, so edges
		// converge (no churn). A re-enrolled/replacement agent (new id) re-reports edges under the new
		// provenance until the old set ages out — an accepted tradeoff, documented on SyncInput.
		Provenance: agent.ID,
	})
	if err != nil {
		writeError(w, f.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{
		"assets": res.Assets, "edges": res.Edges, "coverage_gaps": len(res.Gaps),
	})
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

// keyedLimiter is a minimal fixed-window rate limiter keyed by an arbitrary string (agent id or
// client IP) with an injectable clock. Its key map is bounded: when it grows past maxKeys, expired
// windows are pruned so an untrusted key space (client IPs) cannot grow it without bound.
type keyedLimiter struct {
	mu      sync.Mutex
	perMin  int
	now     func() time.Time
	windows map[string]*rateWindow
}

const limiterMaxKeys = 8192

type rateWindow struct {
	start time.Time
	count int
}

func newKeyedLimiter(perMin int, now func() time.Time) *keyedLimiter {
	if now == nil {
		now = time.Now
	}
	return &keyedLimiter{perMin: perMin, now: now, windows: map[string]*rateWindow{}}
}

func (l *keyedLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	win, ok := l.windows[key]
	if !ok || t.Sub(win.start) >= time.Minute {
		if !ok && len(l.windows) >= limiterMaxKeys {
			l.pruneLocked(t)
		}
		l.windows[key] = &rateWindow{start: t, count: 1}
		return true
	}
	if win.count >= l.perMin {
		return false
	}
	win.count++
	return true
}

// pruneLocked drops windows whose fixed window has fully elapsed. Callers hold l.mu.
func (l *keyedLimiter) pruneLocked(t time.Time) {
	for k, w := range l.windows {
		if t.Sub(w.start) >= time.Minute {
			delete(l.windows, k)
		}
	}
}
