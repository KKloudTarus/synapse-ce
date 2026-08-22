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
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetrollout"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetversion"
	dhi "github.com/KKloudTarus/synapse-ce/internal/domain/hostinventory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	clusterinventoryuc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/clusterinventory"
	hostinventoryuc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/hostinventory"
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
	// Decommission records the agent's own clean-uninstall report (#412).
	Decommission(ctx context.Context, agent *fleetagent.Agent) error
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

// fleetHostInventory persists a VM host inventory an agent reports (#446). The host-inventory use
// case implements it; nil means the host ingest route is not served.
type fleetHostInventory interface {
	Sync(ctx context.Context, actor string, in hostinventoryuc.SyncInput) (*hostinventoryuc.SyncResult, error)
}

// fleetRolloutDecider answers what ONE agent is offered. It is the narrow slice of the rollout service
// this transport needs; fleetrolloutuc.Service satisfies it.
type fleetRolloutDecider interface {
	DecideFor(ctx context.Context, tenantID shared.ID, channel, agentGroup, agentVersion string) fleetrollout.Decision
}

type fleetRouter struct {
	agents           fleetAgentService
	work             fleetWorkService
	clusterInv       fleetClusterInventory // optional; nil ⇒ cluster inventory ingest is not served
	hostInv          fleetHostInventory    // optional; nil ⇒ host inventory ingest is not served
	telemetry        fleetTelemetryIngest  // optional; nil ⇒ telemetry ingest is not served (A3 #624)
	detections       fleetDetectionIngest  // optional; nil ⇒ detection ingest is not served (A4 #625)
	keyReg           fleetKeyRegistration  // optional; nil ⇒ signing-key registration is not served (A4 #625)
	minAgentVersion  string                // #412 version skew: agents below this are refused work; "" = no floor
	cpVersion        string                // control-plane version advertised to agents (min_control_plane check)
	rollout          fleetRolloutDecider   // optional; nil ⇒ no update is ever offered (#412 req 9)
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

// SetFleetRollout wires the operator-controlled update rollout (#412 req 9). Optional: with no
// decider wired the heartbeat offers no update at all, which is the fail-closed default — an absent
// rollout service must never read as permission to update.
func (rt *Router) SetFleetRollout(d fleetRolloutDecider) {
	if rt.fleet != nil {
		rt.fleet.rollout = d
	}
}

// SetFleetClusterInventory wires the cluster snapshot ingest use case onto the agent transport plane.
// It must be called after SetFleet; a nil fleet (transport disabled) makes it a no-op.
func (rt *Router) SetFleetClusterInventory(s fleetClusterInventory) {
	if rt.fleet != nil {
		rt.fleet.clusterInv = s
	}
}

// SetFleetHostInventory wires the VM host inventory ingest use case onto the agent transport plane.
// It must be called after SetFleet; a nil fleet (transport disabled) makes it a no-op.
func (rt *Router) SetFleetHostInventory(s fleetHostInventory) {
	if rt.fleet != nil {
		rt.fleet.hostInv = s
	}
}

// SetFleetTelemetry wires the agent-plane telemetry batch ingest (A3 #624). When nil (or unset),
// POST /api/v1/fleet/telemetry returns 404. It must be called after SetFleet.
func (rt *Router) SetFleetTelemetry(s fleetTelemetryIngest) {
	if rt.fleet != nil {
		rt.fleet.telemetry = s
	}
}

// SetFleetDetectionIngest wires the agent-plane detection batch ingest (A4 #625). When nil (or unset),
// POST /api/v1/fleet/detections returns 404. It must be called after SetFleet.
func (rt *Router) SetFleetDetectionIngest(s fleetDetectionIngest) {
	if rt.fleet != nil {
		rt.fleet.detections = s
	}
}

// SetFleetKeyRegistration wires the agent-plane signing-key registration (A4 #625, A0.2). When nil (or
// unset), POST /api/v1/fleet/keys returns 404. It must be called after SetFleet.
func (rt *Router) SetFleetKeyRegistration(s fleetKeyRegistration) {
	if rt.fleet != nil {
		rt.fleet.keyReg = s
	}
}

// SetFleetKeyAdmin wires the operator (human, RBAC-gated) signing-key management routes (list + revoke).
// When nil, those routes are not registered.
func (rt *Router) SetFleetKeyAdmin(s fleetKeyAdmin) { rt.fleetKeys = s }

// SetFleetVersionPolicy wires the version-skew policy (#412): minAgentVersion is the minimum agent
// version allowed to claim work (empty = no floor), and cpVersion is the control-plane version
// advertised to agents so they can enforce their own minimum control-plane requirement. Must be
// called after SetFleet.
func (rt *Router) SetFleetVersionPolicy(minAgentVersion, cpVersion string) {
	if rt.fleet != nil {
		rt.fleet.minAgentVersion = strings.TrimSpace(minAgentVersion)
		rt.fleet.cpVersion = strings.TrimSpace(cpVersion)
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

// fleetAgentPlaneRoute is one route on the untrusted agent-auth plane: the pattern its mux serves
// and the top-level prefix the Router mounts it under. The two live together so a new agent route
// cannot be registered without also declaring how it is mounted - the failure mode being that the
// route falls through to the human RBAC chain and is rejected as an unauthenticated operator
// request. Anything under /api/v1/fleet NOT listed here is an operator route on the human plane.
type fleetAgentPlaneRoute struct {
	pattern string // the mux pattern, including the method
	mount   string // the top-level prefix Router.Handler() mounts this plane under
	// handler produces the route's handler from the router. Carrying it here rather than in a
	// side table makes the pattern/mount/handler relation TOTAL by construction: a new route cannot
	// be declared without a handler, so there is no missing-case branch to fail open or 404.
	handler func(*fleetRouter) http.HandlerFunc
}

// fleetAgentPlaneRoutes is the single source of truth consumed by BOTH fleetRouter.handler() (which
// registers the patterns) and Router.Handler() (which mounts the distinct prefixes).
func fleetAgentPlaneRoutes() []fleetAgentPlaneRoute {
	return []fleetAgentPlaneRoute{
		{"POST /api/v1/fleet/enrol", "/api/v1/fleet/enrol",
			func(f *fleetRouter) http.HandlerFunc { return f.entry(f.enrol) }},
		{"POST /api/v1/fleet/heartbeat", "/api/v1/fleet/heartbeat",
			func(f *fleetRouter) http.HandlerFunc { return f.entry(f.authed(f.heartbeat)) }},
		{"POST /api/v1/fleet/decommission", "/api/v1/fleet/decommission",
			func(f *fleetRouter) http.HandlerFunc { return f.entry(f.authed(f.decommission)) }},
		{"POST /api/v1/fleet/work/claim", "/api/v1/fleet/work/",
			func(f *fleetRouter) http.HandlerFunc { return f.entry(f.authed(f.claim)) }},
		{"POST /api/v1/fleet/work/{id}/progress", "/api/v1/fleet/work/",
			func(f *fleetRouter) http.HandlerFunc { return f.entry(f.authed(f.progress)) }},
		{"POST /api/v1/fleet/work/{id}/result", "/api/v1/fleet/work/",
			func(f *fleetRouter) http.HandlerFunc { return f.entry(f.authed(f.result)) }},
		{"POST /api/v1/fleet/inventory/cluster", "/api/v1/fleet/inventory/",
			func(f *fleetRouter) http.HandlerFunc { return f.entry(f.authed(f.clusterInventory)) }},
		{"POST /api/v1/fleet/inventory/host", "/api/v1/fleet/inventory/",
			func(f *fleetRouter) http.HandlerFunc { return f.entry(f.authed(f.hostInventory)) }},
		{"POST /api/v1/fleet/telemetry", "/api/v1/fleet/telemetry",
			func(f *fleetRouter) http.HandlerFunc { return f.entry(f.authed(f.ingestTelemetry)) }},
		{"POST /api/v1/fleet/detections", "/api/v1/fleet/detections",
			func(f *fleetRouter) http.HandlerFunc { return f.entry(f.authed(f.ingestDetections)) }},
		{"POST /api/v1/fleet/keys", "/api/v1/fleet/keys",
			func(f *fleetRouter) http.HandlerFunc { return f.entry(f.authed(f.registerKey)) }},
	}
}

// fleetAgentPlaneMounts returns the deduplicated top-level prefixes for the agent plane, preserving
// declaration order.
func fleetAgentPlaneMounts() []string {
	seen := make(map[string]bool)
	var mounts []string
	for _, route := range fleetAgentPlaneRoutes() {
		if !seen[route.mount] {
			seen[route.mount] = true
			mounts = append(mounts, route.mount)
		}
	}
	return mounts
}

// handler builds the agent-plane mux. Every route checks the protocol version; every route except
// enrol requires a valid agent bearer credential (agent-auth, NOT the human RBAC plane).
func (f *fleetRouter) handler() http.Handler {
	mux := http.NewServeMux()
	for _, route := range fleetAgentPlaneRoutes() {
		mux.HandleFunc(route.pattern, route.handler(f))
	}
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
			case errors.Is(err, fleetagentuc.ErrDecommissioned):
				writeJSON(w, http.StatusForbidden, errorBody{Error: "decommissioned"})
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
		// Bind the AUTHENTICATED agent's tenant onto the context (never a request field). Downstream
		// writes - notably the hash-chained audit log - read the tenant from the context to satisfy
		// tenant RLS, and this plane has no human principal to carry it. Without this, heartbeat,
		// claim, result, and inventory writes fail the audit insert with
		// "new row violates row-level security policy for table audit_log".
		ctx = shared.WithTenant(ctx, agent.TenantID)
		if observation := requestObservationFrom(ctx); observation != nil {
			observation.setPrincipal(agent.ID.String())
		}
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
	// Advertise the protocol version, the control-plane version, and the minimum supported agent
	// version so the agent can act on version skew (#412): update itself, or refuse to run against a
	// control plane older than it requires.
	out := map[string]any{
		"proto":                       FleetProtoVersion,
		"control_plane_version":       f.cpVersion,
		"min_supported_agent_version": f.minAgentVersion,
	}
	// The update offer (#412 req 9). It is computed from the OPERATOR's rollout plan and the agent's
	// operator-assigned group — never from anything the agent just reported about itself, which is why
	// the group comes off the stored agent rather than out of the heartbeat body. With no rollout
	// service wired, no update is ever offered: the absence of a decider is not permission.
	out["update"] = f.updateOffer(r.Context(), agent, req.AgentVersion)
	writeJSON(w, http.StatusOK, out)
}

// decommission records the agent's own clean-uninstall report (#412, AC 11). It is agent-authenticated
// (the caller is the agent, resolved by authed), tenant-scoped to that agent's identity, and takes no
// body — the identity is the credential, never a request field. The control plane then shows the agent
// as decommissioned rather than letting it decay into stale, and the credential stops authenticating.
func (f *fleetRouter) decommission(w http.ResponseWriter, r *http.Request) {
	agent, _ := agentFrom(r.Context())
	if err := f.agents.Decommission(r.Context(), agent); err != nil {
		writeError(w, f.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "decommissioned"})
}

// updateOffer computes the heartbeat's update block for ONE agent.
//
// The group comes off the STORED agent, never out of the heartbeat body: an agent that could name its
// own group could place itself in one pinned to an older, vulnerable version. With no rollout decider
// wired nothing is ever offered — the absence of a decider is not permission.
func (f *fleetRouter) updateOffer(ctx context.Context, agent *fleetagent.Agent, agentVersion string) map[string]any {
	if f.rollout == nil {
		return map[string]any{"available": false, "reason": "no rollout service is configured"}
	}
	decision := f.rollout.DecideFor(ctx, agent.TenantID, fleetrollout.DefaultChannel, agent.Group, agentVersion)
	offer := map[string]any{"available": decision.Offer, "reason": string(decision.Reason)}
	if decision.Offer {
		offer["target_version"] = decision.Target
	}
	return offer
}

func (f *fleetRouter) claim(w http.ResponseWriter, r *http.Request) {
	agent, _ := agentFrom(r.Context())
	// Version skew (#412): an agent below the minimum supported version is refused work with a clear
	// instruction to update, rather than handed orders it may mishandle. Fail-closed: an agent that
	// does not state a parseable version under an active floor is refused too.
	if !fleetversion.MeetsFloor(agent.AgentVersion, f.minAgentVersion) {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{
			"error":                       "agent version below minimum supported",
			"your_version":                agent.AgentVersion,
			"min_supported_agent_version": f.minAgentVersion,
			"instruction":                 "update the agent to at least the minimum supported version, then resume claiming work",
		})
		return
	}
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

// hostInventory ingests a VM host inventory the agent collected and persists the host into the asset
// model via the host-inventory use case. Tenant and actor come from the authenticated agent (never
// the request body). The coverage summary (complete/degraded/gaps) is returned so a partial host
// inventory is visible, never silently treated as clean.
func (f *fleetRouter) hostInventory(w http.ResponseWriter, r *http.Request) {
	if f.hostInv == nil {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "host inventory ingest not enabled"})
		return
	}
	agent, ok := agentFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthenticated"})
		return
	}
	var inv dhi.HostInventory
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, fleetInventoryCap)).Decode(&inv); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid host inventory body"})
		return
	}
	res, err := f.hostInv.Sync(r.Context(), agent.ID.String(), hostinventoryuc.SyncInput{
		TenantID:  agent.TenantID,
		Inventory: inv,
	})
	if err != nil {
		writeError(w, f.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"asset_id": res.AssetID.String(), "complete": res.Complete, "degraded": res.Degraded, "coverage_gaps": res.Coverage,
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
