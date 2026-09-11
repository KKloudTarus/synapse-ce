package httpapi

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	ownershipuc "github.com/KKloudTarus/synapse-ce/internal/usecase/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func (rt *Router) SetOwnership(s *ownershipuc.Service, mode, reason string) {
	rt.ownership = s
	rt.ownershipMode = mode
	rt.ownershipUnavailable = reason
}
func (rt *Router) registerOwnership(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/ownership/capabilities", rt.authz(user.PermView, rt.ownershipCapabilities))
	if rt.ownership == nil {
		return
	}
	mux.HandleFunc("GET /api/v1/ownership/teams", rt.ownershipAuthorized(user.PermView, rt.ownershipTeams))
	mux.HandleFunc("POST /api/v1/ownership/teams", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipTeams))
	mux.HandleFunc("GET /api/v1/ownership/teams/{tid}", rt.ownershipAuthorized(user.PermView, rt.ownershipTeams))
	mux.HandleFunc("PATCH /api/v1/ownership/teams/{tid}", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipTeams))
	mux.HandleFunc("GET /api/v1/ownership/teams/{tid}/members", rt.ownershipAuthorized(user.PermView, rt.ownershipMembers))
	mux.HandleFunc("PUT /api/v1/ownership/teams/{tid}/members/{uid}", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipMembers))
	mux.HandleFunc("DELETE /api/v1/ownership/teams/{tid}/members/{uid}", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipMembers))
	mux.HandleFunc("GET /api/v1/ownership/mappings", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipMappings))
	mux.HandleFunc("PUT /api/v1/ownership/mappings", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipMappings))
	mux.HandleFunc("DELETE /api/v1/ownership/mappings", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipMappings))
	mux.HandleFunc("GET /api/v1/ownership/asset-mappings", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipAssetMappings))
	mux.HandleFunc("PUT /api/v1/ownership/asset-mappings", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipAssetMappings))
	mux.HandleFunc("DELETE /api/v1/ownership/asset-mappings", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipAssetMappings))
	mux.HandleFunc("GET /api/v1/ownership/snapshots", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipSnapshots))
	mux.HandleFunc("POST /api/v1/ownership/snapshots", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipSnapshots))
	mux.HandleFunc("GET /api/v1/ownership/snapshots/{sid}", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipSnapshots))
	mux.HandleFunc("POST /api/v1/ownership/snapshots/{sid}/approve", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipApproveSnapshot))
	mux.HandleFunc("GET /api/v1/ownership/policies", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipPolicies))
	mux.HandleFunc("POST /api/v1/ownership/policies", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipPolicies))
	mux.HandleFunc("GET /api/v1/ownership/policies/{pid}", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipPolicies))
	mux.HandleFunc("POST /api/v1/ownership/policies/{pid}/versions", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipPolicies))
	mux.HandleFunc("GET /api/v1/ownership/policies/{pid}/versions/{version}", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipPolicies))
	mux.HandleFunc("POST /api/v1/ownership/policies/{pid}/activate", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipActivate))
	mux.HandleFunc("POST /api/v1/ownership/policies/{pid}/preview", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipStartRun))
	mux.HandleFunc("POST /api/v1/ownership/policies/{pid}/reroute", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipStartRun))
	mux.HandleFunc("GET /api/v1/ownership/runs/{rid}", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipRun))
	mux.HandleFunc("GET /api/v1/ownership/runs/{rid}/items", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipRun))
	mux.HandleFunc("POST /api/v1/ownership/runs/{rid}/cancel", rt.ownershipAuthorized(user.PermAdminister, rt.ownershipRun))
	mux.HandleFunc("GET /api/v1/ownership/findings", rt.ownershipAuthorized(user.PermView, rt.ownershipInbox))
	mux.HandleFunc("POST /api/v1/ownership/bulk", rt.ownershipAuthorized(user.PermTriage, rt.ownershipBulk))
	mux.HandleFunc("GET /api/v1/engagements/{id}/findings/{fid}/ownership", rt.ownershipAuthorized(user.PermView, rt.ownershipFinding))
	mux.HandleFunc("POST /api/v1/engagements/{id}/findings/{fid}/ownership", rt.ownershipAuthorized(user.PermTriage, rt.ownershipFinding))
	mux.HandleFunc("GET /api/v1/engagements/{id}/findings/{fid}/ownership/history", rt.ownershipAuthorized(user.PermView, rt.ownershipFinding))
}

// Authority comes from the authenticated principal, including when an ambient
// tenant context conflicts. Services recheck the stored role and visibility.
func (rt *Router) ownershipAuthorized(permission user.Permission, handler http.HandlerFunc) http.HandlerFunc {
	return rt.authz(permission, func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(shared.WithTenant(r.Context(), shared.TenantOrDefault(shared.ID(TenantFrom(r.Context())))))
		handler(w, r)
	})
}
func (rt *Router) ownershipCapabilities(w http.ResponseWriter, r *http.Request) {
	if rt.ownership != nil {
		writeJSON(w, 200, rt.ownership.Capability())
		return
	}
	mode := rt.ownershipMode
	if mode == "" {
		mode = "off"
	}
	reason := rt.ownershipUnavailable
	if reason == "" {
		reason = "disabled"
	}
	writeJSON(w, 200, ownershipuc.Capability{Mode: mode, Reason: reason})
}
func (rt *Router) ownershipReply(w http.ResponseWriter, status int, value any, err error) {
	if errors.Is(err, ownershipuc.ErrWorkerUnavailable) {
		writeJSON(w, 503, errorBody{Error: err.Error()})
		return
	}
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if status == 204 {
		w.WriteHeader(status)
		return
	}
	writeJSON(w, status, value)
}
func decodeOwnership(w http.ResponseWriter, r *http.Request, out any, maximum int64) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, maximum))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return shared.ErrValidation
	}
	var tail any
	if err := d.Decode(&tail); err != io.EOF {
		return shared.ErrValidation
	}
	return nil
}
func ownershipQuery(r *http.Request, allowed ...string) error {
	keys := map[string]bool{"limit": true, "cursor": true}
	for _, k := range allowed {
		keys[k] = true
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return shared.ErrValidation
	}
	for k, v := range q {
		if !keys[k] || len(v) != 1 {
			return shared.ErrValidation
		}
	}
	return nil
}
func ownershipPositive(raw string) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 0, shared.ErrValidation
	}
	return n, nil
}
func ownershipScope(r *http.Request) string {
	q := r.URL.Query()
	q.Del("cursor")
	q.Del("limit")
	sum := sha256.Sum256([]byte(r.URL.Path + "?" + q.Encode() + "\x00" + TenantFrom(r.Context()) + "\x00" + PrincipalFrom(r.Context())))
	return hex.EncodeToString(sum[:])
}

type ownershipCursor struct {
	Scope string `json:"scope"`
	After string `json:"after"`
}

func ownershipNext(r *http.Request, after string) string {
	if after == "" {
		return ""
	}
	data, _ := json.Marshal(ownershipCursor{Scope: ownershipScope(r), After: after})
	return base64.RawURLEncoding.EncodeToString(data)
}
func ownershipPage(r *http.Request) (string, int, error) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		v, e := ownershipPositive(raw)
		if e != nil || v > 200 {
			return "", 0, shared.ErrValidation
		}
		limit = v
	}
	raw := r.URL.Query().Get("cursor")
	if raw == "" {
		return "", limit, nil
	}
	if len(raw) > 4096 {
		return "", 0, shared.ErrValidation
	}
	data, e := base64.RawURLEncoding.DecodeString(raw)
	var c ownershipCursor
	if e != nil || json.Unmarshal(data, &c) != nil || c.Scope != ownershipScope(r) || c.After == "" {
		return "", 0, shared.ErrValidation
	}
	return c.After, limit, nil
}

type ownershipList[T any] struct {
	Items []T    `json:"items"`
	Next  string `json:"next,omitempty"`
}

func ownershipListPage[T any](r *http.Request, items []T, limit int, last func(T) string) ownershipList[T] {
	if items == nil {
		items = []T{}
	}
	out := ownershipList[T]{Items: items}
	if len(items) == limit && len(items) > 0 {
		out.Next = ownershipNext(r, last(items[len(items)-1]))
	}
	return out
}

func (rt *Router) ownershipTeams(w http.ResponseWriter, r *http.Request) {
	s, ctx, actor, id := rt.ownership, r.Context(), PrincipalFrom(r.Context()), shared.ID(r.PathValue("tid"))
	if r.Method != "GET" {
		var in ownershipuc.TeamInput
		if e := decodeOwnership(w, r, &in, 8192); e != nil {
			rt.ownershipReply(w, 0, nil, e)
			return
		}
		if r.Method == "PATCH" && in.Revision < 1 {
			rt.ownershipReply(w, 0, nil, shared.ErrValidation)
			return
		}
		v, e := s.SaveTeam(ctx, actor, id, in)
		status := 200
		if r.Method == "POST" {
			status = 201
		}
		rt.ownershipReply(w, status, v, e)
		return
	}
	if !id.IsZero() {
		v, e := s.Team(ctx, actor, id)
		rt.ownershipReply(w, 200, v, e)
		return
	}
	if e := ownershipQuery(r); e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	after, limit, e := ownershipPage(r)
	if e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	v, e := s.Teams(ctx, actor, shared.ID(after), limit)
	out := ownershipListPage(r, v, limit, func(v domain.Team) string { return v.ID.String() })
	rt.ownershipReply(w, 200, out, e)
}
func (rt *Router) ownershipMembers(w http.ResponseWriter, r *http.Request) {
	id := shared.ID(r.PathValue("tid"))
	if r.Method != "GET" {
		var in struct {
			Revision int `json:"revision"`
		}
		if e := decodeOwnership(w, r, &in, 8192); e != nil {
			rt.ownershipReply(w, 0, nil, e)
			return
		}
		e := rt.ownership.Member(r.Context(), PrincipalFrom(r.Context()), id, shared.ID(r.PathValue("uid")), in.Revision, r.Method == "DELETE")
		rt.ownershipReply(w, 204, nil, e)
		return
	}
	if e := ownershipQuery(r); e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	after, limit, e := ownershipPage(r)
	if e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	v, e := rt.ownership.Members(r.Context(), PrincipalFrom(r.Context()), id, shared.ID(after), limit)
	rt.ownershipReply(w, 200, ownershipListPage(r, v, limit, func(v domain.Membership) string { return v.UserID.String() }), e)
}
func (rt *Router) ownershipMappings(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		var in struct {
			EngagementID shared.ID      `json:"engagement_id"`
			Mapping      domain.Mapping `json:"mapping"`
			Revision     int            `json:"revision"`
		}
		if e := decodeOwnership(w, r, &in, 16384); e != nil {
			rt.ownershipReply(w, 0, nil, e)
			return
		}
		e := rt.ownership.SaveMapping(r.Context(), PrincipalFrom(r.Context()), in.EngagementID, ports.OwnershipMapping{Mapping: in.Mapping, Revision: in.Revision}, r.Method == "DELETE")
		rt.ownershipReply(w, 204, nil, e)
		return
	}
	if e := ownershipQuery(r, "engagement_id", "repository"); e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	after, limit, e := ownershipPage(r)
	if e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	q := r.URL.Query()
	v, e := rt.ownership.Mappings(r.Context(), PrincipalFrom(r.Context()), shared.ID(q.Get("engagement_id")), q.Get("repository"), after, limit)
	rt.ownershipReply(w, 200, ownershipListPage(r, v, limit, func(v ports.OwnershipMapping) string { return v.Mapping.Owner }), e)
}
func (rt *Router) ownershipAssetMappings(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		var in ports.OwnershipAssetMapping
		if e := decodeOwnership(w, r, &in, 16384); e != nil {
			rt.ownershipReply(w, 0, nil, e)
			return
		}
		e := rt.ownership.SaveAssetMapping(r.Context(), PrincipalFrom(r.Context()), in, r.Method == "DELETE")
		rt.ownershipReply(w, 204, nil, e)
		return
	}
	if e := ownershipQuery(r); e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	after, limit, e := ownershipPage(r)
	if e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	v, e := rt.ownership.AssetMappings(r.Context(), PrincipalFrom(r.Context()), shared.ID(after), limit)
	rt.ownershipReply(w, 200, ownershipListPage(r, v, limit, func(v ports.OwnershipAssetMapping) string { return v.Mapping.AssetID.String() }), e)
}
func (rt *Router) ownershipSnapshots(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var in ownershipuc.SnapshotInput
		if e := decodeOwnership(w, r, &in, 4<<20); e != nil {
			rt.ownershipReply(w, 0, nil, e)
			return
		}
		v, e := rt.ownership.ImportSnapshot(r.Context(), PrincipalFrom(r.Context()), in)
		rt.ownershipReply(w, 201, v, e)
		return
	}
	if id := r.PathValue("sid"); id != "" {
		v, e := rt.ownership.Snapshot(r.Context(), PrincipalFrom(r.Context()), shared.ID(id))
		rt.ownershipReply(w, 200, v, e)
		return
	}
	if e := ownershipQuery(r, "engagement_id"); e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	after, limit, e := ownershipPage(r)
	if e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	v, e := rt.ownership.Snapshots(r.Context(), PrincipalFrom(r.Context()), shared.ID(r.URL.Query().Get("engagement_id")), shared.ID(after), limit)
	rt.ownershipReply(w, 200, ownershipListPage(r, v, limit, func(v domain.Snapshot) string { return v.ID.String() }), e)
}
func (rt *Router) ownershipApproveSnapshot(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Hash   string `json:"content_hash"`
		Accept bool   `json:"accept_diagnostics"`
	}
	if e := decodeOwnership(w, r, &in, 8192); e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	v, e := rt.ownership.ApproveSnapshot(r.Context(), PrincipalFrom(r.Context()), shared.ID(r.PathValue("sid")), in.Hash, in.Accept)
	rt.ownershipReply(w, 201, v, e)
}
func (rt *Router) ownershipPolicies(w http.ResponseWriter, r *http.Request) {
	id := shared.ID(r.PathValue("pid"))
	if r.Method == "POST" {
		var in ownershipuc.PolicyInput
		if e := decodeOwnership(w, r, &in, 8<<20); e != nil {
			rt.ownershipReply(w, 0, nil, e)
			return
		}
		v, e := rt.ownership.SavePolicy(r.Context(), PrincipalFrom(r.Context()), id, in)
		rt.ownershipReply(w, 201, map[string]any{"policy": v, "content_hash": v.Hash()}, e)
		return
	}
	if !id.IsZero() {
		if version := r.PathValue("version"); version != "" {
			n, e := ownershipPositive(version)
			if e != nil {
				rt.ownershipReply(w, 0, nil, e)
				return
			}
			v, e := rt.ownership.PolicyVersion(r.Context(), PrincipalFrom(r.Context()), id, n)
			rt.ownershipReply(w, 200, map[string]any{"policy": v, "content_hash": v.Hash()}, e)
			return
		}
		v, e := rt.ownership.Policy(r.Context(), PrincipalFrom(r.Context()), id)
		rt.ownershipReply(w, 200, v, e)
		return
	}
	if e := ownershipQuery(r, "engagement_id"); e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	after, limit, e := ownershipPage(r)
	if e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	v, e := rt.ownership.Policies(r.Context(), PrincipalFrom(r.Context()), shared.ID(r.URL.Query().Get("engagement_id")), shared.ID(after), limit)
	rt.ownershipReply(w, 200, ownershipListPage(r, v, limit, func(v ports.OwnershipPolicyHeader) string { return v.ID.String() }), e)
}
func (rt *Router) ownershipActivate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Version  int    `json:"version"`
		Revision int    `json:"revision"`
		Hash     string `json:"content_hash"`
	}
	if e := decodeOwnership(w, r, &in, 8192); e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	e := rt.ownership.Activate(r.Context(), PrincipalFrom(r.Context()), ports.OwnershipActivation{PolicyID: shared.ID(r.PathValue("pid")), Version: in.Version, ExpectedRevision: in.Revision, ExpectedHash: in.Hash})
	rt.ownershipReply(w, 204, nil, e)
}
func (rt *Router) ownershipStartRun(w http.ResponseWriter, r *http.Request) {
	var in ownershipuc.RunInput
	if e := decodeOwnership(w, r, &in, 65536); e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	mode := "preview"
	if strings.HasSuffix(r.URL.Path, "/reroute") {
		mode = "reroute"
	}
	v, e := rt.ownership.StartRun(r.Context(), PrincipalFrom(r.Context()), r.Header.Get("Idempotency-Key"), shared.ID(r.PathValue("pid")), mode, in)
	rt.ownershipReply(w, 202, v, e)
}
func (rt *Router) ownershipRun(w http.ResponseWriter, r *http.Request) {
	id := shared.ID(r.PathValue("rid"))
	if r.Method == "POST" {
		var in struct {
			Revision int `json:"revision"`
		}
		if e := decodeOwnership(w, r, &in, 8192); e != nil {
			rt.ownershipReply(w, 0, nil, e)
			return
		}
		e := rt.ownership.CancelRun(r.Context(), PrincipalFrom(r.Context()), id, in.Revision)
		rt.ownershipReply(w, 204, nil, e)
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/items") {
		v, e := rt.ownership.Run(r.Context(), PrincipalFrom(r.Context()), id)
		rt.ownershipReply(w, 200, v, e)
		return
	}
	if e := ownershipQuery(r); e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	after, limit, e := ownershipPage(r)
	if e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	v, e := rt.ownership.RunItems(r.Context(), PrincipalFrom(r.Context()), id, shared.ID(after), limit)
	rt.ownershipReply(w, 200, ownershipListPage(r, v, limit, func(v ports.OwnershipRunItem) string { return v.FindingID.String() }), e)
}
func (rt *Router) ownershipInbox(w http.ResponseWriter, r *http.Request) {
	if e := ownershipQuery(r, "engagement_id", "team_id", "assignee_id", "mine", "my_teams", "unresolved", "severity", "status", "kind", "sla_status", "due_before"); e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	after, limit, e := ownershipPage(r)
	if e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	q := r.URL.Query()
	flags := map[string]bool{}
	for _, key := range []string{"mine", "my_teams", "unresolved"} {
		if raw := q.Get(key); raw != "" {
			v, err := strconv.ParseBool(raw)
			if err != nil {
				rt.ownershipReply(w, 0, nil, shared.ErrValidation)
				return
			}
			flags[key] = v
		}
	}
	f := ports.OwnershipInboxFilter{EngagementID: shared.ID(q.Get("engagement_id")), TeamID: shared.ID(q.Get("team_id")), AssigneeID: shared.ID(q.Get("assignee_id")), MyTeams: flags["my_teams"], Unresolved: flags["unresolved"], Severity: shared.Severity(q.Get("severity")), Status: finding.Status(q.Get("status")), Kind: q.Get("kind"), SLAStatus: q.Get("sla_status"), After: shared.ID(after), Limit: limit}
	if flags["mine"] {
		if !f.AssigneeID.IsZero() && f.AssigneeID.String() != PrincipalFrom(r.Context()) {
			rt.ownershipReply(w, 0, nil, shared.ErrValidation)
			return
		}
		f.AssigneeID = shared.ID(PrincipalFrom(r.Context()))
	}
	if raw := q.Get("due_before"); raw != "" {
		at, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			rt.ownershipReply(w, 0, nil, shared.ErrValidation)
			return
		}
		f.DueBefore = &at
	}
	v, e := rt.ownership.Inbox(r.Context(), PrincipalFrom(r.Context()), f)
	v.Next = ownershipNext(r, v.Next)
	rt.ownershipReply(w, 200, v, e)
}
func (rt *Router) ownershipFinding(w http.ResponseWriter, r *http.Request) {
	eng, id := shared.ID(r.PathValue("id")), shared.ID(r.PathValue("fid"))
	actor := PrincipalFrom(r.Context())
	if r.Method == "POST" {
		var in ownershipuc.AssignmentInput
		if e := decodeOwnership(w, r, &in, 16384); e != nil {
			rt.ownershipReply(w, 0, nil, e)
			return
		}
		if !in.EngagementID.IsZero() && in.EngagementID != eng || !in.FindingID.IsZero() && in.FindingID != id {
			rt.ownershipReply(w, 0, nil, shared.ErrValidation)
			return
		}
		in.EngagementID, in.FindingID = eng, id
		v, e := rt.ownership.Assign(r.Context(), actor, r.Header.Get("Idempotency-Key"), in)
		rt.ownershipReply(w, 200, v, e)
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/history") {
		v, e := rt.ownership.Current(r.Context(), actor, eng, id)
		rt.ownershipReply(w, 200, v, e)
		return
	}
	if e := ownershipQuery(r); e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	after, limit, e := ownershipPage(r)
	if e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	c := ports.OwnershipHistoryCursor{Limit: limit}
	if after != "" {
		parts := strings.SplitN(after, "|", 2)
		if len(parts) != 2 {
			rt.ownershipReply(w, 0, nil, shared.ErrValidation)
			return
		}
		at, err := time.Parse(time.RFC3339Nano, parts[0])
		if err != nil {
			rt.ownershipReply(w, 0, nil, shared.ErrValidation)
			return
		}
		c.Before, c.BeforeID = at, shared.ID(parts[1])
	}
	v, e := rt.ownership.History(r.Context(), actor, eng, id, c)
	rt.ownershipReply(w, 200, ownershipListPage(r, v, limit, func(v domain.Decision) string { return v.CreatedAt.Format(time.RFC3339Nano) + "|" + v.ID.String() }), e)
}
func (rt *Router) ownershipBulk(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Items []ownershipuc.AssignmentInput `json:"items"`
	}
	if e := decodeOwnership(w, r, &in, 1<<20); e != nil {
		rt.ownershipReply(w, 0, nil, e)
		return
	}
	v, e := rt.ownership.Bulk(r.Context(), PrincipalFrom(r.Context()), r.Header.Get("Idempotency-Key"), in.Items)
	rt.ownershipReply(w, 200, map[string]any{"items": v}, e)
}
