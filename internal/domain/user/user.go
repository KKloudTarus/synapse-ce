// Package user models operator identities: each consultant is a
// distinct user with their own API key, so every action – comments, findings,
// assignments, audit, evidence – is attributable to a real person, not a shared
// "operator". Only the API key's SHA-256 digest is ever stored; the raw key is
// shown once at creation and never persisted.
package user

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Role is the coarse permission level of a user (RBAC).
type Role string

const (
	RoleAdmin      Role = "admin"      // full access + user/tenant management
	RoleConsultant Role = "consultant" // engagement work: run tools, edit scope, author findings, agent
	RoleReviewer   Role = "reviewer"   // QA/sign-off: triage + verify findings + decide agent approvals
	RoleReadOnly   Role = "readonly"   // read engagement data + sealed report artifacts; no writes
	// RoleMember is the name for RoleConsultant. Kept valid so existing users (and the
	// createUser default) keep working; it is granted exactly the consultant permission set.
	RoleMember Role = "member"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleConsultant, RoleReviewer, RoleReadOnly, RoleMember:
		return true
	}
	return false
}

// Permission is a coarse capability a handler requires (RBAC). Buckets are intentionally
// few and well-understood – easier to reason about and audit than dozens of fine-grained flags.
type Permission string

const (
	// PermView – read engagement-scoped data + sealed report/export artifacts. The floor for any
	// authenticated human principal in a tenant.
	PermView Permission = "view"
	// PermOperate – engagement work that writes or executes: create/edit engagements, scope,
	// window, RoE, live-recon, transition; run scans/recon; import SBOM; capture evidence; apply
	// VEX; manage credentials; author findings; start agent sessions; import a bundle.
	PermOperate Permission = "operate"
	// PermTriage – light finding handling that is neither authoring nor sign-off: comment, set
	// status, assign, record a retest. Held by consultants and reviewers.
	PermTriage Permission = "triage"
	// PermReview – sign-off with separation of duties: verify/confirm an exploitation finding
	// and decide an agent HITL approval. NEVER held by a machine (mcp/agent) role.
	PermReview Permission = "review"
	// PermAdminister – user management + tenant assignment. Admin only.
	PermAdminister Permission = "administer"
)

// rolePermissions is the static RBAC policy: role → the permissions it grants. A role absent from
// a permission's set is denied. Machine roles (mcp/agent) and any unknown role appear nowhere, so
// they are granted nothing on the human REST API (they act only via their own propose-only surface).
//
// INVARIANT: read-only after package initialization. It is never mutated at runtime; Can is the
// only accessor. Do not write to it – a guarded static table is what makes authorization a pure,
// race-free decision.
var rolePermissions = map[Role]map[Permission]bool{
	RoleAdmin:      {PermView: true, PermOperate: true, PermTriage: true, PermReview: true, PermAdminister: true},
	RoleConsultant: {PermView: true, PermOperate: true, PermTriage: true},
	RoleReviewer:   {PermView: true, PermTriage: true, PermReview: true},
	RoleReadOnly:   {PermView: true},
}

// Can reports whether role r is granted permission p. Unknown and machine roles grant nothing.
// RoleMember resolves to the consultant permission set (backward compatibility).
func (r Role) Can(p Permission) bool {
	if r == RoleMember {
		r = RoleConsultant
	}
	return rolePermissions[r][p]
}

// User is an operator identity. APIKeyHash is the lowercase-hex SHA-256 of the
// user's bearer token (never the raw token).
type User struct {
	ID         shared.ID
	Name       string
	Role       Role
	APIKeyHash string
	Disabled   bool
	// TenantID is the tenant this operator belongs to; the authenticated Principal carries it so
	// it propagates into writes and scopes reads. Empty = the single default tenant
	// (single-tenant mode); the bootstrap admin is intentionally '' (the default-tenant superadmin).
	// Assigned at construction by the provisioning admin, never from the new user's own token.
	TenantID string
	Audit    shared.Audit
}

// New validates and constructs a user in tenantID (” = the single default tenant).
func New(id shared.ID, tenantID string, name string, role Role, apiKeyHash string, now time.Time) (*User, error) {
	if id.IsZero() {
		return nil, fmt.Errorf("%w: user id is required", shared.ErrValidation)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("%w: user name is required", shared.ErrValidation)
	}
	if !role.Valid() {
		return nil, fmt.Errorf("%w: invalid role %q", shared.ErrValidation, role)
	}
	if apiKeyHash == "" {
		return nil, fmt.Errorf("%w: api key hash is required", shared.ErrValidation)
	}
	return &User{ID: id, TenantID: tenantID, Name: name, Role: role, APIKeyHash: apiKeyHash, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}}, nil
}
