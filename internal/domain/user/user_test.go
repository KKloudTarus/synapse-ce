package user

import "testing"

// TestRolePermissions pins the RBAC matrix exactly – including the crown-jewel
// separation-of-duties property that machine (mcp/agent) and unknown roles are granted NOTHING,
// so they can never operate, triage, review (verify/decide), or administer via the human API.
func TestRolePermissions(t *testing.T) {
	cases := []struct {
		role Role
		perm Permission
		want bool
	}{
		// admin: everything.
		{RoleAdmin, PermView, true}, {RoleAdmin, PermOperate, true}, {RoleAdmin, PermTriage, true}, {RoleAdmin, PermReview, true}, {RoleAdmin, PermAdminister, true},
		// consultant: view + operate + triage; NOT review (sign-off) or administer.
		{RoleConsultant, PermView, true}, {RoleConsultant, PermOperate, true}, {RoleConsultant, PermTriage, true}, {RoleConsultant, PermReview, false}, {RoleConsultant, PermAdminister, false},
		// member is the alias for consultant – identical grants.
		{RoleMember, PermView, true}, {RoleMember, PermOperate, true}, {RoleMember, PermTriage, true}, {RoleMember, PermReview, false}, {RoleMember, PermAdminister, false},
		// reviewer: view + triage + review (sign-off); NOT operate or administer (separation of duties).
		{RoleReviewer, PermView, true}, {RoleReviewer, PermTriage, true}, {RoleReviewer, PermReview, true}, {RoleReviewer, PermOperate, false}, {RoleReviewer, PermAdminister, false},
		// readonly: view only.
		{RoleReadOnly, PermView, true}, {RoleReadOnly, PermOperate, false}, {RoleReadOnly, PermTriage, false}, {RoleReadOnly, PermReview, false}, {RoleReadOnly, PermAdminister, false},
		// machine + unknown roles: NOTHING (the SoD invariant – an agent/mcp principal can never
		// approve its own actions or verify findings, and an unknown role is fail-closed).
		{Role("mcp"), PermView, false}, {Role("mcp"), PermReview, false}, {Role("mcp"), PermOperate, false}, {Role("mcp"), PermAdminister, false},
		{Role("agent"), PermView, false}, {Role("agent"), PermReview, false}, {Role("agent"), PermOperate, false},
		{Role("bogus"), PermView, false}, {Role(""), PermView, false}, {Role(""), PermReview, false},
	}
	for _, c := range cases {
		if got := c.role.Can(c.perm); got != c.want {
			t.Errorf("Role(%q).Can(%q) = %v, want %v", c.role, c.perm, got, c.want)
		}
	}
}

// TestEveryDeclaredRoleIsInMatrix guards against adding a Role constant but forgetting its matrix
// entry – such a role would silently grant nothing (fail-closed, so safe, but a latent bug that
// the exhaustive case table above would not catch for a NEW role). Every canonical human role must
// appear and grant at least the view floor. (RoleMember aliases to consultant, so it is exempt.)
func TestEveryDeclaredRoleIsInMatrix(t *testing.T) {
	for _, r := range []Role{RoleAdmin, RoleConsultant, RoleReviewer, RoleReadOnly} {
		if _, ok := rolePermissions[r]; !ok {
			t.Errorf("role %q is declared but missing from rolePermissions (would silently grant nothing)", r)
		}
		if !r.Can(PermView) {
			t.Errorf("role %q grants not even PermView – likely a missing/empty matrix entry", r)
		}
	}
}

func TestRoleValid(t *testing.T) {
	for _, r := range []Role{RoleAdmin, RoleConsultant, RoleReviewer, RoleReadOnly, RoleMember} {
		if !r.Valid() {
			t.Errorf("%q must be a valid role", r)
		}
	}
	for _, r := range []Role{"mcp", "agent", "bogus", ""} {
		if r.Valid() {
			t.Errorf("%q must NOT be a valid role", r)
		}
	}
}
