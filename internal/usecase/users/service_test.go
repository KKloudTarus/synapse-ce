package users

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type nopAudit struct{}

func (nopAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Date(2026, 6, 21, 0, 0, 0, 0, time.UTC) }

type seqIDs struct {
	mu sync.Mutex
	n  int
}

func (g *seqIDs) NewID() shared.ID {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	return shared.ID("u-" + strconv.Itoa(g.n))
}

// bootstrapActor is the platform admin (the SYNAPSE_API_TOKEN principal), the only identity allowed
// to provision into another tenant.
var bootstrapActor = Actor{ID: BootstrapID}

// adminActor is an ordinary tenant admin: confined to its own tenant.
func adminActor(id, tenant string) Actor { return Actor{ID: id, TenantID: tenant} }

func newSvc(t *testing.T) (*Service, *memory.UserRepository) {
	t.Helper()
	repo := memory.NewUserRepository()
	svc, err := NewService(repo, nopAudit{}, fixedClock{}, &seqIDs{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return svc, repo
}

func TestCreateUserReturnsKeyOnceAndAuthenticates(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()

	u, key, err := svc.CreateUser(ctx, bootstrapActor, "", "Alice", user.RoleMember)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.Name != "Alice" || u.Role != user.RoleMember {
		t.Fatalf("user = %+v", u)
	}
	if !strings.HasPrefix(key, "syn_") {
		t.Errorf("api key should be prefixed: %q", key)
	}
	if u.APIKeyHash == key || u.APIKeyHash != HashToken(key) {
		t.Error("only the key HASH must be stored, never the raw key")
	}

	// The issued key authenticates back to that exact user – distinct attribution.
	got, err := svc.Authenticate(ctx, key)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got.ID != u.ID {
		t.Errorf("authenticated %s, want %s", got.ID, u.ID)
	}
	if _, err := svc.Authenticate(ctx, "syn_wrong"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("unknown token: want ErrNotFound, got %v", err)
	}
}

// TestCreateUserAssignsTenant covers the activation step (closes the "isolation is inert"
// gap): a provisioned user is stamped with the assigned tenant, and that tenant survives a
// re-authenticate round-trip – so the resolved Principal carries it and every read/write the user
// makes is tenant-scoped. The bootstrap admin stays tenant ” (the deliberate single-tenant /
// default-tenant superadmin), which is the only principal the ” escape hatch is meant for.
func TestCreateUserAssignsTenant(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()

	u, key, err := svc.CreateUser(ctx, bootstrapActor, "acme", "Alice", user.RoleMember)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.TenantID != "acme" {
		t.Fatalf("created user tenant = %q, want acme", u.TenantID)
	}
	got, err := svc.Authenticate(ctx, key)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got.TenantID != "acme" {
		t.Errorf("authenticated user tenant = %q, want acme (must survive the resolve round-trip)", got.TenantID)
	}

	if err := svc.EnsureBootstrapAdmin(ctx, "env-token"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	admin, err := svc.Authenticate(ctx, "env-token")
	if err != nil {
		t.Fatalf("authenticate admin: %v", err)
	}
	if admin.TenantID != "" {
		t.Errorf("bootstrap admin tenant = %q, want '' (single-tenant superadmin)", admin.TenantID)
	}
}

func TestBootstrapAdminIdempotentAndAuthenticates(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()

	if err := svc.EnsureBootstrapAdmin(ctx, "env-token"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	// Idempotent – a second call (e.g. restart) must not error or duplicate.
	if err := svc.EnsureBootstrapAdmin(ctx, "env-token"); err != nil {
		t.Fatalf("bootstrap (again): %v", err)
	}
	u, err := svc.Authenticate(ctx, "env-token")
	if err != nil {
		t.Fatalf("authenticate bootstrap: %v", err)
	}
	// id "operator" keeps historical attribution valid; it is an admin.
	if u.ID != BootstrapID || u.Role != user.RoleAdmin {
		t.Errorf("bootstrap user = %s/%s, want operator/admin", u.ID, u.Role)
	}
}

func TestTwoConsultantsAreDistinct(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	a, ka, _ := svc.CreateUser(ctx, bootstrapActor, "", "Alice", user.RoleMember)
	b, kb, _ := svc.CreateUser(ctx, bootstrapActor, "", "Bob", user.RoleMember)
	ua, _ := svc.Authenticate(ctx, ka)
	ub, _ := svc.Authenticate(ctx, kb)
	if ua.ID == ub.ID || ua.ID != a.ID || ub.ID != b.ID {
		t.Fatalf("consultants must resolve to distinct ids: %s vs %s", ua.ID, ub.ID)
	}
}

// recordingAudit captures the audit trail so the tests can prove every mutation is audited the way
// CreateUser is.
type recordingAudit struct{ entries []ports.AuditEntry }

func (a *recordingAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

func (a *recordingAudit) actions() []string {
	out := make([]string, 0, len(a.entries))
	for _, e := range a.entries {
		out = append(out, e.Action)
	}
	return out
}

func (a *recordingAudit) has(action, target string) bool {
	for _, e := range a.entries {
		if e.Action == action && e.Target == target {
			return true
		}
	}
	return false
}

func newAuditedSvc(t *testing.T) (*Service, *recordingAudit) {
	t.Helper()
	audit := &recordingAudit{}
	svc, err := NewService(memory.NewUserRepository(), audit, fixedClock{}, &seqIDs{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return svc, audit
}

// seedAdmin provisions an admin in tenant and returns the actor that admin authenticates as.
func seedAdmin(t *testing.T, svc *Service, tenant, name string) (*user.User, string, Actor) {
	t.Helper()
	u, key, err := svc.CreateUser(context.Background(), bootstrapActor, tenant, name, user.RoleAdmin)
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	return u, key, adminActor(u.ID.String(), tenant)
}

// TestRotateAPIKeyInvalidatesTheOldKey is the revocation path: a leaked key must stop working the
// moment a new one is issued.
func TestRotateAPIKeyInvalidatesTheOldKey(t *testing.T) {
	svc, audit := newAuditedSvc(t)
	ctx := context.Background()
	_, _, admin := seedAdmin(t, svc, "acme", "Admin")
	target, oldKey, err := svc.CreateUser(ctx, admin, "", "Alice", user.RoleMember)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	rotated, newKey, err := svc.RotateAPIKey(ctx, admin, target.ID)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if newKey == oldKey || !strings.HasPrefix(newKey, "syn_") {
		t.Fatalf("rotation must issue a different prefixed key, got %q", newKey)
	}
	if rotated.APIKeyHash != HashToken(newKey) {
		t.Error("only the new key HASH must be stored")
	}
	if _, err := svc.Authenticate(ctx, oldKey); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("old key still authenticates: %v", err)
	}
	got, err := svc.Authenticate(ctx, newKey)
	if err != nil || got.ID != target.ID {
		t.Fatalf("new key must authenticate the same user: %+v %v", got, err)
	}
	if !audit.has("user.api_key_rotated", target.ID.String()) {
		t.Errorf("rotation was not audited: %v", audit.actions())
	}
}

// TestDisableRejectsTheUsersKeyAndEnableRestoresIt covers revocation without deletion: the identity
// (and its attribution) survives, only authentication stops.
func TestDisableRejectsTheUsersKeyAndEnableRestoresIt(t *testing.T) {
	svc, audit := newAuditedSvc(t)
	ctx := context.Background()
	_, _, admin := seedAdmin(t, svc, "acme", "Admin")
	target, key, err := svc.CreateUser(ctx, admin, "", "Alice", user.RoleMember)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	disabled, err := svc.SetDisabled(ctx, admin, target.ID, true)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if !disabled.Disabled {
		t.Fatal("user must be disabled")
	}
	if _, err := svc.Authenticate(ctx, key); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("disabled user's key must be rejected, got %v", err)
	}
	if _, err := svc.SetDisabled(ctx, admin, target.ID, false); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if got, err := svc.Authenticate(ctx, key); err != nil || got.ID != target.ID {
		t.Fatalf("re-enabled user must authenticate with the same key: %+v %v", got, err)
	}
	if !audit.has("user.disabled", target.ID.String()) || !audit.has("user.enabled", target.ID.String()) {
		t.Errorf("disable/enable were not audited: %v", audit.actions())
	}
}

func TestUpdateChangesNameAndRole(t *testing.T) {
	svc, audit := newAuditedSvc(t)
	ctx := context.Background()
	_, _, admin := seedAdmin(t, svc, "acme", "Admin")
	target, _, err := svc.CreateUser(ctx, admin, "", "Alice", user.RoleMember)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	updated, err := svc.Update(ctx, admin, target.ID, "Alice Smith", user.RoleReviewer)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "Alice Smith" || updated.Role != user.RoleReviewer {
		t.Fatalf("update = %+v", updated)
	}
	// An omitted field keeps its value.
	if again, err := svc.Update(ctx, admin, target.ID, "", ""); err != nil || again.Name != "Alice Smith" || again.Role != user.RoleReviewer {
		t.Fatalf("empty fields must not clear: %+v %v", again, err)
	}
	if _, err := svc.Update(ctx, admin, target.ID, "Alice", user.Role("mcp")); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("a machine role must be rejected, got %v", err)
	}
	if !audit.has("user.updated", target.ID.String()) {
		t.Errorf("update was not audited: %v", audit.actions())
	}
}

// TestCannotDisableOrDemoteTheLastEnabledAdmin guards the tenant against locking itself out.
func TestCannotDisableOrDemoteTheLastEnabledAdmin(t *testing.T) {
	svc, _ := newAuditedSvc(t)
	ctx := context.Background()
	only, _, admin := seedAdmin(t, svc, "acme", "Only Admin")

	if _, err := svc.SetDisabled(ctx, admin, only.ID, true); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("disabling the last enabled admin must conflict, got %v", err)
	}
	if _, err := svc.Update(ctx, admin, only.ID, "", user.RoleReadOnly); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("demoting the last enabled admin must conflict, got %v", err)
	}
	// A second admin makes the first one disposable again.
	second, _, err := svc.CreateUser(ctx, admin, "", "Second Admin", user.RoleAdmin)
	if err != nil {
		t.Fatalf("create second admin: %v", err)
	}
	if _, err := svc.SetDisabled(ctx, admin, only.ID, true); err != nil {
		t.Fatalf("disable with a second admin present: %v", err)
	}
	// ...and once the first is disabled, the second is the last one standing.
	if _, err := svc.SetDisabled(ctx, admin, second.ID, true); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("disabling the remaining admin must conflict, got %v", err)
	}
}

// TestUserManagementIsConfinedToTheCallersTenant is the cross-tenant defect: a tenant-A admin could
// provision an admin into tenant B (and receive that admin's key), and list every tenant's users.
func TestUserManagementIsConfinedToTheCallersTenant(t *testing.T) {
	svc, _ := newAuditedSvc(t)
	ctx := context.Background()
	_, _, adminA := seedAdmin(t, svc, "tenant-a", "A Admin")
	_, _, adminB := seedAdmin(t, svc, "tenant-b", "B Admin")
	if _, _, err := svc.CreateUser(ctx, adminA, "", "A Member", user.RoleMember); err != nil {
		t.Fatalf("same-tenant create: %v", err)
	}
	targetB, _, err := svc.CreateUser(ctx, adminB, "", "B Member", user.RoleMember)
	if err != nil {
		t.Fatalf("same-tenant create: %v", err)
	}

	if _, _, err := svc.CreateUser(ctx, adminA, "tenant-b", "Planted Admin", user.RoleAdmin); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("cross-tenant provisioning must be forbidden, got %v", err)
	}
	// Reads and every other mutation are invisible across the tenant boundary.
	roster, err := svc.List(ctx, adminA)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, u := range roster {
		if u.TenantID != "tenant-a" {
			t.Errorf("tenant-a roster leaked %s of tenant %q", u.ID, u.TenantID)
		}
	}
	if len(roster) != 2 {
		t.Errorf("tenant-a roster = %d users, want 2", len(roster))
	}
	for _, mutation := range []struct {
		name string
		run  func() error
	}{
		{"update", func() error { _, err := svc.Update(ctx, adminA, targetB.ID, "Renamed", ""); return err }},
		{"disable", func() error { _, err := svc.SetDisabled(ctx, adminA, targetB.ID, true); return err }},
		{"rotate", func() error { _, _, err := svc.RotateAPIKey(ctx, adminA, targetB.ID); return err }},
	} {
		if err := mutation.run(); !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("cross-tenant %s = %v, want not found", mutation.name, err)
		}
	}
}

// TestPlatformAdminMayProvisionAnotherTenant keeps the one deliberate cross-tenant power: the
// bootstrap principal seeds a new tenant's first admin.
func TestPlatformAdminMayProvisionAnotherTenant(t *testing.T) {
	svc, _ := newAuditedSvc(t)
	ctx := context.Background()
	u, key, err := svc.CreateUser(ctx, bootstrapActor, "tenant-b", "B Admin", user.RoleAdmin)
	if err != nil {
		t.Fatalf("platform admin provisioning: %v", err)
	}
	if u.TenantID != "tenant-b" {
		t.Fatalf("provisioned tenant = %q, want tenant-b", u.TenantID)
	}
	got, err := svc.Authenticate(ctx, key)
	if err != nil || got.TenantID != "tenant-b" {
		t.Fatalf("provisioned key must authenticate into tenant-b: %+v %v", got, err)
	}
}

// TestDefaultTenantAdminCannotSeizeTheBootstrapPrincipal pins the escalation that the tenant
// confinement alone does not close. The bootstrap admin is stored with an empty tenant_id, which
// normalizes to the default tenant, so it sits in that tenant's roster and an ordinary default-tenant
// admin reaches it through the normal lookup. Rotating its key would hand that admin the plaintext
// credential of the platform principal every global-resource guard tests for; disabling or demoting
// it would lock the deployment operator out.
func TestDefaultTenantAdminCannotSeizeTheBootstrapPrincipal(t *testing.T) {
	svc, _ := newAuditedSvc(t)
	ctx := context.Background()
	if err := svc.EnsureBootstrapAdmin(ctx, "env-token"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	// An admin of the default tenant, which is the tenant the bootstrap row normalizes into.
	_, _, admin := seedAdmin(t, svc, "default", "Default Admin")

	// The operator is visible in the roster; that is honest, it really is in this tenant.
	roster, err := svc.List(ctx, admin)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var sawOperator bool
	for _, u := range roster {
		if u.ID.String() == BootstrapID {
			sawOperator = true
		}
	}
	if !sawOperator {
		t.Fatal("bootstrap admin should be listed in the default tenant it belongs to")
	}

	mutations := []struct {
		name string
		call func() error
	}{
		{"rotate", func() error { _, _, err := svc.RotateAPIKey(ctx, admin, BootstrapID); return err }},
		{"disable", func() error { _, err := svc.SetDisabled(ctx, admin, BootstrapID, true); return err }},
		{"demote", func() error { _, err := svc.Update(ctx, admin, BootstrapID, "", user.RoleReadOnly); return err }},
		{"rename", func() error { _, err := svc.Update(ctx, admin, BootstrapID, "Pwned", ""); return err }},
	}
	for _, m := range mutations {
		if err := m.call(); !errors.Is(err, shared.ErrForbidden) {
			t.Errorf("%s of the bootstrap principal = %v, want forbidden", m.name, err)
		}
	}

	// The env token still authenticates as the untouched operator.
	got, err := svc.Authenticate(ctx, "env-token")
	if err != nil {
		t.Fatalf("bootstrap token must still authenticate: %v", err)
	}
	if got.ID.String() != BootstrapID || got.Disabled || !got.Role.Can(user.PermAdminister) {
		t.Fatalf("bootstrap principal was altered: %+v", got)
	}

	// The operator cannot rotate itself either. EnsureBootstrapAdmin rewrites this row from the
	// environment token on every startup, so a key issued here would authenticate only until the
	// next restart while the environment token stopped working in the meantime.
	if _, _, err := svc.RotateAPIKey(ctx, bootstrapActor, BootstrapID); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("bootstrap self-rotation = %v, want forbidden", err)
	}
	if _, err := svc.SetDisabled(ctx, bootstrapActor, BootstrapID, true); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("bootstrap self-disable = %v, want forbidden", err)
	}
}

// TestConcurrentDemotionsCannotStrandATenant is the regression for the last-admin guard's
// read-modify-write. The guard counts the tenant's OTHER enabled admins and then writes. Two
// concurrent demotions, one per admin, each see the other still enabled, so both pass the count and
// both commit, leaving a tenant nobody can administer. The guard exists precisely to make that
// impossible, so exactly one of the two must be refused.
func TestConcurrentDemotionsCannotStrandATenant(t *testing.T) {
	for iteration := 0; iteration < 200; iteration++ {
		svc, _ := newAuditedSvc(t)
		ctx := context.Background()
		a1, _, actor1 := seedAdmin(t, svc, "acme", "Admin One")
		a2, _, actor2 := seedAdmin(t, svc, "acme", "Admin Two")

		start := make(chan struct{})
		errs := make(chan error, 2)
		for _, demotion := range []struct {
			actor Actor
			id    shared.ID
		}{{actor1, a2.ID}, {actor2, a1.ID}} {
			go func() {
				<-start
				_, err := svc.Update(ctx, demotion.actor, demotion.id, "", user.RoleReadOnly)
				errs <- err
			}()
		}
		close(start)
		first, second := <-errs, <-errs

		roster, err := svc.List(ctx, actor1)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		enabledAdmins := 0
		for _, u := range roster {
			if !u.Disabled && u.Role.Can(user.PermAdminister) {
				enabledAdmins++
			}
		}
		if enabledAdmins == 0 {
			t.Fatalf("iteration %d: both demotions succeeded and the tenant has no enabled admin (errors %v / %v)", iteration, first, second)
		}
		if first == nil && second == nil {
			t.Fatalf("iteration %d: both demotions reported success; one must be refused", iteration)
		}
	}
}

// TestConcurrentDisableAndDemoteCannotStrandATenant is the same race across the two mutations that
// share the guard, which is the shape a real deployment is likelier to hit than two demotions.
func TestConcurrentDisableAndDemoteCannotStrandATenant(t *testing.T) {
	for iteration := 0; iteration < 200; iteration++ {
		svc, _ := newAuditedSvc(t)
		ctx := context.Background()
		a1, _, actor1 := seedAdmin(t, svc, "acme", "Admin One")
		a2, _, actor2 := seedAdmin(t, svc, "acme", "Admin Two")

		start := make(chan struct{})
		errs := make(chan error, 2)
		go func() {
			<-start
			_, err := svc.SetDisabled(ctx, actor1, a2.ID, true)
			errs <- err
		}()
		go func() {
			<-start
			_, err := svc.Update(ctx, actor2, a1.ID, "", user.RoleReadOnly)
			errs <- err
		}()
		close(start)
		first, second := <-errs, <-errs

		roster, err := svc.List(ctx, actor1)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		enabledAdmins := 0
		for _, u := range roster {
			if !u.Disabled && u.Role.Can(user.PermAdminister) {
				enabledAdmins++
			}
		}
		if enabledAdmins == 0 {
			t.Fatalf("iteration %d: the tenant has no enabled admin (errors %v / %v)", iteration, first, second)
		}
	}
}

// TestRotationDoesNotRevertAConcurrentDisable pins the read-modify-write in key rotation.
//
// Update writes the whole aggregate, so rotation that reads the user outside the guard can carry a
// stale disabled flag or role back over a change another caller committed in between. Reading the
// user from the locked roster closes the window: a revoked account must stay revoked after somebody
// rotates its key.
func TestRotationDoesNotRevertAConcurrentDisable(t *testing.T) {
	for iteration := 0; iteration < 200; iteration++ {
		svc, _ := newAuditedSvc(t)
		ctx := context.Background()
		_, _, admin := seedAdmin(t, svc, "acme", "Admin")
		target, _, err := svc.CreateUser(ctx, admin, "", "Member", user.RoleMember)
		if err != nil {
			t.Fatalf("seed member: %v", err)
		}

		start := make(chan struct{})
		done := make(chan struct{}, 2)
		go func() {
			<-start
			_, _ = svc.SetDisabled(ctx, admin, target.ID, true)
			done <- struct{}{}
		}()
		go func() {
			<-start
			_, _, _ = svc.RotateAPIKey(ctx, admin, target.ID)
			done <- struct{}{}
		}()
		close(start)
		<-done
		<-done

		roster, err := svc.List(ctx, admin)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, u := range roster {
			if u.ID == target.ID && !u.Disabled {
				t.Fatalf("iteration %d: the disable was reverted by a concurrent rotation", iteration)
			}
		}
	}
}
