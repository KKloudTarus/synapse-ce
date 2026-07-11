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

	u, key, err := svc.CreateUser(ctx, "operator", "", "Alice", user.RoleMember)
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

	u, key, err := svc.CreateUser(ctx, "operator", "acme", "Alice", user.RoleMember)
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
	a, ka, _ := svc.CreateUser(ctx, "operator", "", "Alice", user.RoleMember)
	b, kb, _ := svc.CreateUser(ctx, "operator", "", "Bob", user.RoleMember)
	ua, _ := svc.Authenticate(ctx, ka)
	ub, _ := svc.Authenticate(ctx, kb)
	if ua.ID == ub.ID || ua.ID != a.ID || ub.ID != b.ID {
		t.Fatalf("consultants must resolve to distinct ids: %s vs %s", ua.ID, ub.ID)
	}
}
