package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	usersuc "github.com/KKloudTarus/synapse-ce/internal/usecase/users"
)

// faultyAudit writes through the real audit log (so a successful record joins the tenant
// transaction) and fails every record while fail is set.
type faultyAudit struct {
	inner ports.AuditLogger
	fail  atomic.Bool
}

func (a *faultyAudit) Record(ctx context.Context, e ports.AuditEntry) error {
	if a.fail.Load() {
		return errors.New("audit sink unavailable")
	}
	return a.inner.Record(ctx, e)
}

type pgClock struct{}

func (pgClock) Now() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

type pgIDs struct {
	prefix string
	n      atomic.Int64
}

func (g *pgIDs) NewID() shared.ID { return shared.ID(fmt.Sprintf("%s-%d", g.prefix, g.n.Add(1))) }

// A consequential users mutation and its audit record commit or roll back together in PostgreSQL:
// with the audit failing, disable leaves the user enabled with its key and sessions intact,
// rotation leaves the old key working, and the link command leaves no link.
func TestPostgresUserMutationsRollBackOnAuditFailure(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("SYNAPSE_TEST_DB_DSN not set – skipping Postgres integration test")
	}
	ctx := context.Background()
	if err := postgres.MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := postgres.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenant := shared.ID("audit-rollback-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id, name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, tenant.String()); err != nil {
		t.Fatal(err)
	}
	repo := postgres.NewUserRepository(pool)
	identities, err := postgres.NewIdentityStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	audit := &faultyAudit{inner: postgres.NewAuditLog(pool)}
	svc, err := usersuc.NewService(repo, audit, pgClock{}, &pgIDs{prefix: "u-" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTransactionRunner(postgres.NewTenantTransactionRunner(pool))
	svc.SetIdentityStore(identities)
	if err := svc.SetOIDCLinking("https://issuer.example", tenant); err != nil {
		t.Fatal(err)
	}
	admin, _, err := svc.CreateUser(ctx, usersuc.Actor{ID: usersuc.BootstrapID}, tenant.String(), "Admin", user.RoleAdmin)
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	actor := usersuc.Actor{ID: admin.ID.String(), TenantID: tenant.String()}
	target, key, err := svc.CreateUser(ctx, actor, "", "Alice", user.RoleMember)
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	now := pgClock{}.Now()
	session, err := identity.NewSession(shared.ID("s-"+suffix), tenant, target.ID, "tok-"+suffix, "csrf-"+suffix, nil, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := identities.CreateSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	sessionActive := func() bool {
		got, err := identities.GetSessionByTokenHash(shared.WithTenant(ctx, tenant), session.TokenHash)
		if err != nil {
			t.Fatal(err)
		}
		return got.Active(pgClock{}.Now())
	}

	audit.fail.Store(true)
	if _, err := svc.SetDisabled(ctx, actor, target.ID, true); err == nil {
		t.Fatal("disable succeeded although its audit failed")
	}
	stored, err := repo.GetByID(ctx, tenant, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Disabled || stored.APIKeyHash != usersuc.HashToken(key) {
		t.Fatalf("a failed disable changed the user: disabled=%v keyChanged=%v", stored.Disabled, stored.APIKeyHash != usersuc.HashToken(key))
	}
	if !sessionActive() {
		t.Fatal("a failed disable revoked the session")
	}
	if _, _, err := svc.RotateAPIKey(ctx, actor, target.ID); err == nil {
		t.Fatal("rotation succeeded although its audit failed")
	}
	if _, err := svc.Authenticate(ctx, key); err != nil {
		t.Fatalf("a failed rotation revoked the old key: %v", err)
	}
	if _, err := svc.LinkOIDCIdentity(ctx, actor, target.ID, "https://issuer.example", "sub-"+suffix); err == nil {
		t.Fatal("link succeeded although its audit failed")
	}
	if _, err := identities.GetExternalIdentity(shared.WithTenant(ctx, tenant), "https://issuer.example", "sub-"+suffix); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("a failed link left a row: %v", err)
	}

	audit.fail.Store(false)
	if _, err := svc.LinkOIDCIdentity(ctx, actor, target.ID, "https://issuer.example", "sub-"+suffix); err != nil {
		t.Fatalf("link: %v", err)
	}
	if _, err := svc.SetDisabled(ctx, actor, target.ID, true); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if sessionActive() {
		t.Fatal("disable did not revoke the session")
	}
	if _, err := svc.SetDisabled(ctx, actor, target.ID, false); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if sessionActive() {
		t.Fatal("re-enable restored the session")
	}
	if _, err := svc.Authenticate(ctx, key); !errors.Is(err, authz.ErrCredentialInvalid) {
		t.Fatalf("re-enable restored the key: %v", err)
	}
	links, err := identities.ListExternalIdentities(ctx, tenant, target.ID)
	if err != nil || len(links) != 1 {
		t.Fatalf("links = %+v, %v", links, err)
	}
}

// Unlinking an OIDC identity in PostgreSQL removes the link, revokes the user's sessions and writes
// its audit record as one tenant transaction: with the audit failing, the link and the session
// survive; once it succeeds, both are gone, and the link id is confined to its own user.
func TestPostgresIdentityStoreUnlinkRollsBackOnAuditFailure(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("SYNAPSE_TEST_DB_DSN not set – skipping Postgres integration test")
	}
	ctx := context.Background()
	if err := postgres.MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := postgres.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenant := shared.ID("unlink-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id, name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, tenant.String()); err != nil {
		t.Fatal(err)
	}
	identities, err := postgres.NewIdentityStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	audit := &faultyAudit{inner: postgres.NewAuditLog(pool)}
	svc, err := usersuc.NewService(postgres.NewUserRepository(pool), audit, pgClock{}, &pgIDs{prefix: "ul-" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTransactionRunner(postgres.NewTenantTransactionRunner(pool))
	svc.SetIdentityStore(identities)
	if err := svc.SetOIDCLinking("https://issuer.example", tenant); err != nil {
		t.Fatal(err)
	}
	admin, _, err := svc.CreateUser(ctx, usersuc.Actor{ID: usersuc.BootstrapID}, tenant.String(), "Admin", user.RoleAdmin)
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	actor := usersuc.Actor{ID: admin.ID.String(), TenantID: tenant.String()}
	target, _, err := svc.CreateUser(ctx, actor, "", "Alice", user.RoleMember)
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	other, _, err := svc.CreateUser(ctx, actor, "", "Bob", user.RoleMember)
	if err != nil {
		t.Fatalf("create other: %v", err)
	}
	subject := "sub-unlink-" + suffix
	link, err := svc.LinkOIDCIdentity(ctx, actor, target.ID, "https://issuer.example", subject)
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	now := pgClock{}.Now()
	session, err := identity.NewSession(shared.ID("su-"+suffix), tenant, target.ID, "tok-u-"+suffix, "csrf-u-"+suffix, nil, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := identities.CreateSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	sessionActive := func() bool {
		got, err := identities.GetSessionByTokenHash(shared.WithTenant(ctx, tenant), session.TokenHash)
		if err != nil {
			t.Fatal(err)
		}
		return got.Active(pgClock{}.Now())
	}
	linked := func() bool {
		_, err := identities.GetExternalIdentity(shared.WithTenant(ctx, tenant), "https://issuer.example", subject)
		if err != nil && !errors.Is(err, shared.ErrNotFound) {
			t.Fatal(err)
		}
		return err == nil
	}

	if _, err := svc.UnlinkOIDCIdentity(ctx, actor, other.ID, link.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unlinking through another user: want ErrNotFound, got %v", err)
	}
	if !linked() {
		t.Fatal("unlinking through another user removed the link")
	}
	audit.fail.Store(true)
	if _, err := svc.UnlinkOIDCIdentity(ctx, actor, target.ID, link.ID); err == nil {
		t.Fatal("unlink succeeded although its audit failed")
	}
	if !linked() || !sessionActive() {
		t.Fatalf("a failed unlink changed state: linked=%v sessionActive=%v", linked(), sessionActive())
	}
	audit.fail.Store(false)
	removed, err := svc.UnlinkOIDCIdentity(ctx, actor, target.ID, link.ID)
	if err != nil || removed.ID != link.ID || removed.Subject != subject {
		t.Fatalf("unlink = %+v, %v", removed, err)
	}
	if linked() || sessionActive() {
		t.Fatalf("unlink left state behind: linked=%v sessionActive=%v", linked(), sessionActive())
	}
	if _, err := svc.UnlinkOIDCIdentity(ctx, actor, target.ID, link.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("repeated unlink: want ErrNotFound, got %v", err)
	}
}
