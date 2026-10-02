package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// identityFixture is a fresh database migrated by a dedicated non-superuser owner, plus a separate
// NOSUPERUSER NOBYPASSRLS runtime role holding exactly the production runtime grants. Every
// isolation assertion runs on the runtime pool; the superuser admin pool is only for seeding and
// fault injection. The platform pool connects as the owner, the identity a platform operator uses
// for the owner-only person command.
type identityFixture struct {
	admin      *pgxpool.Pool
	runtime    *pgxpool.Pool
	owner      *pgxpool.Pool
	store      *IdentityFoundationStore
	platform   *IdentityFoundationStore
	platformTx *TenantTransactionRunner
	users      *UserRepository
	tx         *TenantTransactionRunner
	audit      *AuditLog
}

func newIdentityFixture(t *testing.T) *identityFixture {
	t.Helper()
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the identity foundation PostgreSQL tests")
	}
	ctx := context.Background()
	super, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	// The random suffix keeps role names unique in pg_authid even when two fixtures start within
	// one clock tick.
	name := fmt.Sprintf("identity_fnd_%d_%s", time.Now().UnixNano(), identityRandomHex(t, 4))
	owner, runtime := name+"_owner", name+"_runtime"
	password := identityRandomHex(t, 16)
	quote := func(v string) string { return pgx.Identifier{v}.Sanitize() }
	for _, role := range []string{owner, runtime} {
		if _, err := super.Exec(ctx, `CREATE ROLE `+quote(role)+` LOGIN PASSWORD '`+password+`' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := super.Exec(ctx, `CREATE DATABASE `+quote(name)+` OWNER `+quote(owner)); err != nil {
		t.Fatal(err)
	}
	f := &identityFixture{}
	t.Cleanup(func() {
		if f.runtime != nil {
			f.runtime.Close()
		}
		if f.owner != nil {
			f.owner.Close()
		}
		if f.admin != nil {
			f.admin.Close()
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := super.Exec(cleanup, `DROP DATABASE `+quote(name)+` WITH (FORCE)`); err != nil {
			t.Error(err)
		}
		for _, role := range []string{runtime, owner} {
			if _, err := super.Exec(cleanup, `DROP ROLE `+quote(role)); err != nil {
				t.Error(err)
			}
		}
		_ = super.Close(cleanup)
	})
	base, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	base.Path, base.RawPath = "/"+name, ""
	adminDSN := base.String()
	ownerURL, runtimeURL := *base, *base
	ownerURL.User = url.UserPassword(owner, password)
	runtimeURL.User = url.UserPassword(runtime, password)
	if err := Migrate(ctx, ownerURL.String()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := GrantRuntimePrivileges(ctx, adminDSN, runtimeURL.String()); err != nil {
		t.Fatalf("grant runtime privileges: %v", err)
	}
	if f.admin, err = pgxpool.New(ctx, adminDSN); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(runtimeURL.String())
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 12
	if f.runtime, err = pgxpool.NewWithConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := CheckRLSRuntimeRole(ctx, f.runtime); err != nil {
		t.Fatalf("runtime role cannot enforce RLS: %v", err)
	}
	if f.store, err = NewIdentityFoundationStore(f.runtime); err != nil {
		t.Fatal(err)
	}
	f.users, f.tx, f.audit = NewUserRepository(f.runtime), NewTenantTransactionRunner(f.runtime), NewAuditLog(f.runtime)
	if f.owner, err = pgxpool.New(ctx, ownerURL.String()); err != nil {
		t.Fatal(err)
	}
	if f.platform, err = NewIdentityFoundationStore(f.owner); err != nil {
		t.Fatal(err)
	}
	f.platformTx = NewTenantTransactionRunner(f.owner)
	return f
}

func identityRandomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func identityDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (f *identityFixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := f.admin.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("admin exec %q: %v", sql, err)
	}
}

func (f *identityFixture) tenants(t *testing.T, ids ...string) {
	t.Helper()
	for _, id := range ids {
		f.exec(t, `INSERT INTO tenants(id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`, id, "Org "+id)
	}
}

// seedUser inserts a legacy users row directly, as an older binary would have.
func (f *identityFixture) seedUser(t *testing.T, tenant, id string, role user.Role, hash string, disabled bool) {
	t.Helper()
	f.exec(t, `INSERT INTO users(id, name, role, api_key_hash, disabled, tenant_id) VALUES ($1,$2,$3,$4,$5,$6)`,
		id, "User "+id, string(role), hash, disabled, tenant)
}

// seedAudit appends a tenant audit record the way the users service does.
func (f *identityFixture) seedAudit(t *testing.T, tenant, action, target string, meta map[string]string) {
	t.Helper()
	if err := WithTenant(context.Background(), f.runtime, tenant, func(tx pgx.Tx) error {
		return appendTenantAudit(context.Background(), tx, tenant, ports.AuditEntry{Actor: "admin", Action: action, Target: target, Metadata: meta, At: time.Now().UTC()})
	}); err != nil {
		t.Fatal(err)
	}
}

// runtimeCount counts rows on the runtime pool inside tenant, so RLS applies.
func (f *identityFixture) runtimeCount(t *testing.T, tenant, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := WithTenant(context.Background(), f.runtime, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), sql, args...).Scan(&n)
	}); err != nil {
		t.Fatalf("runtime count %q: %v", sql, err)
	}
	return n
}

func (f *identityFixture) adminCount(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := f.admin.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("admin count %q: %v", sql, err)
	}
	return n
}

// enableProjection takes the tenant fence without running a batch, which turns on write-path
// projection exactly as the first backfill run does.
func (f *identityFixture) enableProjection(t *testing.T, tenant string, now time.Time) ports.IdentityBackfillRun {
	t.Helper()
	run, err := f.store.StartRun(context.Background(), shared.ID(tenant), shared.ID("run-"+identityRandomHex(t, 6)), "test", 100, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.FinishRun(context.Background(), run, nil, now); err != nil {
		t.Fatal(err)
	}
	return run
}

// declare moves a tenant through shadow to the declared cutover phase.
func (f *identityFixture) declare(t *testing.T, tenant string) {
	t.Helper()
	if err := WithTenant(context.Background(), f.runtime, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `INSERT INTO identity_policies(tenant_id, id, cutover_phase) VALUES ($1,'policy','shadow')`, tenant); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `UPDATE identity_policies SET cutover_phase='declared' WHERE tenant_id=$1`, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// createUser creates a user through the legacy write path inside a tenant transaction with its
// audit, as the users service does, and returns the raw key digest.
func (f *identityFixture) createUser(t *testing.T, tenant, id string, role user.Role, now time.Time) string {
	t.Helper()
	digest := identityDigest("key-" + id + identityRandomHex(t, 8))
	u, err := user.New(shared.ID(id), tenant, "User "+id, role, digest, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.tx.Run(context.Background(), shared.ID(tenant), func(ctx context.Context) error {
		if err := f.users.Create(ctx, u); err != nil {
			return err
		}
		return f.audit.Record(ctx, ports.AuditEntry{Actor: "admin", Action: "user.created", Target: id, At: now})
	}); err != nil {
		t.Fatal(err)
	}
	return digest
}

// updateUser applies mutate to the stored user through UserRepository.Update in one tenant
// transaction, optionally followed by an audit record.
func (f *identityFixture) updateUser(t *testing.T, tenant, id string, action string, mutate func(*user.User)) error {
	t.Helper()
	return f.tx.Run(context.Background(), shared.ID(tenant), func(ctx context.Context) error {
		u, err := f.users.GetByID(ctx, shared.ID(tenant), shared.ID(id))
		if err != nil {
			return err
		}
		mutate(u)
		if err := f.users.Update(ctx, shared.ID(tenant), u); err != nil {
			return err
		}
		if action == "" {
			return nil
		}
		return f.audit.Record(ctx, ports.AuditEntry{Actor: "admin", Action: action, Target: id, At: time.Now().UTC()})
	})
}
