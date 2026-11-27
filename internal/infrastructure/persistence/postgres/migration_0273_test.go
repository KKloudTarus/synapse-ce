package postgres_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/audit"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestMigration0273AuditStoresTheSchemeItHashedWith pins the write path: the row the audit log
// appends names the scheme it was hashed with, and its stored hash is that scheme's hash of its
// stored content.
func TestMigration0273AuditStoresTheSchemeItHashedWith(t *testing.T) {
	pool := auditTxTestPool(t)
	ctx := shared.WithTenant(context.Background(), "default")
	target := "hash-scheme-write-" + time.Now().UTC().Format("150405.000000000")
	cleanupAuditRows(t, pool, target)

	meta := map[string]string{"a=b": "c"}
	if err := postgres.NewAuditLog(pool).Record(ctx, ports.AuditEntry{Actor: "ada", Action: "hash.scheme.write", Target: target, Metadata: meta, At: time.Now().UTC()}); err != nil {
		t.Fatalf("record: %v", err)
	}
	var (
		scheme         int
		hash, previous string
		actor, action  string
		rawMeta        []byte
		at             time.Time
	)
	if err := pool.QueryRow(ctx, `SELECT hash_scheme, hash, COALESCE(previous_hash,''), actor, action, metadata, created_at
		FROM audit_log WHERE target=$1`, target).Scan(&scheme, &hash, &previous, &actor, &action, &rawMeta, &at); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if scheme != audit.CurrentHashScheme {
		t.Fatalf("stored hash_scheme = %d, want %d", scheme, audit.CurrentHashScheme)
	}
	var stored map[string]string
	if err := json.Unmarshal(rawMeta, &stored); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if want := audit.ComputeHash(scheme, previous, actor, action, target, stored, at); hash != want {
		t.Fatalf("stored hash is not the scheme %d hash of the stored row", scheme)
	}
}

// TestMigration0273VerifyGlobalReadsEachRowsScheme seeds one tenant chain the way an upgraded
// database holds it: a row written before the migration (scheme 1, legacy hash) followed by a
// row written after it (scheme 2, framed hash). The chain must verify, and a row whose stored scheme
// disagrees with how its hash was made must be named as the break.
func TestMigration0273VerifyGlobalReadsEachRowsScheme(t *testing.T) {
	pool := auditTxTestPool(t)
	ctx := context.Background()
	stamp := time.Now().UTC().Format("150405.000000000")
	at := time.Now().UTC().Truncate(time.Microsecond)

	seed := func(t *testing.T, tenant shared.ID, secondScheme int, secondHashedAs int) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, tenant.String()); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		target := "hash-scheme-" + tenant.String()
		cleanupAuditRows(t, pool, target)
		first := audit.ComputeHash(audit.HashSchemeLegacy, "", "op", "before", target, nil, at)
		if _, err := pool.Exec(ctx, `INSERT INTO audit_log (tenant_id, actor, action, target, metadata, created_at, hash, previous_hash, hash_version, hash_scheme)
			VALUES ($1,'op','before',$2,'{}',$3,$4,'',2,1)`, tenant.String(), target, at, first); err != nil {
			t.Fatalf("seed legacy row: %v", err)
		}
		second := audit.ComputeHash(secondHashedAs, first, "op", "after", target, nil, at)
		if _, err := pool.Exec(ctx, `INSERT INTO audit_log (tenant_id, actor, action, target, metadata, created_at, hash, previous_hash, hash_version, hash_scheme)
			VALUES ($1,'op','after',$2,'{}',$3,$4,$5,2,$6)`, tenant.String(), target, at, second, first, secondScheme); err != nil {
			t.Fatalf("seed framed row: %v", err)
		}
	}

	// The report names at most eight broken chains, sorted. The suite's database is shared and
	// append-only, so other tests leave broken chains behind; ids starting "0000-" sort these two
	// ahead of every other tenant chain, so neither assertion can pass because the list was cut.
	healthy := shared.ID("0000-hash-scheme-ok-" + stamp)
	seed(t, healthy, audit.HashSchemeFramed, audit.HashSchemeFramed)
	mislabelled := shared.ID("0000-hash-scheme-bad-" + stamp)
	seed(t, mislabelled, audit.HashSchemeFramed, audit.HashSchemeLegacy)

	report, err := postgres.NewAuditLog(pool).VerifyGlobal(ctx)
	if err != nil {
		t.Fatalf("verify global: %v", err)
	}
	// The suite's database is shared and append-only, so other tests may leave their own chains
	// broken. What this test owns is that its healthy chain is not named and its broken one is.
	if strings.Contains(report.Error, "tenant "+healthy.String()+":") {
		t.Fatalf("a chain mixing legacy and framed rows was reported broken: %s", report.Error)
	}
	if !strings.Contains(report.Error, "tenant "+mislabelled.String()+":") {
		t.Fatalf("a row whose scheme disagrees with its hash was not named: %q", report.Error)
	}
}

// TestMigration0273VerifyGlobalRefusesAFilteredRead pins the false pass #1703 describes. audit_log
// forces RLS, and a role that cannot bypass it reads zero rows with no tenant bound. Zero rows verify
// as intact. VerifyGlobal must refuse instead of reporting that.
func TestMigration0273VerifyGlobalRefusesAFilteredRead(t *testing.T) {
	pool := auditTxTestPool(t)
	ctx := context.Background()
	target := "hash-scheme-filtered-" + time.Now().UTC().Format("150405.000000000")
	cleanupAuditRows(t, pool, target)
	// At least one row exists, so a filtered read genuinely hides something.
	if err := postgres.NewAuditLog(pool).Record(shared.WithTenant(ctx, "default"), ports.AuditEntry{Actor: "op", Action: "hash.scheme.filtered", Target: target, At: time.Now().UTC()}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const role = "audit_global_probe_role"
	for _, stmt := range []string{
		`DROP OWNED BY ` + role,
		`DROP ROLE IF EXISTS ` + role,
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		// SELECT is granted so the only thing that can stop the read is row-level security.
		`GRANT SELECT ON audit_log, evidence TO ` + role,
	} {
		_, _ = pool.Exec(ctx, stmt)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DROP OWNED BY `+role)
		_, _ = pool.Exec(bg, `DROP ROLE IF EXISTS `+role)
	})

	cfg, err := pgxpool.ParseConfig(os.Getenv("SYNAPSE_TEST_DB_DSN"))
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SET ROLE `+role)
		return err
	}
	restricted, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("restricted pool: %v", err)
	}
	t.Cleanup(restricted.Close)

	report, err := postgres.NewAuditLog(restricted).VerifyGlobal(ctx)
	if err == nil {
		t.Fatalf("a role that cannot see every row produced a report: %+v", report)
	}
	if !strings.Contains(err.Error(), "row-level security") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestMigration0273EvidenceRoundTripsItsScheme pins that the evidence store persists the scheme a
// link was sealed with and returns it, so a chain read back verifies; and that a link stored before
// the migration reads back as legacy and still verifies beside it.
func TestMigration0273EvidenceRoundTripsItsScheme(t *testing.T) {
	pool := auditTxTestPool(t)
	ctx := shared.WithTenant(context.Background(), "default")
	eng := "eng-hash-scheme-" + time.Now().UTC().Format("150405.000000000")
	if _, err := pool.Exec(ctx, `INSERT INTO engagements (id, tenant_id, name) VALUES ($1, 'default', 'test') ON CONFLICT (id) DO NOTHING`, eng); err != nil {
		t.Fatalf("seed engagement: %v", err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)

	// A pre-migration link: legacy hash, scheme 1.
	legacy := evidence.Evidence{ID: shared.ID(eng + "-a"), EngagementID: shared.ID(eng), Kind: "scan", Content: []byte("one"), CreatedBy: "op", CreatedAt: at}
	legacy.Hash = evidence.ComputeHash(legacy)
	if _, err := pool.Exec(ctx, `INSERT INTO evidence (id, tenant_id, engagement_id, kind, sha256, previous_hash, storage_ref, content, created_by, created_at, hash_scheme)
		VALUES ($1,'default',$2,'scan',$3,'','',$4,'op',$5,1)`, legacy.ID.String(), eng, legacy.Hash, legacy.Content, at); err != nil {
		t.Fatalf("seed legacy link: %v", err)
	}

	store := postgres.NewEvidenceStore(pool)
	sealed := evidence.Evidence{ID: shared.ID(eng + "-b"), EngagementID: shared.ID(eng), Kind: "finding", Content: []byte("two"), PreviousHash: legacy.Hash, CreatedBy: "op", CreatedAt: at}.Seal()
	if err := store.Append(ctx, []evidence.Evidence{sealed}); err != nil {
		t.Fatalf("append sealed: %v", err)
	}
	// A framed link, as writers seal it since #1703, must persist and read back framed.
	framed := evidence.Evidence{ID: shared.ID(eng + "-c"), EngagementID: shared.ID(eng), Kind: "finding", Content: []byte("three"), PreviousHash: sealed.Hash, CreatedBy: "op", CreatedAt: at, HashScheme: evidence.HashSchemeFramed}
	framed.Hash = evidence.ComputeHash(framed)
	if err := store.Append(ctx, []evidence.Evidence{framed}); err != nil {
		t.Fatalf("append framed: %v", err)
	}

	items, err := store.ListByEngagement(ctx, shared.ID(eng))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("listed %d links, want 3", len(items))
	}
	if items[0].HashScheme != evidence.HashSchemeLegacy || items[1].HashScheme != evidence.CurrentHashScheme || items[2].HashScheme != evidence.HashSchemeFramed {
		t.Fatalf("schemes read back as %d, %d, %d; want legacy, current, framed", items[0].HashScheme, items[1].HashScheme, items[2].HashScheme)
	}
	if err := evidence.VerifyChain(items); err != nil {
		t.Fatalf("a chain spanning the migration does not verify: %v", err)
	}
	one, found, err := store.LookupSealedByID(ctx, shared.ID(eng), framed.ID)
	if err != nil || !found || one.HashScheme != evidence.HashSchemeFramed {
		t.Fatalf("lookup by id lost the scheme: found=%v scheme=%d err=%v", found, one.HashScheme, err)
	}
}

// TestMigration0274ValidatesTheHashSchemeChecks pins that the checks 0273 adds NOT VALID end up
// validated, and that they refuse a scheme no reader knows.
func TestMigration0274ValidatesTheHashSchemeChecks(t *testing.T) {
	pool := auditTxTestPool(t)
	ctx := context.Background()
	for _, name := range []string{"audit_log_hash_scheme_check", "evidence_hash_scheme_check"} {
		var validated bool
		if err := pool.QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conname=$1`, name).Scan(&validated); err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !validated {
			t.Fatalf("%s is still NOT VALID after migrating", name)
		}
	}
	target := "hash-scheme-check-" + time.Now().UTC().Format("150405.000000000")
	cleanupAuditRows(t, pool, target)
	_, err := pool.Exec(ctx, `INSERT INTO audit_log (tenant_id, actor, action, target, metadata, created_at, hash, previous_hash, hash_scheme)
		VALUES ('', 'op', 'x', $1, '{}', now(), 'h', NULL, 3)`, target)
	if err == nil || !strings.Contains(err.Error(), "audit_log_hash_scheme_check") {
		t.Fatalf("a row with an unknown scheme was stored: %v", err)
	}
}
