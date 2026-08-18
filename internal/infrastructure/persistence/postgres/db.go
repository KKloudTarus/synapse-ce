// Package postgres provides PostgreSQL-backed repositories (pgx/v5) and applies
// migrations via goose. Used when SYNAPSE_DB_DSN is set; otherwise the server
// falls back to in-memory persistence for dev.
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"hash/fnv"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver for goose
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

// PoolConfig sizes the pgx connection pool. Zero values get sane defaults. Sizing the pool
// explicitly (the default pgx cap is max(4, NumCPU) ≈ 8) is required now that the durable
// agent path holds a connection-bearing advisory lock per active run – an unsized pool would
// starve HTTP handlers at low-tens concurrency.
type PoolConfig struct {
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
}

func (c *PoolConfig) withDefaults() {
	if c.MaxConns <= 0 {
		c.MaxConns = 32
	}
	if c.MaxConnLifetime <= 0 {
		c.MaxConnLifetime = time.Hour
	}
	if c.MaxConnIdleTime <= 0 {
		c.MaxConnIdleTime = 30 * time.Minute
	}
	if c.HealthCheckPeriod <= 0 {
		c.HealthCheckPeriod = time.Minute
	}
}

// buildPoolConfig parses the DSN and applies sizing. Extracted (and not connecting) so the
// override logic is unit-testable without a database. An explicit DSN `pool_max_conns` always
// wins (operator override); the configured default applies only when the DSN did not set it.
func buildPoolConfig(dsn string, pc PoolConfig) (*pgxpool.Config, error) {
	pc.withDefaults()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres parse dsn: %w", err)
	}
	if !strings.Contains(dsn, "pool_max_conns") {
		cfg.MaxConns = pc.MaxConns
	}
	cfg.MinConns = pc.MinConns
	cfg.MaxConnLifetime = pc.MaxConnLifetime
	cfg.MaxConnIdleTime = pc.MaxConnIdleTime
	cfg.HealthCheckPeriod = pc.HealthCheckPeriod
	return cfg, nil
}

// ConnectPool opens a sized pgx pool and verifies connectivity.
func ConnectPool(ctx context.Context, dsn string, pc PoolConfig) (*pgxpool.Pool, error) {
	cfg, err := buildPoolConfig(dsn, pc)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres ping: %w", err)
	}
	return pool, nil
}

// Connect opens a pgx pool with default sizing (back-compat wrapper).
func Connect(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	return ConnectPool(ctx, dsn, PoolConfig{})
}

// singletonLockKey derives a stable advisory-lock key PER ROLE. Scoping by
// role lets one synapse-api AND one synapse-worker run together (each a singleton in its
// own role) while still refusing a second instance of the SAME role – the multi-process
// model the worker era needs, instead of a single global lock that would block the worker.
func singletonLockKey(role string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("synapse:singleton:" + role))
	return int64(h.Sum64())
}

// AcquireSingletonLock takes a session-level advisory lock (keyed by role) on a DEDICATED
// connection the caller holds for the whole process lifetime – releasing it drops the
// lock. A second instance OF THE SAME ROLE gets ok=false so it can fail fast (the repos
// still ignore tenant_id, so two same-role writers would race). Returns the held
// connection (retain it; Release at shutdown), whether the lock was obtained, and any error.
func AcquireSingletonLock(ctx context.Context, pool *pgxpool.Pool, role string) (*pgxpool.Conn, bool, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("acquire lock connection: %w", err)
	}
	var ok bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", singletonLockKey(role)).Scan(&ok); err != nil {
		conn.Release()
		return nil, false, fmt.Errorf("advisory lock: %w", err)
	}
	if !ok {
		conn.Release() // another instance of this role holds it
		return nil, false, nil
	}
	return conn, true, nil
}

// dsnForMigrate strips pgxpool-only query params (pool_*) from a DSN. ConnectPool (pgxpool)
// understands pool_max_conns etc., but goose migrates over database/sql via the pgx stdlib
// driver, whose pgconn.ParseConfig REJECTS those params ("unrecognized configuration
// parameter pool_max_conns"). Stripping them lets an operator set pool sizing in the DSN –
// the documented PR0 override – without breaking migrations at boot.
func dsnForMigrate(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		// keyword-form (or unparseable): best-effort field filter.
		if !strings.Contains(dsn, "pool_") {
			return dsn
		}
		fields := strings.Fields(dsn)
		kept := fields[:0]
		for _, f := range fields {
			if !strings.HasPrefix(f, "pool_") {
				kept = append(kept, f)
			}
		}
		return strings.Join(kept, " ")
	}
	q := u.Query()
	for k := range q {
		if strings.HasPrefix(k, "pool_") {
			q.Del(k)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Migrate applies all pending goose migrations (idempotent; tracked in goose_db_version).
func Migrate(ctx context.Context, dsn string) error {
	db, err := sql.Open("pgx", dsnForMigrate(dsn))
	if err != nil {
		return fmt.Errorf("migrate open: %w", err)
	}
	defer func() { _ = db.Close() }()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("migrate dialect: %w", err)
	}
	if err := goose.UpContext(ctx, db, "."); err != nil {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

// CheckDatabaseReady verifies the runtime pool can execute a trivial query.
func CheckDatabaseReady(ctx context.Context, pool *pgxpool.Pool) error {
	return checkDatabaseReady(ctx, pool)
}

type readinessQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func checkDatabaseReady(ctx context.Context, queryer readinessQueryer) error {
	var one int
	if err := queryer.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		return fmt.Errorf("database readiness: %w", err)
	}
	if one != 1 {
		return fmt.Errorf("database readiness returned %d", one)
	}
	return nil
}

// CheckMigrationsReady verifies the latest state of every embedded migration is applied. Goose
// retains down records, so the query considers only the newest row for each migration version.
func CheckMigrationsReady(ctx context.Context, pool *pgxpool.Pool) error {
	return checkMigrationsReady(ctx, pool)
}

func checkMigrationsReady(ctx context.Context, queryer readinessQueryer) error {
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		return fmt.Errorf("read embedded migrations: %w", err)
	}
	expected := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			expected++
		}
	}

	var applied int
	err = queryer.QueryRow(ctx, `
		SELECT count(*)
		FROM (
			SELECT DISTINCT ON (version_id) version_id, is_applied
			FROM goose_db_version
			WHERE version_id > 0
			ORDER BY version_id, id DESC
		) AS latest
		WHERE is_applied`).Scan(&applied)
	if err != nil {
		return fmt.Errorf("migration readiness: %w", err)
	}
	if applied != expected {
		return fmt.Errorf("migration readiness: %d of %d embedded migrations applied", applied, expected)
	}
	return nil
}

// ValidateMigrationRoleSeparation ensures migrations cannot run as the runtime role.
func ValidateMigrationRoleSeparation(migrationDSN, runtimeDSN string) error {
	migrationConfig, err := pgxpool.ParseConfig(migrationDSN)
	if err != nil {
		return fmt.Errorf("parse migration dsn: %w", err)
	}
	if migrationConfig.ConnConfig.User == "" {
		return fmt.Errorf("migration dsn has no user")
	}
	runtimeConfig, err := pgxpool.ParseConfig(runtimeDSN)
	if err != nil {
		return fmt.Errorf("parse runtime dsn: %w", err)
	}
	if runtimeConfig.ConnConfig.User == "" {
		return fmt.Errorf("runtime dsn has no user")
	}
	if migrationConfig.ConnConfig.User == runtimeConfig.ConnConfig.User {
		return fmt.Errorf("migration and runtime DSNs must use distinct database users")
	}
	return nil
}

func quoteIdentifier(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}

// GrantRuntimePrivileges grants the runtime role the DML privileges required by the
// application after migrations have completed under the separate owner credential.
func GrantRuntimePrivileges(ctx context.Context, adminDSN, runtimeDSN string) error {
	runtimeConfig, err := pgxpool.ParseConfig(runtimeDSN)
	if err != nil {
		return fmt.Errorf("parse runtime dsn: %w", err)
	}
	role := runtimeConfig.ConnConfig.User
	if role == "" {
		return fmt.Errorf("runtime dsn has no user")
	}
	adminDB, err := sql.Open("pgx", dsnForMigrate(adminDSN))
	if err != nil {
		return fmt.Errorf("open admin dsn: %w", err)
	}
	defer func() { _ = adminDB.Close() }()

	quotedRole := `"` + strings.ReplaceAll(role, `"`, `""`) + `"`
	for _, statement := range []string{
		"REVOKE CREATE ON SCHEMA public FROM " + quotedRole,
		"REVOKE CREATE ON DATABASE " + quoteIdentifier(runtimeConfig.ConnConfig.Database) + " FROM " + quotedRole,
		"GRANT USAGE ON SCHEMA public TO " + quotedRole,
		"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO " + quotedRole,
		"GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO " + quotedRole,
	} {
		if _, err := adminDB.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("grant runtime privileges: %w", err)
		}
	}
	return nil
}
