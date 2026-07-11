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
