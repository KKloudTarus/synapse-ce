// Package postgres provides PostgreSQL-backed repositories (pgx/v5) and applies
// migrations via goose. Used when SYNAPSE_DB_DSN is set; otherwise the server
// falls back to in-memory persistence for dev.
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"hash/fnv"
	"io/fs"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver for goose
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
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

// PoolStatsSource exposes aggregate pool saturation through a driver-free port so the
// metrics adapter never depends on pgx.
type PoolStatsSource struct{ pool *pgxpool.Pool }

var _ ports.PoolStatsReader = (*PoolStatsSource)(nil)

// NewPoolStatsSource returns nil for a nil pool so a composition root can pass the result
// straight to an optional collector without constructing a typed-nil interface.
func NewPoolStatsSource(pool *pgxpool.Pool) *PoolStatsSource {
	if pool == nil {
		return nil
	}
	return &PoolStatsSource{pool: pool}
}

// PoolStats snapshots the pool's aggregate counters; it carries no connection identity.
func (s *PoolStatsSource) PoolStats() ports.PoolStats {
	stats := s.pool.Stat()
	return ports.PoolStats{
		AcquiredConns:        stats.AcquiredConns(),
		ConstructingConns:    stats.ConstructingConns(),
		IdleConns:            stats.IdleConns(),
		MaxConns:             stats.MaxConns(),
		TotalConns:           stats.TotalConns(),
		AcquireCount:         stats.AcquireCount(),
		CanceledAcquireCount: stats.CanceledAcquireCount(),
		EmptyAcquireCount:    stats.EmptyAcquireCount(),
		NewConnsCount:        stats.NewConnsCount(),
		MaxIdleDestroyCount:  stats.MaxIdleDestroyCount(),
		MaxLifetimeDestroy:   stats.MaxLifetimeDestroyCount(),
		AcquireDuration:      stats.AcquireDuration(),
		EmptyAcquireWaitTime: stats.EmptyAcquireWaitTime(),
	}
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

func migrationLockKey() int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("synapse:migration"))
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
	return migrate(ctx, db)
}

// MigrateLocked applies the embedded migration set while holding a database-wide advisory lock.
// The lock and goose share the pool's sole connection, so the session lock is held for the
// complete migration run. Acquisition blocks until the caller's context expires.
func MigrateLocked(ctx context.Context, dsn string) error {
	db, err := sql.Open("pgx", dsnForMigrate(dsn))
	if err != nil {
		return fmt.Errorf("migrate open: %w", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if _, err := db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey()); err != nil {
		return fmt.Errorf("acquire migration advisory lock: %w", err)
	}
	defer func() {
		// A network failure during cleanup must not turn a bounded migration startup
		// into an unbounded shutdown hang. Closing the sole connection also releases
		// the session lock if this best-effort unlock cannot complete.
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = db.ExecContext(releaseCtx, "SELECT pg_advisory_unlock($1)", migrationLockKey())
	}()
	return migrate(ctx, db)
}

func migrate(ctx context.Context, db *sql.DB) error {
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

type migrationReadinessQueryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func checkMigrationsReady(ctx context.Context, queryer migrationReadinessQueryer) error {
	expected, err := embeddedMigrationVersions()
	if err != nil {
		return err
	}
	rows, err := queryer.Query(ctx, `SELECT version_id, is_applied
		FROM (
			SELECT DISTINCT ON (version_id) version_id, is_applied
			FROM goose_db_version
			WHERE version_id > 0
			ORDER BY version_id, id DESC
		) AS latest
		ORDER BY version_id`)
	if err != nil {
		return fmt.Errorf("migration readiness query: %w", err)
	}
	defer rows.Close()

	actual := make([]migrationState, 0, len(expected))
	for rows.Next() {
		var state migrationState
		if err := rows.Scan(&state.version, &state.applied); err != nil {
			return fmt.Errorf("migration readiness scan: %w", err)
		}
		actual = append(actual, state)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("migration readiness rows: %w", err)
	}
	return compareMigrationStates(expected, actual)
}

type migrationState struct {
	version int64
	applied bool
}

func embeddedMigrationVersions() ([]int64, error) {
	return migrationVersions(migrations.FS)
}

func migrationVersions(source fs.FS) ([]int64, error) {
	entries, err := fs.ReadDir(source, ".")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}

	versions := make([]int64, 0, len(entries))
	seen := make(map[int64]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			return nil, fmt.Errorf("embedded migration %q has an invalid filename", entry.Name())
		}
		version, err := goose.NumericComponent(entry.Name())
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("embedded migration %q has invalid version %q", entry.Name(), prefix)
		}
		if previous, duplicate := seen[version]; duplicate {
			return nil, fmt.Errorf("embedded migrations %q and %q use duplicate version %d", previous, entry.Name(), version)
		}
		seen[version] = entry.Name()
		versions = append(versions, version)
	}
	if len(versions) == 0 {
		return nil, fmt.Errorf("no embedded SQL migrations found")
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	return versions, nil
}

func compareMigrationStates(expected []int64, actual []migrationState) error {
	if len(expected) == 0 {
		return fmt.Errorf("migration readiness: no embedded migrations expected")
	}

	want := make(map[int64]struct{}, len(expected))
	latestExpected := expected[0]
	for _, version := range expected {
		if _, duplicate := want[version]; duplicate {
			return fmt.Errorf("migration readiness: duplicate embedded migration %d", version)
		}
		want[version] = struct{}{}
		if version > latestExpected {
			latestExpected = version
		}
	}
	got := make(map[int64]bool, len(actual))
	for _, state := range actual {
		if _, duplicate := got[state.version]; duplicate {
			return fmt.Errorf("migration readiness: duplicate latest state for version %d", state.version)
		}
		got[state.version] = state.applied
	}
	for _, version := range expected {
		applied, ok := got[version]
		if !ok {
			return fmt.Errorf("migration readiness: embedded migration %d is missing", version)
		}
		if !applied {
			return fmt.Errorf("migration readiness: embedded migration %d is not applied", version)
		}
	}
	for version, applied := range got {
		if _, ok := want[version]; ok {
			continue
		}
		if version <= latestExpected {
			return fmt.Errorf("migration readiness: database contains divergent migration %d", version)
		}
		if !applied {
			return fmt.Errorf("migration readiness: newer migration %d is not applied", version)
		}
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
