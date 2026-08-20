package postgres

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// credential-free DSN (parses without connecting; no secret).
const poolTestDSN = "postgres://localhost:5432/db?sslmode=disable"

// TestBuildPoolConfig_DefaultApplied: with no pool_max_conns in the DSN, the configured
// default is applied (the unsized-pool starvation fix).
func TestBuildPoolConfig_DefaultApplied(t *testing.T) {
	cfg, err := buildPoolConfig(poolTestDSN, PoolConfig{MaxConns: 32})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxConns != 32 {
		t.Fatalf("MaxConns = %d, want 32 (configured default)", cfg.MaxConns)
	}
}

// TestBuildPoolConfig_DSNOverrideWins: an explicit pool_max_conns in the DSN beats the config.
func TestBuildPoolConfig_DSNOverrideWins(t *testing.T) {
	cfg, err := buildPoolConfig(poolTestDSN+"&pool_max_conns=7", PoolConfig{MaxConns: 32})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxConns != 7 {
		t.Fatalf("MaxConns = %d, want 7 (operator DSN override must win)", cfg.MaxConns)
	}
}

// TestBuildPoolConfig_ZeroUsesBuiltinDefault: a zero PoolConfig defaults MaxConns to 32.
func TestBuildPoolConfig_ZeroUsesBuiltinDefault(t *testing.T) {
	cfg, err := buildPoolConfig(poolTestDSN, PoolConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxConns != 32 {
		t.Fatalf("MaxConns = %d, want 32 (built-in default)", cfg.MaxConns)
	}
}

func TestBuildPoolConfig_BadDSN(t *testing.T) {
	if _, err := buildPoolConfig("::not a dsn::", PoolConfig{}); err == nil {
		t.Fatal("a malformed DSN must error")
	}
}

// TestDSNForMigrate_StripsPoolParams: the pgxpool-only pool_* params must be removed before
// the DSN reaches the database/sql pgx driver (goose), which rejects them – while every other
// param (sslmode, etc.) is preserved. Regression for the boot failure host validation caught.
func TestDSNForMigrate_StripsPoolParams(t *testing.T) {
	got := dsnForMigrate(poolTestDSN + "&pool_max_conns=24&pool_min_conns=2")
	if strings.Contains(got, "pool_max_conns") || strings.Contains(got, "pool_min_conns") {
		t.Fatalf("pool_* params must be stripped, got %q", got)
	}
	if !strings.Contains(got, "sslmode=disable") {
		t.Fatalf("non-pool params must be preserved, got %q", got)
	}
}

func TestDSNForMigrate_NoPoolParamsUnchanged(t *testing.T) {
	if got := dsnForMigrate(poolTestDSN); got != poolTestDSN {
		t.Fatalf("a DSN without pool_* must be unchanged, got %q", got)
	}
}

func TestDSNForMigrate_KeywordForm(t *testing.T) {
	got := dsnForMigrate("host=localhost user=synapse sslmode=disable pool_max_conns=24")
	if strings.Contains(got, "pool_max_conns") {
		t.Fatalf("keyword-form pool_* must be stripped, got %q", got)
	}
	if !strings.Contains(got, "host=localhost") || !strings.Contains(got, "sslmode=disable") {
		t.Fatalf("keyword-form non-pool fields must be preserved, got %q", got)
	}
}

func TestMigrationLockKeyIsDedicated(t *testing.T) {
	migrationKey := migrationLockKey()
	for _, role := range []string{"api", "worker", "mcp"} {
		if migrationKey == singletonLockKey(role) {
			t.Fatalf("migration lock key must differ from %s singleton lock key", role)
		}
	}
}

func TestMigrateLockedWaitsForMigrationLock(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	holder, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Release()
	if _, err := holder.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey()); err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if !locked {
			return
		}
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer releaseCancel()
		_, _ = holder.Exec(releaseCtx, "SELECT pg_advisory_unlock($1)", migrationLockKey())
	}()

	contenderName := fmt.Sprintf("synapse-migration-test-%d", time.Now().UnixNano())
	contenderDSN, err := dsnWithApplicationName(dsn, contenderName)
	if err != nil {
		t.Fatal(err)
	}
	contenderCtx, contenderCancel := context.WithCancel(ctx)
	defer contenderCancel()
	done := make(chan error, 1)
	go func() { done <- MigrateLocked(contenderCtx, contenderDSN) }()

	waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer waitCancel()
	for {
		var waiting bool
		err := holder.QueryRow(waitCtx, `
SELECT EXISTS (
	SELECT 1
	FROM pg_stat_activity AS activity
	JOIN pg_locks AS lock ON lock.pid = activity.pid
	WHERE activity.application_name = $1
		AND lock.locktype = 'advisory'
		AND NOT lock.granted
		AND lock.database = activity.datid
		AND lock.objsubid = 1
		AND ((lock.classid::bigint << 32) | lock.objid::bigint) = $2
)`, contenderName, migrationLockKey()).Scan(&waiting)
		if err != nil {
			t.Fatalf("inspect contender advisory lock request: %v", err)
		}
		if waiting {
			break
		}

		select {
		case <-waitCtx.Done():
			t.Fatalf("contender did not request the migration advisory lock: %v", waitCtx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}

	if _, err := holder.Exec(ctx, "SELECT pg_advisory_unlock($1)", migrationLockKey()); err != nil {
		t.Fatal(err)
	}
	locked = false
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatalf("MigrateLocked did not complete after migration lock release: %v", ctx.Err())
	}
}

func dsnWithApplicationName(dsn, applicationName string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", fmt.Errorf("parse test database dsn to set application_name: %w", err)
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return dsn + " application_name=" + applicationName, nil
	}
	q := u.Query()
	q.Set("application_name", applicationName)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func TestValidateMigrationRoleSeparation(t *testing.T) {
	tests := []struct {
		name         string
		migrationDSN string
		runtimeDSN   string
		wantErr      bool
	}{
		{
			name:         "identical DSNs",
			migrationDSN: "postgres://synapse_app:secret@localhost/synapse?sslmode=disable",
			runtimeDSN:   "postgres://synapse_app:secret@localhost/synapse?sslmode=disable",
			wantErr:      true,
		},
		{
			name:         "same role with different credentials and options",
			migrationDSN: "postgres://synapse_app:owner-secret@localhost/synapse?sslmode=require&application_name=migrate",
			runtimeDSN:   "postgres://synapse_app:runtime-secret@localhost/synapse?application_name=api&sslmode=disable",
			wantErr:      true,
		},
		{
			name:         "distinct roles",
			migrationDSN: "postgres://synapse_owner:owner-secret@localhost/synapse?sslmode=disable",
			runtimeDSN:   "postgres://synapse_app:runtime-secret@localhost/synapse?sslmode=disable",
		},
		{
			name:         "malformed migration DSN",
			migrationDSN: "::not a dsn::",
			runtimeDSN:   "postgres://synapse_app:runtime-secret@localhost/synapse?sslmode=disable",
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMigrationRoleSeparation(tt.migrationDSN, tt.runtimeDSN)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateMigrationRoleSeparation() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}
