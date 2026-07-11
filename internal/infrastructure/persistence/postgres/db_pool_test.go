package postgres

import (
	"strings"
	"testing"
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
