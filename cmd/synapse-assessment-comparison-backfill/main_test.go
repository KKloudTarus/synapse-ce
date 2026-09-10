package main

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"

	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
)

func TestParseComparisonBackfillOptions(t *testing.T) {
	cfg := config.Config{AssessmentBatchSize: 500, AssessmentBacklogWarning: 500, AssessmentBacklogHardLimit: 1000}
	options, err := parseComparisonBackfillOptions([]string{
		"--tenants", "tenant-a,tenant-b,tenant-a", "--repair-failed", "--batch-size", "2000",
		"--oldest-active-limit", "15m", "--timeout", "1h",
	}, io.Discard, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.tenants) != 2 || !options.repairFailed || options.batchSize != 2000 || options.oldestActiveLimit != 15*time.Minute {
		t.Fatalf("unexpected options: %+v", options)
	}
	if _, err := parseComparisonBackfillOptions([]string{"--tenants", "tenant-a", "--batch-size", "2001"}, io.Discard, cfg); err == nil {
		t.Fatal("expected oversized batch rejection")
	}
	if _, err := parseComparisonBackfillOptions([]string{"--tenants", "tenant-a,tenant-b", "--after-updated-at", "2026-09-01T00:00:00Z", "--after-cycle-id", "cycle-a"}, io.Discard, cfg); err == nil {
		t.Fatal("expected multi-tenant checkpoint rejection")
	}
}

func TestRunRejectsRLSBypassingRole(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN for the PostgreSQL startup guard test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := postgres.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	guardErr := postgres.CheckRLSRuntimeRole(ctx, pool)
	pool.Close()
	if guardErr == nil {
		t.Skip("test requires a privileged database fixture role")
	}
	if !strings.Contains(guardErr.Error(), "cannot enforce isolation") {
		t.Fatal(guardErr)
	}
	t.Setenv("SYNAPSE_DB_DSN", dsn)
	t.Setenv("SYNAPSE_ASSESSMENT_SNAPSHOT_ENABLED", "true")
	t.Setenv("SYNAPSE_ASSESSMENT_IDENTITY_COMPARISON_SHADOW_ENABLED", "true")
	t.Setenv("SYNAPSE_ASSESSMENT_IDENTITY_COMPARISON_SHADOW_TENANTS", "assessment-cycle-role-guard-test")
	err = run([]string{"--tenants", "assessment-cycle-role-guard-test", "--dry-run", "--timeout", "10s"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "cannot enforce isolation") {
		t.Fatalf("expected startup rejection before backfill writes, got %v", err)
	}
}
