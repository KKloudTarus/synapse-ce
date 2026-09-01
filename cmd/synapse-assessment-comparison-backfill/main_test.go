package main

import (
	"io"
	"testing"
	"time"

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
