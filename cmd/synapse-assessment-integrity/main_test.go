package main

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
)

func TestParseIntegrityOptions(t *testing.T) {
	options, err := parseIntegrityOptions([]string{"--tenants", "tenant-a,tenant-b,tenant-a", "--batch-size", "2000", "--timeout", "1h"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.tenants) != 2 || options.batchSize != 2000 || options.timeout != time.Hour {
		t.Fatalf("options = %+v", options)
	}
	for _, args := range [][]string{
		{},
		{"--tenants", "a,b,c,d,e"},
		{"--tenants", "a", "--batch-size", "2001"},
		{"--tenants", "a", "--dry-run=false"},
	} {
		if _, err := parseIntegrityOptions(args, io.Discard); err == nil {
			t.Fatalf("expected invalid options for %v", args)
		}
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
	err = run([]string{"--tenants", "assessment-cycle-role-guard-test", "--dry-run", "--timeout", "10s"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "cannot enforce isolation") {
		t.Fatalf("expected startup rejection before backfill writes, got %v", err)
	}
}
