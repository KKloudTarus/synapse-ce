package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestParseIdentityBackfillOptions(t *testing.T) {
	options, err := parseOptions([]string{"--tenants", "tenant-a,tenant-b,tenant-a", "--oidc-issuer", "https://idp.example.test", "--batch-size", "50", "--max-drift", "2"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if options.mode != "backfill" || len(options.tenants) != 2 || options.issuer != "https://idp.example.test" || options.batchSize != 50 || options.maxDrift != 2 {
		t.Fatalf("unexpected options: %+v", options)
	}
}

func TestParseIdentityBackfillOptionsRejectsUnsafeInput(t *testing.T) {
	for _, args := range [][]string{
		{"--tenants", ""},
		{"--tenants", "a", "--batch-size", "1001"},
		{"--tenants", "a", "--batch-size", "0"},
		{"--tenants", "a", "--mode", "repair"},
		{"--tenants", "a", "--mode", "declare"},
		{"--tenants", "a", "--migration-version", "208"},
		{"--tenants", "a", "--max-drift", "-1"},
		{"--tenants", "a", "--oidc-issuer", " https://idp.example.test"},
		{"--tenants", "a", "--delivery-limit", "501"},
		{"--tenants", "a", "extra"},
	} {
		if _, err := parseOptions(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("expected rejection for %v", args)
		}
	}
}

func TestParseIdentityCutoverDeclarationEvidence(t *testing.T) {
	o, err := parseOptions([]string{"--tenants", "a", "--mode", "declare", "--expected-policy-version", "2", "--shadow-report-id", "report", "--old-writer-generation", "shared-authentication:test", "--migration-version", "209"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if o.policyVersion != 2 || o.shadowReportID != "report" || o.oldWriterGeneration != "shared-authentication:test" || o.migrationVersion != 209 {
		t.Fatalf("cutover options = %+v", o)
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
	t.Setenv("SYNAPSE_DB_DSN", dsn)
	err = run([]string{"--tenants", "identity-backfill-role-guard", "--mode", "shadow", "--timeout", "10s"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "cannot enforce isolation") {
		t.Fatalf("expected startup rejection before backfill writes, got %v", err)
	}
}

func TestShadowOutcomeExitCodes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		report ports.IdentityShadowReport
		code   int
		label  string
	}{
		{"ready", ports.IdentityShadowReport{Ready: true}, exitReady, "ready"},
		{"drift within threshold", ports.IdentityShadowReport{DriftTotal: 2}, exitNotReady, "not_ready"},
		{"ambiguous only", ports.IdentityShadowReport{Ambiguous: 1}, exitNotReady, "not_ready"},
		{"drift above threshold", ports.IdentityShadowReport{DriftTotal: 3, Aborted: true}, exitAborted, "aborted"},
	} {
		code, label := reportOutcome(tc.report)
		if code != tc.code || label != tc.label {
			t.Fatalf("%s: outcome = %d %s, want %d %s", tc.name, code, label, tc.code, tc.label)
		}
	}
	if exitCode(nil) != exitReady {
		t.Fatal("success must exit 0")
	}
	if exitCode(errors.New("boom")) != exitFailure {
		t.Fatal("operational failure must exit 1")
	}
	wrapped := fmt.Errorf("outer: %w", &outcomeError{code: exitAborted, err: errors.New("aborted")})
	if exitCode(wrapped) != exitAborted {
		t.Fatal("aborted outcome lost its exit code")
	}
	if exitNotReady == exitFailure || exitAborted == exitFailure || exitNotReady == exitAborted {
		t.Fatal("exit codes must be distinct")
	}
}

type captureInfoLogger struct {
	args []any
}

func (l *captureInfoLogger) Info(_ string, args ...any) { l.args = append(l.args, args...) }

func TestLogReportIncludesAuthenticatorParity(t *testing.T) {
	log := &captureInfoLogger{}
	logReport(log, ports.IdentityShadowReport{
		AuthenticatorsExpected: 3, AuthenticatorsMatched: 2, AuthenticatorMismatches: 1,
	}, "not_ready")
	got := fmt.Sprint(log.args...)
	for _, want := range []string{"authenticators_expected", "3", "authenticators_matched", "2", "authenticator_mismatches", "1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("shadow log lacks %q: %v", want, log.args)
		}
	}
}

func TestUsageDocumentsExitCodes(t *testing.T) {
	var out bytes.Buffer
	if _, err := parseOptions([]string{"--help"}, &out); err == nil {
		t.Fatal("--help should stop parsing")
	}
	for _, want := range []string{"Exit status:", "  3  not ready", "  4  aborted", "--max-drift"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("usage lacks %q:\n%s", want, out.String())
		}
	}
}
