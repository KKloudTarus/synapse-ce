package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/restoreverify"
)

type verifierStub struct {
	result restoreverify.Result
	err    error
	ctx    context.Context
}

func (s *verifierStub) Verify(ctx context.Context) (restoreverify.Result, error) {
	s.ctx = ctx
	return s.result, s.err
}

func TestLoadSettingsRequiresExternalServicesWithoutLeakingValues(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"database", map[string]string{}, "SYNAPSE_DB_DSN is required"},
		{"blob", map[string]string{"SYNAPSE_DB_DSN": "postgres://user:secret@host/database"}, "SYNAPSE_BLOB_ENDPOINT"},
		{"boolean", validEnv("SYNAPSE_BLOB_USE_SSL", "not-bool"), "SYNAPSE_BLOB_USE_SSL must be a boolean"},
		{"timeout", validEnv("SYNAPSE_RESTORE_VERIFY_TIMEOUT", "zero"), "SYNAPSE_RESTORE_VERIFY_TIMEOUT must be a positive duration"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadSettings(func(key string) string { return tt.env[key] })
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("loadSettings() error = %v, want %q", err, tt.want)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("loadSettings() leaked a credential: %v", err)
			}
		})
	}
}

func TestRunWritesIndentedReportAndFailsForNonIntactResult(t *testing.T) {
	stub := &verifierStub{result: restoreverify.Result{Intact: false}}
	closed := false
	var out bytes.Buffer
	err := run(context.Background(), settings{timeout: time.Second}, func(context.Context, settings) (verifier, func(), error) {
		return stub, func() { closed = true }, nil
	}, &out)
	if !errors.Is(err, errIntegrity) {
		t.Fatalf("run() error = %v, want integrity error", err)
	}
	if !closed {
		t.Fatal("run() did not close dependencies")
	}
	if got, want := out.String(), "{\n  \"intact\": false,"; !strings.HasPrefix(got, want) {
		t.Fatalf("run() output = %q, want indented JSON starting %q", got, want)
	}
}

func TestRunReturnsGenericExecutionErrorWithoutWritingReport(t *testing.T) {
	var out bytes.Buffer
	err := run(context.Background(), settings{timeout: time.Second}, func(context.Context, settings) (verifier, func(), error) {
		return &verifierStub{err: errors.New("connection failed for postgres://user:secret@host/database")}, nil, nil
	}, &out)
	if err == nil || err.Error() != "restore verification failed" {
		t.Fatalf("run() error = %v, want generic execution error", err)
	}
	if out.Len() != 0 {
		t.Fatalf("run() wrote report on execution failure: %q", out.String())
	}
}

func TestRunHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	err := run(ctx, settings{timeout: time.Second}, func(context.Context, settings) (verifier, func(), error) {
		return &verifierStub{err: context.Canceled}, nil, nil
	}, &out)
	if err == nil || err.Error() != "restore verification canceled" {
		t.Fatalf("run() error = %v, want cancellation error", err)
	}
}

func validEnv(key, value string) map[string]string {
	return map[string]string{
		"SYNAPSE_DB_DSN":          "postgres://user:secret@host/database",
		"SYNAPSE_BLOB_ENDPOINT":   "minio.example.test:9000",
		"SYNAPSE_BLOB_ACCESS_KEY": "access-key",
		"SYNAPSE_BLOB_SECRET_KEY": "secret-key",
		"SYNAPSE_BLOB_BUCKET":     "evidence",
		key:                       value,
	}
}

func TestLoadExpectedStateStrictAndDoesNotExposeInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	valid := `{"audit_head":"","evidence_chains":[{"engagement_id":"eng","head":"","count":0}],"migration_versions":[7]}`
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	state, err := loadExpectedState(path)
	if err != nil || state == nil || len(state.EvidenceChains) != 1 {
		t.Fatalf("loadExpectedState() = %#v, %v", state, err)
	}
	if err := os.WriteFile(path, []byte(`{"audit_head":"SECRET","extra":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadExpectedState(path); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("strict parse error leaked input: %v", err)
	}
	if _, err := loadExpectedState(filepath.Join(dir, "missing-secret.json")); err == nil || strings.Contains(err.Error(), "missing-secret") {
		t.Fatalf("read error leaked path: %v", err)
	}
}
