package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sourceartifact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// --retain-source must be self-consistent: capture needs an analysis to key the snapshot on, and the
// identity flags mean nothing on their own. Both directions are usage errors, never a silent skip.
func TestValidateSourceRetention(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      sourceRetention
		wantErr bool
	}{
		{name: "disabled and empty", in: sourceRetention{}},
		{name: "enabled with both ids", in: sourceRetention{Enabled: true, ProjectID: "p1", AnalysisID: "a1"}},
		{name: "enabled with tenant too", in: sourceRetention{Enabled: true, ProjectID: "p1", AnalysisID: "a1", TenantID: "t1"}},
		{name: "enabled without project", in: sourceRetention{Enabled: true, AnalysisID: "a1"}, wantErr: true},
		{name: "enabled without analysis", in: sourceRetention{Enabled: true, ProjectID: "p1"}, wantErr: true},
		{name: "enabled with neither", in: sourceRetention{Enabled: true}, wantErr: true},
		{name: "enabled with blank project", in: sourceRetention{Enabled: true, ProjectID: "   ", AnalysisID: "a1"}, wantErr: true},
		{name: "ids without the flag", in: sourceRetention{ProjectID: "p1", AnalysisID: "a1"}, wantErr: true},
		{name: "tenant without the flag", in: sourceRetention{TenantID: "t1"}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateSourceRetention(test.in)
			if test.wantErr && err == nil {
				t.Fatalf("validateSourceRetention(%+v) = nil, want an error", test.in)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("validateSourceRetention(%+v) = %v, want nil", test.in, err)
			}
		})
	}
}

// A stray shell space must not push the snapshot under a key the API will never look up.
func TestSourceRetentionNormalizedTrims(t *testing.T) {
	t.Parallel()
	got := sourceRetention{Enabled: true, TenantID: " t1\t", ProjectID: " p1 ", AnalysisID: "\na1 "}.normalized()
	want := sourceRetention{Enabled: true, TenantID: "t1", ProjectID: "p1", AnalysisID: "a1"}
	if got != want {
		t.Fatalf("normalized() = %+v, want %+v", got, want)
	}
}

// The store the CLI wires must satisfy the same port the API composition root injects, so a CLI capture
// is interchangeable with a server-side one.
func TestCLIStoreSatisfiesPort(t *testing.T) {
	t.Parallel()
	var _ ports.ProjectSourceArtifactStore = sourceartifact.New(t.TempDir(), 1<<20, 10, 1<<20)
}

// End to end for the capture contract: a snapshot written with the CLI's tenant/project/analysis key is
// readable through the same Load the Code workspace's /code/file uses. This is the acceptance criterion
// that the closed #346 wiring could not reach.
func TestCLICaptureIsServableByCodeFile(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	retain := sourceRetention{Enabled: true, TenantID: "", ProjectID: "proj-1", AnalysisID: "analysis-1"}.normalized()
	if err := validateSourceRetention(retain); err != nil {
		t.Fatalf("fixture retention is invalid: %v", err)
	}

	srcDir := t.TempDir()
	const rel = "app/main.go"
	const body = "package main\n\nfunc main() {}\n"
	if err := os.MkdirAll(filepath.Join(srcDir, "app"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, rel), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	store := sourceartifact.New(t.TempDir(), 1<<20, 100, 10<<20)
	capture, err := store.Capture(ctx, shared.ID(retain.TenantID), shared.ID(retain.ProjectID), retain.AnalysisID, srcDir)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if !capture.Capabilities.Source.Available {
		t.Fatalf("capture reported unavailable: reason=%q", capture.Capabilities.Source.Reason)
	}
	if len(capture.Manifest.Files) == 0 {
		t.Fatal("manifest recorded no files")
	}

	// Same key the code viewer resolves with.
	data, _, err := store.Load(ctx, shared.ID(retain.TenantID), shared.ID(retain.ProjectID), retain.AnalysisID, rel)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(data) != body {
		t.Fatalf("Load returned %q, want %q", string(data), body)
	}
}
