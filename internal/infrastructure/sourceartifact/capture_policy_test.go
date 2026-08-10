package sourceartifact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestCaptureSkipsSecretBearingPaths(t *testing.T) {
	workspace := t.TempDir()
	for name, body := range map[string]string{
		"main.go":          "package main\n",
		".env":             "fixture-blocked-by-path\n",
		"server.key":       "fixture-blocked-by-path\n",
		"credentials.json": "fixture-blocked-by-path\n",
	} {
		if err := os.WriteFile(filepath.Join(workspace, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	store := New(filepath.Join(t.TempDir(), "source"), 0, 0, 0)
	capture, err := store.Capture(context.Background(), "tenant", "project", "analysis", workspace)
	if err != nil {
		t.Fatal(err)
	}
	if len(capture.Manifest.Files) != 1 || capture.Manifest.Files[0].Path != "main.go" {
		t.Fatalf("captured files=%+v", capture.Manifest.Files)
	}
	for _, name := range []string{".env", "server.key", "credentials.json"} {
		if _, _, err := store.Load(context.Background(), "tenant", "project", "analysis", name); !errors.Is(err, projectanalysis.ErrSourceNotRetained) {
			t.Fatalf("Load(%q) error=%v, want not retained", name, err)
		}
	}
}

func TestCaptureBaseSkipsSecretBearingPaths(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "source"), 0, 0, 0)
	manifest, err := store.CaptureBase(context.Background(), "tenant", "project", "analysis", map[string][]byte{
		"main.go":    []byte("package main\n"),
		".env":       []byte("fixture-blocked-by-path\n"),
		"server.pem": []byte("fixture-blocked-by-path\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 1 || manifest.Files[0].Path != "main.go" {
		t.Fatalf("base files=%+v", manifest.Files)
	}
	for _, name := range []string{".env", "server.pem"} {
		if _, _, err := store.LoadBase(context.Background(), "tenant", "project", "analysis", name); !errors.Is(err, projectanalysis.ErrSourceNotRetained) {
			t.Fatalf("LoadBase(%q) error=%v, want not retained", name, err)
		}
	}
}

func TestCaptureIsCreateOnly(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	path := filepath.Join(workspace, "main.go")
	if err := os.WriteFile(path, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := New(filepath.Join(t.TempDir(), "source"), 0, 0, 0)
	if _, err := store.Capture(ctx, "tenant", "project", "analysis", workspace); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := store.Capture(ctx, "tenant", "project", "analysis", workspace)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("second Capture() error=%v, want conflict", err)
	}
	if second.Capabilities.Source.Reason != projectanalysis.UnavailableAlreadyRetained {
		t.Fatalf("second capture reason=%q, want %q", second.Capabilities.Source.Reason, projectanalysis.UnavailableAlreadyRetained)
	}
	data, _, err := store.Load(ctx, "tenant", "project", "analysis", "main.go")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first\n" {
		t.Fatalf("existing capture was overwritten: %q", data)
	}
}
