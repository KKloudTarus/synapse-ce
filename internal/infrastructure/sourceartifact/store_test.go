package sourceartifact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
)

func TestCaptureLoadAndVerifyImmutableSource(t *testing.T) {
	workspace := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workspace, "cmd"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "cmd", "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := New(filepath.Join(t.TempDir(), "source"), 0, 0, 0)
	capture, err := store.Capture(context.Background(), "tenant", "project", "analysis", workspace)
	if err != nil {
		t.Fatal(err)
	}
	if !capture.Capabilities.Source.Available || len(capture.Manifest.Files) != 1 || capture.Manifest.Digest != capture.Manifest.ArtifactDigest() {
		t.Fatalf("capture=%+v", capture)
	}
	if err := os.WriteFile(filepath.Join(workspace, "cmd", "main.go"), []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, file, err := store.Load(context.Background(), "tenant", "project", "analysis", "cmd/main.go")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "package main\n" || !file.Available {
		t.Fatalf("data=%q file=%+v", data, file)
	}
}

func TestCaptureSkipsGitMetadata(t *testing.T) {
	workspace := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workspace, ".git", "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".git", "objects", "secret"), []byte("metadata"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	capture, err := New(filepath.Join(t.TempDir(), "source"), 0, 0, 0).Capture(context.Background(), "tenant", "project", "analysis", workspace)
	if err != nil {
		t.Fatal(err)
	}
	if len(capture.Manifest.Files) != 1 || capture.Manifest.Files[0].Path != "main.go" {
		t.Fatalf("files=%+v", capture.Manifest.Files)
	}
}

func TestCaptureMarksUnsupportedFilesWithoutFailingAnalysis(t *testing.T) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "binary.bin"), []byte{0, 1}, 0o600); err != nil {
		t.Fatal(err)
	}
	store := New(filepath.Join(t.TempDir(), "source"), 0, 0, 0)
	capture, err := store.Capture(context.Background(), "tenant", "project", "analysis", workspace)
	if err != nil {
		t.Fatal(err)
	}
	file := capture.Manifest.Files[0]
	if file.Available || file.Reason != projectanalysis.UnavailableBinary {
		t.Fatalf("file=%+v", file)
	}
	if _, _, err := store.Load(context.Background(), "tenant", "project", "analysis", "binary.bin"); !errors.Is(err, projectanalysis.ErrSourceUnsupported) {
		t.Fatalf("Load() error=%v", err)
	}
}

func TestCaptureRetainsPartialManifestAtLimits(t *testing.T) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "a.go"), []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "b.go"), []byte("b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := New(filepath.Join(t.TempDir(), "source"), 0, 10, 2)
	capture, err := store.Capture(context.Background(), "tenant", "project", "analysis", workspace)
	if err != nil {
		t.Fatal(err)
	}
	if !capture.Capabilities.Source.Available || !capture.Manifest.Truncated || len(capture.Manifest.Files) != 2 {
		t.Fatalf("capture=%+v", capture)
	}
	if !capture.Manifest.Files[0].Available || capture.Manifest.Files[1].Available || capture.Manifest.Files[1].Reason != projectanalysis.UnavailableLimitExceeded {
		t.Fatalf("files=%+v", capture.Manifest.Files)
	}
	if _, _, err := store.Load(context.Background(), "tenant", "project", "analysis", "b.go"); !errors.Is(err, projectanalysis.ErrSourceLimit) {
		t.Fatalf("Load() error=%v", err)
	}
}

func TestCaptureBaseRetainsPartialManifestAtLimits(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "source"), 0, 1, 0)
	manifest, err := store.CaptureBase(context.Background(), "tenant", "project", "analysis", map[string][]byte{
		"a.go": []byte("a\n"),
		"b.go": []byte("b\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.Truncated || len(manifest.Files) != 1 || manifest.Digest != manifest.ArtifactDigest() {
		t.Fatalf("manifest=%+v", manifest)
	}
	if _, _, err := store.LoadBase(context.Background(), "tenant", "project", "analysis", "a.go"); err != nil {
		t.Fatalf("LoadBase() error=%v", err)
	}
	if _, _, err := store.LoadBase(context.Background(), "tenant", "project", "analysis", "b.go"); !errors.Is(err, projectanalysis.ErrSourceNotRetained) {
		t.Fatalf("LoadBase() error=%v", err)
	}
}

func TestLineCountUsesPhysicalLines(t *testing.T) {
	for _, tc := range []struct {
		content string
		want    int
	}{{"", 0}, {"one", 1}, {"one\n", 1}, {"one\ntwo\n", 2}} {
		if got := lineCount([]byte(tc.content)); got != tc.want {
			t.Errorf("lineCount(%q)=%d, want %d", tc.content, got, tc.want)
		}
	}
}

func TestLoadRejectsArtifactTampering(t *testing.T) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "source")
	store := New(root, 0, 0, 0)
	capture, err := store.Capture(context.Background(), "tenant", "project", "analysis", workspace)
	if err != nil {
		t.Fatal(err)
	}
	blob := filepath.Join(root, "tenant", "project", "analysis", "blobs", capture.Manifest.Files[0].Digest+".gz")
	if err := os.WriteFile(blob, []byte("not gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(context.Background(), "tenant", "project", "analysis", "main.go"); err == nil {
		t.Fatal("tampered artifact loaded")
	}
}
