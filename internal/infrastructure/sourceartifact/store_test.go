package sourceartifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
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

func TestCaptureDefaultTenantIsIsolated(t *testing.T) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "main.go"), []byte("default\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := New(filepath.Join(t.TempDir(), "source"), 0, 0, 0)
	if _, err := store.Capture(context.Background(), "", "project", "analysis", workspace); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "main.go"), []byte("named\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Capture(context.Background(), "project", "analysis", "named", workspace); err != nil {
		t.Fatal(err)
	}
	data, _, err := store.Load(context.Background(), "", "project", "analysis", "main.go")
	if err != nil || string(data) != "default\n" {
		t.Fatalf("default data=%q err=%v", data, err)
	}
	data, _, err = store.Load(context.Background(), "project", "analysis", "named", "main.go")
	if err != nil || string(data) != "named\n" {
		t.Fatalf("named data=%q err=%v", data, err)
	}
	if store.analysisDir("", "project", "analysis") == store.analysisDir("project", "analysis", "named") {
		t.Fatal("default and named tenants share artifact paths")
	}
}

func TestCaptureBaseValidatesContext(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "source"), 0, 0, 0)
	for _, tc := range []struct {
		project  shared.ID
		analysis string
	}{{"", "analysis"}, {"project", ""}} {
		if _, err := store.CaptureBase(context.Background(), "", tc.project, tc.analysis, nil); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("CaptureBase(%q, %q) error=%v", tc.project, tc.analysis, err)
		}
	}
	if _, err := store.CaptureBase(context.Background(), "", "project", "analysis", map[string][]byte{"base.go": []byte("base\n")}); err != nil {
		t.Fatalf("default tenant CaptureBase: %v", err)
	}
	data, _, err := store.LoadBase(context.Background(), "", "project", "analysis", "base.go")
	if err != nil || string(data) != "base\n" {
		t.Fatalf("LoadBase data=%q err=%v", data, err)
	}
}

func TestLoadReadsNamedTenantLegacyArtifact(t *testing.T) {
	root := filepath.Join(t.TempDir(), "source")
	store := New(root, 0, 0, 0)
	writeLegacyArtifact(t, filepath.Join(root, "tenant", "project", "analysis"), "main.go", []byte("legacy\n"))
	data, _, err := store.Load(context.Background(), "tenant", "project", "analysis", "main.go")
	if err != nil || string(data) != "legacy\n" {
		t.Fatalf("legacy data=%q err=%v", data, err)
	}
}

func TestDefaultTenantDoesNotReadLegacyArtifact(t *testing.T) {
	root := filepath.Join(t.TempDir(), "source")
	store := New(root, 0, 0, 0)
	writeLegacyArtifact(t, filepath.Join(root, "project", "analysis"), "main.go", []byte("ambiguous\n"))
	if _, _, err := store.Load(context.Background(), "", "project", "analysis", "main.go"); !errors.Is(err, ErrNotRetained) {
		t.Fatalf("default tenant read ambiguous legacy artifact: %v", err)
	}
}

func writeLegacyArtifact(t *testing.T, root, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "blobs"), 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	digestHex := hex.EncodeToString(digest[:])
	if err := writeGzip(filepath.Join(root, "blobs", digestHex+".gz"), data); err != nil {
		t.Fatal(err)
	}
	manifest := projectanalysis.SourceManifest{Files: []projectanalysis.SourceFile{{Path: path, Digest: digestHex, Bytes: int64(len(data)), Lines: lineCount(data), Available: true}}}
	manifest.SetArtifactDigest()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteProjectLeavesOtherTenantArtifacts(t *testing.T) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "main.go"), []byte("source\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := New(filepath.Join(t.TempDir(), "source"), 0, 0, 0)
	for _, tenant := range []shared.ID{"", "tenant"} {
		if _, err := store.Capture(context.Background(), tenant, "project", "analysis", workspace); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.DeleteProject(context.Background(), "", "project"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(context.Background(), "", "project", "analysis", "main.go"); !errors.Is(err, ErrNotRetained) {
		t.Fatalf("deleted default tenant loaded: %v", err)
	}
	if _, _, err := store.Load(context.Background(), "tenant", "project", "analysis", "main.go"); err != nil {
		t.Fatalf("named tenant artifact deleted: %v", err)
	}
}

func TestCleanupExpiredKeepsFreshTenantArtifacts(t *testing.T) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "main.go"), []byte("source\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := New(filepath.Join(t.TempDir(), "source"), 0, 0, 0)
	if _, err := store.Capture(context.Background(), "", "project", "old", workspace); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Capture(context.Background(), "tenant", "project", "fresh", workspace); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(store.analysisDir("", "project", "old"), old, old); err != nil {
		t.Fatal(err)
	}
	if err := store.CleanupExpired(context.Background(), time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(context.Background(), "", "project", "old", "main.go"); !errors.Is(err, ErrNotRetained) {
		t.Fatalf("expired artifact loaded: %v", err)
	}
	if _, _, err := store.Load(context.Background(), "tenant", "project", "fresh", "main.go"); err != nil {
		t.Fatalf("fresh artifact removed: %v", err)
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

func TestLoadRejectsTamperedManifest(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "source"), 8, 0, 0)
	root := store.analysisDir("tenant", "project", "analysis")
	writeLegacyArtifact(t, root, "main.go", []byte("original"))
	manifestData, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest projectanalysis.SourceManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Files[0].Path = "other.go"
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(context.Background(), "tenant", "project", "analysis", "other.go"); !errors.Is(err, projectanalysis.ErrSourceIntegrity) {
		t.Fatalf("Load() error=%v, want integrity error", err)
	}
}

func TestLoadRejectsMalformedManifestDigest(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "source"), 8, 0, 0)
	root := store.analysisDir("tenant", "project", "analysis")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := projectanalysis.SourceManifest{Files: []projectanalysis.SourceFile{{Path: "main.go", Digest: "../outside", Bytes: 1, Lines: 1, Available: true}}}
	manifest.SetArtifactDigest()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(context.Background(), "tenant", "project", "analysis", "main.go"); !errors.Is(err, projectanalysis.ErrSourceIntegrity) {
		t.Fatalf("Load() error=%v, want integrity error", err)
	}
}

func TestLoadRejectsOversizedDecompressedBlob(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "source"), 8, 0, 0)
	root := store.analysisDir("tenant", "project", "analysis")
	data := []byte("123456789")
	writeLegacyArtifact(t, root, "main.go", data)
	if _, _, err := store.Load(context.Background(), "tenant", "project", "analysis", "main.go"); !errors.Is(err, projectanalysis.ErrSourceIntegrity) {
		t.Fatalf("Load() error=%v, want integrity error", err)
	}
}

func TestLoadAcceptsConfiguredFileBoundary(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "source"), 8, 0, 0)
	root := store.analysisDir("tenant", "project", "analysis")
	data := []byte("12345678")
	writeLegacyArtifact(t, root, "main.go", data)
	got, _, err := store.Load(context.Background(), "tenant", "project", "analysis", "main.go")
	if err != nil || string(got) != string(data) {
		t.Fatalf("Load() data=%q error=%v", got, err)
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
	blob := filepath.Join(store.analysisDir("tenant", "project", "analysis"), "blobs", capture.Manifest.Files[0].Digest+".gz")
	if err := os.WriteFile(blob, []byte("not gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(context.Background(), "tenant", "project", "analysis", "main.go"); err == nil {
		t.Fatal("tampered artifact loaded")
	}
}
