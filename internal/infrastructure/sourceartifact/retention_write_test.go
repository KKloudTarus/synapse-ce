package sourceartifact

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestSnapshotWritersRunRetentionCleanupBeforeWrite(t *testing.T) {
	tenantID := shared.ID("tenant-retention")
	projectID := shared.ID("project-retention")

	t.Run("capture", func(t *testing.T) {
		store, expired := retentionTestStore(t, tenantID, projectID)
		sourceDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(sourceDir, "main.go"), []byte("package main\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Capture(context.Background(), tenantID, projectID, "fresh-capture", sourceDir); err != nil {
			t.Fatalf("Capture: %v", err)
		}
		assertRetentionRemoved(t, expired)
	})

	t.Run("capture base", func(t *testing.T) {
		store, expired := retentionTestStore(t, tenantID, projectID)
		if _, err := store.CaptureBase(context.Background(), tenantID, projectID, "fresh-base", map[string][]byte{"main.go": []byte("package main\n")}); err != nil {
			t.Fatalf("CaptureBase: %v", err)
		}
		assertRetentionRemoved(t, expired)
	})

	t.Run("sanctioned publish", func(t *testing.T) {
		store, expired := retentionTestStore(t, tenantID, projectID)
		var archive bytes.Buffer
		tw := tar.NewWriter(&archive)
		body := []byte("package main\n")
		if err := tw.WriteHeader(&tar.Header{Name: "main.go", Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		writer := projectanalysis.SourceWriter{Actor: "operator", ToolVersion: "test", PublishedAt: time.Now().UTC()}
		if _, err := store.PublishArchive(context.Background(), tenantID, projectID, "fresh-publish", writer, []string{"main.go"}, &archive); err != nil {
			t.Fatalf("PublishArchive: %v", err)
		}
		assertRetentionRemoved(t, expired)
	})
}

func TestCleanupExpiredRemovesStaleIncompleteClaims(t *testing.T) {
	store := New(t.TempDir(), 0, 0, 0)
	tenantID := shared.ID("tenant-incomplete")
	projectID := shared.ID("project-incomplete")
	claim := store.analysisDir(tenantID, projectID, "interrupted-publish")
	if err := os.MkdirAll(filepath.Join(claim, "blobs"), 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(claim, old, old); err != nil {
		t.Fatal(err)
	}
	if err := store.CleanupExpired(context.Background(), time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("CleanupExpired: %v", err)
	}
	assertRetentionRemoved(t, claim)
}

func retentionTestStore(t *testing.T, tenantID, projectID shared.ID) (*Store, string) {
	t.Helper()
	store := New(t.TempDir(), 0, 0, 0)
	store.SetRetention(time.Hour)
	expired := store.analysisDir(tenantID, projectID, "expired-analysis")
	if err := os.MkdirAll(expired, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(expired, "manifest.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(expired, old, old); err != nil {
		t.Fatal(err)
	}
	return store, expired
}

func assertRetentionRemoved(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expired source artifact still exists after write: stat err=%v", err)
	}
}
