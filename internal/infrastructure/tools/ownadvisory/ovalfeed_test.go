package ownadvisory

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
)

func TestOVALDirFeed(t *testing.T) {
	// Copy the fixture into a fresh dir so the feed reads exactly one OVAL file.
	src, err := os.ReadFile(filepath.Join("testdata", "oval-jammy.xml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "com.ubuntu.jammy.cve.oval.xml"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	// A stray non-OVAL file must be ignored by the suffix filter.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# notes"), 0o644); err != nil {
		t.Fatal(err)
	}

	var got []advisory.Advisory
	skipped, err := NewOVALDirFeed(dir).Each(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Each: %v", err)
	}
	if len(got) != 1 || got[0].ID != "CVE-2023-1000" {
		t.Fatalf("want 1 advisory CVE-2023-1000, got %+v", got)
	}
	// The deferred (no-fix) CVE is dropped by the parser itself (we only emit a CVE with a concrete fixed
	// version), so it never reaches the feed as an inert advisory: no file skips, no inert skips.
	if skipped != 0 {
		t.Errorf("want 0 skipped (README filtered by suffix; no-fix CVE dropped in parse), got %d", skipped)
	}
}

func TestOVALDirFeedBz2(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "oval-jammy.xml.bz2"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "com.ubuntu.jammy.cve.oval.xml.bz2"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	var got []advisory.Advisory
	if _, err := NewOVALDirFeed(dir).Each(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	}); err != nil {
		t.Fatalf("Each(bz2): %v", err)
	}
	if len(got) != 1 || got[0].Affected[0].Ecosystem != "Ubuntu:22.04" {
		t.Errorf("bz2 feed mismatch: %+v", got)
	}
}

func TestOVALDirFeedContextCancelled(t *testing.T) {
	dir := t.TempDir()
	src, _ := os.ReadFile(filepath.Join("testdata", "oval-jammy.xml"))
	_ = os.WriteFile(filepath.Join(dir, "com.ubuntu.jammy.cve.oval.xml"), src, 0o644)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewOVALDirFeed(dir).Each(ctx, func(advisory.Advisory) error { return nil }); err == nil {
		t.Error("a cancelled context must surface an error")
	}
}
