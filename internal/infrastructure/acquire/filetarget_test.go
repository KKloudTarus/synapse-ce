package acquire

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsPyDistMetadata(t *testing.T) {
	yes := []string{
		"Jinja2-2.10.dist-info/METADATA",
		"Jinja2-2.10.dist-info/RECORD",
		"rack.egg-info/PKG-INFO",
		"EGG-INFO/PKG-INFO",
	}
	no := []string{
		"jinja2/__init__.py",
		"jinja2/compiler.py",
		"README.md",
		"jinja2/tests.py",
	}
	for _, p := range yes {
		if !isPyDistMetadata(p) {
			t.Errorf("isPyDistMetadata(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if isPyDistMetadata(p) {
			t.Errorf("isPyDistMetadata(%q) = true, want false", p)
		}
	}
}

func TestUnpackZipBoundedMetadataFilter(t *testing.T) {
	zipPath := writeZip(t, []zipEntry{
		{name: "Jinja2-2.10.dist-info/METADATA", content: "Metadata-Version: 2.1\nName: Jinja2\nVersion: 2.10\n"},
		{name: "jinja2/__init__.py", content: "import os\n"}, // source module: must NOT be extracted
	})
	dest := filepath.Join(t.TempDir(), "out")
	if err := unpackZipBounded(zipPath, dest, MaxWorkspaceBytes, isPyDistMetadata); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "Jinja2-2.10.dist-info", "METADATA")); err != nil {
		t.Errorf("METADATA should be extracted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "jinja2", "__init__.py")); !os.IsNotExist(err) {
		t.Errorf("source module must NOT be extracted (metadata-only), got err=%v", err)
	}
}

func TestUnpackZipBoundedRejectsZipSlip(t *testing.T) {
	zipPath := writeZip(t, []zipEntry{
		{name: "../../../../tmp/escape.dist-info/METADATA", content: "pwned"},
	})
	dest := filepath.Join(t.TempDir(), "out")
	if err := unpackZipBounded(zipPath, dest, MaxWorkspaceBytes, nil); err == nil {
		t.Fatal("expected zip-slip entry to be rejected")
	}
}

func TestUnpackZipBoundedSkipsSymlink(t *testing.T) {
	zipPath := writeZip(t, []zipEntry{
		{name: "a.dist-info/link", content: "/etc/passwd", symlink: true},
		{name: "a.dist-info/METADATA", content: "Name: a\nVersion: 1\n"},
	})
	dest := filepath.Join(t.TempDir(), "out")
	if err := unpackZipBounded(zipPath, dest, MaxWorkspaceBytes, nil); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(filepath.Join(dest, "a.dist-info", "link")); err == nil {
		t.Errorf("symlink entry must be skipped, but was created (mode %v)", fi.Mode())
	}
	if _, err := os.Stat(filepath.Join(dest, "a.dist-info", "METADATA")); err != nil {
		t.Errorf("regular entry alongside the symlink should still extract: %v", err)
	}
}

func TestUnpackZipBoundedBombCap(t *testing.T) {
	zipPath := writeZip(t, []zipEntry{
		{name: "a.dist-info/METADATA", content: string(make([]byte, 4096))},
	})
	dest := filepath.Join(t.TempDir(), "out")
	if err := unpackZipBounded(zipPath, dest, 100, nil); err == nil { // cap below entry size
		t.Fatal("expected an error when uncompressed size exceeds the cap")
	}
}

// TestAcquireFileArtifactWheel round-trips a wheel through the file-target path and asserts the workspace
// carries the extracted dist-info metadata (so the generator can identify the package) but not its source.
func TestAcquireFileArtifactWheel(t *testing.T) {
	zp := writeZip(t, []zipEntry{
		{name: "Jinja2-2.10.dist-info/METADATA", content: "Metadata-Version: 2.1\nName: Jinja2\nVersion: 2.10\n"},
		{name: "jinja2/__init__.py", content: "x = 1\n"},
	})
	whl := filepath.Join(filepath.Dir(zp), "Jinja2-2.10-py3-none-any.whl")
	if err := os.Rename(zp, whl); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(whl)
	if err != nil {
		t.Fatal(err)
	}
	ws, err := acquireFileArtifact(whl, fi.Size(), MaxWorkspaceBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if ws.Cleanup != nil {
			_ = ws.Cleanup()
		}
	}()
	found := false
	_ = filepath.Walk(ws.Dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.Name() == "METADATA" {
			found = true
		}
		if info.Name() == "__init__.py" {
			t.Errorf("wheel source module leaked into workspace: %s", p)
		}
		return nil
	})
	if !found {
		t.Error("wheel dist-info METADATA not present in workspace")
	}
}
