package ast

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolveSidecarInPrefersBundled(t *testing.T) {
	dir := t.TempDir()
	bundled := filepath.Join(dir, sidecarName())
	if err := os.WriteFile(bundled, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := resolveSidecarIn(dir); got != bundled {
		t.Errorf("want bundled sidecar %q, got %q", bundled, got)
	}
}

func TestResolveSidecarInFallsBackToPath(t *testing.T) {
	// An empty dir (no bundled sidecar) falls back to the bare name for a PATH lookup at exec time.
	if got := resolveSidecarIn(t.TempDir()); got != sidecarName() {
		t.Errorf("want fallback %q, got %q", sidecarName(), got)
	}
	// A directory entry named like the sidecar must NOT be picked (it is not a regular file).
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, sidecarName()), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := resolveSidecarIn(dir); got != sidecarName() {
		t.Errorf("a directory named like the sidecar must be ignored; got %q", got)
	}
	// A NON-executable regular file must not shadow a working PATH copy (fall through to the bare name).
	if runtime.GOOS != "windows" {
		nx := t.TempDir()
		if err := os.WriteFile(filepath.Join(nx, sidecarName()), []byte("stub"), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := resolveSidecarIn(nx); got != sidecarName() {
			t.Errorf("a non-executable stub must not be selected; got %q", got)
		}
	}
}

func TestNewEmptyBinResolves(t *testing.T) {
	// New("") must never leave bin empty (it resolves to a bundled path or the bare name).
	if p := New(""); p.bin == "" {
		t.Errorf("New(\"\") left bin empty")
	}
}
