package ignorefile

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".synapseignore"), []byte("CVE-2023-1 # accepted\nGHSA-x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := New().Load(context.Background(), dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(set) != 2 || set[0].ID != "CVE-2023-1" {
		t.Errorf("want 2 rules parsed, got %+v", set)
	}
}

func TestLoadMissingIsEmpty(t *testing.T) {
	set, err := New().Load(context.Background(), t.TempDir())
	if err != nil || len(set) != 0 {
		t.Errorf("a missing .synapseignore must be an empty policy with no error, got set=%+v err=%v", set, err)
	}
}

func TestLoadSymlinkNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	dir := t.TempDir()
	// A .synapseignore symlink pointing OUT of the workspace must not be followed.
	outside := filepath.Join(t.TempDir(), "evil")
	if err := os.WriteFile(outside, []byte("CVE-2023-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, ".synapseignore")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	set, err := New().Load(context.Background(), dir)
	if err != nil || len(set) != 0 {
		t.Errorf("a symlinked .synapseignore must be ignored (not followed), got set=%+v err=%v", set, err)
	}
}
