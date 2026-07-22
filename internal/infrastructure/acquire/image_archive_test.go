package acquire

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func TestIsLocalImageArchive(t *testing.T) {
	dir := t.TempDir()
	tar := filepath.Join(dir, "img.tar")
	if err := os.WriteFile(tar, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		tar:                            true,
		filepath.Join(dir, "a.tar.gz"): false, // does not exist on disk
		"alpine:latest":                false, // bare registry ref
		"docker.io/library/nginx:1.27": false,
		dir:                            false, // a directory, not a regular file
	}
	// materialize the .tar.gz case so the suffix branch is exercised as a real file
	gz := filepath.Join(dir, "a.tar.gz")
	if err := os.WriteFile(gz, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases[gz] = true
	for in, want := range cases {
		if got := isLocalImageArchive(in); got != want {
			t.Errorf("isLocalImageArchive(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestAcquireImageArchive loads a real docker-save tarball (produced in-process) through the
// airgapped path and asserts it materializes an OCI layout that syft can scan — no registry.
func TestAcquireImageArchive(t *testing.T) {
	dir := t.TempDir()
	ref, err := name.NewTag("synapse-test/img:latest")
	if err != nil {
		t.Fatal(err)
	}
	tarPath := filepath.Join(dir, "img.tar")
	if err := tarball.WriteToFile(tarPath, ref, empty.Image); err != nil {
		t.Fatalf("write docker-save tarball: %v", err)
	}

	if !isLocalImageArchive(tarPath) {
		t.Fatalf("expected %q to be recognized as a local image archive", tarPath)
	}

	ws, err := New().acquireImageArchive(context.Background(), tarPath)
	if err != nil {
		t.Fatalf("acquireImageArchive: %v", err)
	}
	defer func() { _ = ws.Cleanup() }()

	// An OCI layout has an index.json and an oci-layout marker at the workspace Dir.
	for _, name := range []string{"index.json", "oci-layout"} {
		if _, err := os.Stat(filepath.Join(ws.Dir, name)); err != nil {
			t.Errorf("expected OCI layout file %s in workspace: %v", name, err)
		}
	}
}

func TestAcquireImageArchiveRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "not-an-image.tar")
	if err := os.WriteFile(bad, []byte("this is not a tar archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New().acquireImageArchive(context.Background(), bad); err == nil {
		t.Fatal("expected an error loading a non-image tarball, got nil")
	}
}
