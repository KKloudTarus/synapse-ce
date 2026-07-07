package jarchecksum

import (
	"context"
	"crypto/sha1" //nolint:gosec // test computes the expected artifact SHA-1 to match the resolver
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func sha1hex(b []byte) string {
	h := sha1.Sum(b) //nolint:gosec // artifact identity, not a security hash
	return hex.EncodeToString(h[:])
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestResolveCapturesJarSHA1(t *testing.T) {
	ws := t.TempDir()
	content := []byte("PK\x03\x04 fake jar bytes for hashing")
	writeFile(t, filepath.Join(ws, "commons-collections-3.2.1.jar"), content)
	want := sha1hex(content)

	comps := []sbom.Component{
		{Name: "commons-collections", Version: "3.2.1", PURL: "pkg:maven/commons-collections/commons-collections@3.2.1", Location: "/commons-collections-3.2.1.jar"},
	}
	n := (&Resolver{}).Resolve(context.Background(), ws, comps)
	if n != 1 {
		t.Fatalf("want 1 component checksummed, got %d", n)
	}
	if comps[0].SHA1 != want {
		t.Errorf("SHA1 = %q, want %q (the jar file's real digest)", comps[0].SHA1, want)
	}
	if len(comps[0].Checksums) != 1 || comps[0].Checksums[0].Algorithm != "SHA1" || comps[0].Checksums[0].Value != want {
		t.Errorf("Checksums = %+v, want [{SHA1 %s}]", comps[0].Checksums, want)
	}
}

func TestResolveDoesNotOverrideExistingSHA1(t *testing.T) {
	ws := t.TempDir()
	writeFile(t, filepath.Join(ws, "x-1.0.jar"), []byte("bytes"))
	comps := []sbom.Component{{Name: "x", Version: "1.0", Location: "/x-1.0.jar", SHA1: "preexisting"}}
	if n := (&Resolver{}).Resolve(context.Background(), ws, comps); n != 0 {
		t.Errorf("must not touch a component that already has a SHA1, set %d", n)
	}
	if comps[0].SHA1 != "preexisting" || len(comps[0].Checksums) != 0 {
		t.Errorf("existing SHA1 must survive, got %q / %+v", comps[0].SHA1, comps[0].Checksums)
	}
}

func TestResolveSkipsMissingJarAndNonJar(t *testing.T) {
	ws := t.TempDir()
	writeFile(t, filepath.Join(ws, "present-1.0.jar"), []byte("here"))
	comps := []sbom.Component{
		{Name: "absent", Version: "1.0", Location: "/absent-1.0.jar"},      // no such file
		{Name: "npmpkg", Version: "1.0", Location: "/node_modules/lodash"}, // not a jar
		{Name: "present", Version: "1.0", Location: "/present-1.0.jar"},    // has a jar
	}
	n := (&Resolver{}).Resolve(context.Background(), ws, comps)
	if n != 1 {
		t.Fatalf("only the present jar should be checksummed, got %d", n)
	}
	if comps[0].SHA1 != "" || comps[1].SHA1 != "" {
		t.Error("absent/non-jar components must stay without a SHA1")
	}
	if comps[2].SHA1 == "" {
		t.Error("the present jar's component must get a SHA1")
	}
}

func TestResolveAmbiguousBasenameSkipped(t *testing.T) {
	ws := t.TempDir()
	// Same file name at two paths with DIFFERENT bytes: we can't attribute a component to one, so skip.
	writeFile(t, filepath.Join(ws, "a", "dup-1.0.jar"), []byte("aaa"))
	writeFile(t, filepath.Join(ws, "b", "dup-1.0.jar"), []byte("bbb"))
	comps := []sbom.Component{{Name: "dup", Version: "1.0", Location: "/dup-1.0.jar"}}
	if n := (&Resolver{}).Resolve(context.Background(), ws, comps); n != 0 {
		t.Errorf("an ambiguous jar base name must be skipped (never guessed), set %d", n)
	}
	if comps[0].SHA1 != "" {
		t.Error("ambiguous base name must not set a SHA1")
	}
}

func TestResolveSkipsSymlink(t *testing.T) {
	ws := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret-1.0.jar")
	writeFile(t, outside, []byte("out of tree"))
	link := filepath.Join(ws, "secret-1.0.jar")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	comps := []sbom.Component{{Name: "secret", Version: "1.0", Location: "/secret-1.0.jar"}}
	if n := (&Resolver{}).Resolve(context.Background(), ws, comps); n != 0 {
		t.Errorf("a symlinked jar must NOT be hashed (could point out of the workspace), set %d", n)
	}
}

func TestResolveNoJARComponentsNoWalk(t *testing.T) {
	ws := t.TempDir()
	comps := []sbom.Component{{Name: "npmpkg", Version: "1.0", Location: "/pkg", PURL: "pkg:npm/pkg@1.0"}}
	if n := (&Resolver{}).Resolve(context.Background(), ws, comps); n != 0 {
		t.Errorf("a non-JVM component set must be a no-op, set %d", n)
	}
}
