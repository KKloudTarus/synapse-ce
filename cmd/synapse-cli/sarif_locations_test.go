package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func writeManifest(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("<project/>"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A dependency result points at the manifest that declares it by a path relative to the scanned directory,
// the way secret and SAST results already do. The owned SBOM producer records the manifest's absolute path,
// which a code-scanning service cannot match against the repository and which also differs between runners.
func TestManifestPathUnderRoot(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, filepath.Join(root, "svc", "pom.xml"))
	elsewhere := t.TempDir()
	writeManifest(t, filepath.Join(elsewhere, "pom.xml"))

	tests := []struct {
		name     string
		location string
		want     string
	}{
		{"absolute path under the scanned directory", filepath.Join(root, "svc", "pom.xml"), "svc/pom.xml"},
		// Syft roots a directory scan's paths at the scanned directory with a leading slash.
		{"workspace-rooted path of a file that is there", "/svc/pom.xml", "svc/pom.xml"},
		{"relative path of a file that is there", filepath.Join("svc", "pom.xml"), "svc/pom.xml"},
		// Never passed off as a repository path: these are the cases that produced private/tmp/... before.
		{"absolute path outside the scanned directory", filepath.Join(elsewhere, "pom.xml"), ""},
		{"workspace-rooted path of a file that is not there", "/private/tmp/build/pom.xml", ""},
		{"traversal out of the scanned directory", filepath.Join(root, "..", filepath.Base(elsewhere), "pom.xml"), ""},
		{"relative traversal", filepath.Join("..", filepath.Base(elsewhere), "pom.xml"), ""},
		{"the scanned directory itself", root, ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := manifestPathUnderRoot(root, tt.location)
			if got != tt.want || ok != (tt.want != "") {
				t.Errorf("manifestPathUnderRoot(%q, %q) = %q, %v; want %q, %v", root, tt.location, got, ok, tt.want, tt.want != "")
			}
		})
	}
}

// On macOS /tmp is a symlink to /private/tmp, so the directory a user names and the path the producer
// records can differ by that link while naming the same file.
func TestManifestPathUnderRootThroughASymlinkedRoot(t *testing.T) {
	real := t.TempDir()
	writeManifest(t, filepath.Join(real, "pom.xml"))
	link := filepath.Join(t.TempDir(), "checkout")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	for _, location := range []string{filepath.Join(real, "pom.xml"), filepath.Join(resolved, "pom.xml"), filepath.Join(link, "pom.xml")} {
		if got, ok := manifestPathUnderRoot(link, location); !ok || got != "pom.xml" {
			t.Errorf("manifestPathUnderRoot(%q, %q) = %q, %v; want pom.xml", link, location, got, ok)
		}
	}
}

func TestSARIFManifestPaths(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, filepath.Join(root, "svc", "pom.xml"))
	components := []sbom.Component{
		{Name: "junit:junit", Version: "4.12", Location: filepath.Join(root, "svc", "pom.xml")},
		{Name: "org.example:outside", Version: "1.0", Location: filepath.Join(t.TempDir(), "pom.xml")},
		{Name: "org.example:nowhere", Version: "1.0"},
	}
	got := sarifManifestPaths(root, components)
	if got["junit:junit@4.12"] != "svc/pom.xml" {
		t.Errorf("junit manifest = %q, want svc/pom.xml", got["junit:junit@4.12"])
	}
	for _, key := range []string{"org.example:outside@1.0", "org.example:nowhere@1.0"} {
		if path, ok := got[key]; ok {
			t.Errorf("%s resolved to %q, want no manifest path", key, path)
		}
	}
}
