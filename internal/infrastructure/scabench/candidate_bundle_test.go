package scabench

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func TestRestoreCandidateBundleReplacesAttestationInReadOnlyDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("archive directory modes require POSIX permissions")
	}
	bundle, currentAttestation := candidateBundleFixture(t)
	captureRoot := t.TempDir()
	if err := restoreCandidateBundle(context.Background(), bundle, currentAttestation, captureRoot); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(captureRoot, "evidence-assets", "environment"), 0o700)
	})
	attestation := filepath.Join(captureRoot, filepath.FromSlash(trustedEnvironmentAttestationLocator))
	body, err := os.ReadFile(attestation)
	if err != nil || string(body) != "current host\n" {
		t.Fatalf("restored attestation = %q, error %v", body, err)
	}
	parent, err := os.Stat(filepath.Dir(attestation))
	if err != nil || parent.Mode().Perm() != 0o555 {
		t.Fatalf("restored attestation directory mode = %v, error %v", parent.Mode(), err)
	}
	tool, err := os.ReadFile(filepath.Join(captureRoot, "tools", "engine"))
	if err != nil || string(tool) != "derived executable\n" {
		t.Fatalf("restored pinned tool = %q, error %v", tool, err)
	}
}

func TestRestoreCandidateBundleRejectsCorruptObjectAndKeepsSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("archive directory modes require POSIX permissions")
	}
	bundle, currentAttestation := candidateBundleFixture(t)
	manifest := filepath.Join(bundle, "input-archive.json")
	before, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := bench.DecodeTrustedInputArchive(strings.NewReader(string(before)))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range archive.Inventory {
		if entry.Locator == "tools/engine" {
			blob := filepath.Join(bundle, "input-cas", "blobs", strings.TrimPrefix(entry.ObjectDigest, "sha256:"))
			if err := os.Chmod(blob, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(blob, []byte("busted executable\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if err := restoreCandidateBundle(context.Background(), bundle, currentAttestation, t.TempDir()); err == nil {
		t.Fatal("corrupted bundle was accepted")
	}
	after, err := os.ReadFile(manifest)
	if err != nil || string(after) != string(before) {
		t.Fatalf("source manifest changed during restore: %v", err)
	}
}

func candidateBundleFixture(t *testing.T) (string, string) {
	t.Helper()
	inputRoot, catalog, spec, _ := trustedInputArchiveFixture(t)
	writeTrustedInputFixtureFile(t, inputRoot, trustedEnvironmentAttestationLocator, []byte("archived host\n"), 0o600)
	if err := os.Chmod(filepath.Join(inputRoot, "evidence-assets", "environment"), 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(inputRoot, "evidence-assets", "environment"), 0o700)
	})
	bundle := filepath.Join(t.TempDir(), "bundle")
	corpus := filepath.Join(bundle, "candidate-corpus")
	if err := os.MkdirAll(corpus, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewPinArchiveStore(filepath.Join(bundle, "input-cas"))
	if err != nil {
		t.Fatal(err)
	}
	archive, err := CollectTrustedInputArchive(context.Background(), catalog, spec, inputRoot, store)
	if err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string]any{
		filepath.Join(corpus, "catalog.json"):                catalog,
		filepath.Join(corpus, "trusted-input-bindings.json"): spec,
	} {
		body, err := bench.CanonicalJSON(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := bench.EncodeTrustedInputArchive(archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "input-archive.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(t.TempDir(), "current-attestation.json")
	if err := os.WriteFile(current, []byte("current host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return bundle, current
}
