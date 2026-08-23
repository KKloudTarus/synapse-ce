package releaseevidence

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var testIdentity = Identity{
	Repository:     "KKloudTarus/synapse-ce",
	SourceRevision: strings.Repeat("a", 40),
	Release:        "v1.2.3-rc.1",
}

func TestGenerateIsDeterministicAndVerifyChecksCompleteAssetSet(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	for _, dir := range []string{first, second} {
		writeAsset(t, dir, "synapse-ce_1.2.3_linux_amd64.tar.gz", "binary")
		writeAsset(t, dir, "synapse-ce_1.2.3_linux_amd64.tar.gz.sig", "signature")
		writeAsset(t, dir, "synapse-ce_1.2.3_linux_amd64.tar.gz.sbom.json", `{"bomFormat":"CycloneDX"}`)
		writeAsset(t, dir, "SHA256SUMS", "sum")
	}

	firstPath := filepath.Join(first, DefaultManifest)
	secondPath := filepath.Join(second, DefaultManifest)
	manifest, err := Generate(first, firstPath, testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(second, secondPath, testIdentity); err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := os.ReadFile(firstPath)
	secondJSON, _ := os.ReadFile(secondPath)
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("deterministic manifests differ:\n%s\n%s", firstJSON, secondJSON)
	}
	if len(manifest.Artifacts) != 4 || manifest.Artifacts[0].Name != "SHA256SUMS" {
		t.Fatalf("unexpected sorted inventory: %+v", manifest.Artifacts)
	}
	if _, err := Verify(first, firstPath, testIdentity); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	// A detached signature for the manifest is intentionally outside the
	// manifest to avoid a recursive digest, but it is the only permitted extra.
	writeAsset(t, first, DefaultManifest+".sig", "manifest signature")
	if _, err := Verify(first, firstPath, testIdentity); err != nil {
		t.Fatalf("Verify() with manifest signature error = %v", err)
	}
}

func TestVerifyRejectsTamperedMissingAndUnlistedAssets(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
		want   string
	}{
		{"tampered", func(t *testing.T, dir string) { writeAsset(t, dir, "agent.tar.gz", "changed") }, "integrity"},
		{"missing", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "agent.tar.gz")); err != nil {
				t.Fatal(err)
			}
		}, "asset set mismatch"},
		{"unlisted", func(t *testing.T, dir string) { writeAsset(t, dir, "injected.tar.gz", "bad") }, "asset set mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeAsset(t, dir, "agent.tar.gz", "original")
			path := filepath.Join(dir, DefaultManifest)
			if _, err := Generate(dir, path, testIdentity); err != nil {
				t.Fatal(err)
			}
			tt.mutate(t, dir)
			if _, err := Verify(dir, path, testIdentity); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Verify() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestVerifyRejectsWrongIdentityStrictJSONAndNonCanonicalJSON(t *testing.T) {
	dir := t.TempDir()
	writeAsset(t, dir, "agent.tar.gz", "artifact")
	path := filepath.Join(dir, DefaultManifest)
	if _, err := Generate(dir, path, testIdentity); err != nil {
		t.Fatal(err)
	}

	wrong := testIdentity
	wrong.SourceRevision = strings.Repeat("b", 40)
	if _, err := Verify(dir, path, wrong); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("wrong identity error = %v", err)
	}

	valid, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	unknown := strings.Replace(string(valid), `"schema_version":`, "\"unknown\": true,\n  \"schema_version\":", 1)
	if err := os.WriteFile(path, []byte(unknown), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, path, testIdentity); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field error = %v", err)
	}

	if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(valid), "  ", "    ")), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, path, testIdentity); err == nil || !strings.Contains(err.Error(), "canonically") {
		t.Fatalf("noncanonical error = %v", err)
	}
}

func TestGenerateRejectsUnsafeInputsAndRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	writeAsset(t, dir, "agent.tar.gz", "artifact")
	path := filepath.Join(dir, DefaultManifest)

	badIdentity := testIdentity
	badIdentity.Repository = "https://github.com/KKloudTarus/synapse-ce"
	if _, err := Generate(dir, path, badIdentity); err == nil {
		t.Fatal("Generate() accepted invalid repository")
	}
	if _, err := Generate(dir, filepath.Join(dir, "nested", DefaultManifest), testIdentity); err == nil {
		t.Fatal("Generate() accepted output outside the asset directory")
	}
	if _, err := Generate(dir, path, testIdentity); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(dir, path, testIdentity); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("overwrite error = %v", err)
	}
}

func TestGenerateRejectsSymlinkAssets(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "outside.tar.gz")
	if err := os.WriteFile(target, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "agent.tar.gz")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := Generate(dir, filepath.Join(dir, DefaultManifest), testIdentity); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink error = %v", err)
	}
}

func TestValidateManifestRejectsDuplicateUnsortedAndMisclassifiedEntries(t *testing.T) {
	base := Artifact{Name: "agent.tar.gz", Kind: KindArtifact, SHA256: strings.Repeat("0", 64), Size: 1}
	tests := []struct {
		name      string
		artifacts []Artifact
		want      string
	}{
		{"duplicate", []Artifact{base, base}, "unique names"},
		{"unsorted", []Artifact{{Name: "z.tar.gz", Kind: KindArtifact, SHA256: strings.Repeat("0", 64)}, base}, "lexical order"},
		{"misclassified", []Artifact{{Name: "agent.sig", Kind: KindArtifact, SHA256: strings.Repeat("0", 64)}}, "expected"},
		{"no-primary", []Artifact{{Name: "SHA256SUMS", Kind: KindChecksum, SHA256: strings.Repeat("0", 64)}}, "no primary"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := Manifest{SchemaVersion: SchemaVersion, Identity: testIdentity, Artifacts: tt.artifacts}
			if err := validateManifest(manifest); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateManifest() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func writeAsset(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
