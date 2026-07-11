package acquire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeBlob writes content to <layout>/blobs/sha256/<sha256(content)> and returns
// the "sha256:<hex>" digest – mimicking how crane lays out an OCI image.
func writeBlob(t *testing.T, layout string, content []byte) string {
	t.Helper()
	sum := sha256.Sum256(content)
	hexsum := hex.EncodeToString(sum[:])
	dir := filepath.Join(layout, "blobs", "sha256")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, hexsum), content, 0o644); err != nil {
		t.Fatal(err)
	}
	return "sha256:" + hexsum
}

func TestReadImageInfo(t *testing.T) {
	layout := t.TempDir()

	config := map[string]any{
		"architecture": "amd64",
		"os":           "linux",
		"rootfs":       map[string]any{"diff_ids": []string{"sha256:layer0", "sha256:layer1"}},
		"history": []map[string]any{
			{"created_by": "/bin/sh -c #(nop) ADD file:... in /", "created": "2024-01-01T00:00:00Z"},
			{"created_by": "ENV PATH=/usr/bin", "empty_layer": true}, // metadata-only: skipped
			{"created_by": "/bin/sh -c apt-get install -y openssl"},
		},
	}
	cfgBytes, _ := json.Marshal(config)
	cfgDigest := writeBlob(t, layout, cfgBytes)

	manifest := map[string]any{"config": map[string]any{"digest": cfgDigest}}
	manBytes, _ := json.Marshal(manifest)
	manDigest := writeBlob(t, layout, manBytes)

	index := map[string]any{"manifests": []map[string]any{
		{"digest": manDigest, "platform": map[string]any{"os": "linux", "architecture": "amd64"}},
	}}
	idxBytes, _ := json.Marshal(index)
	if err := os.WriteFile(filepath.Join(layout, "index.json"), idxBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	info := readImageInfo(layout, "debian:9")
	if info == nil {
		t.Fatal("readImageInfo returned nil")
	}
	if info.Reference != "debian:9" || info.OS != "linux" || info.Architecture != "amd64" {
		t.Errorf("metadata = %+v", info)
	}
	if info.Digest != manDigest {
		t.Errorf("Digest = %q, want %q", info.Digest, manDigest)
	}
	// Two filesystem layers; the empty_layer ENV entry is skipped, so created_by pairs correctly.
	if len(info.Layers) != 2 {
		t.Fatalf("want 2 layers, got %d: %+v", len(info.Layers), info.Layers)
	}
	if info.Layers[0].DiffID != "sha256:layer0" || info.Layers[0].Index != 0 {
		t.Errorf("layer 0 = %+v", info.Layers[0])
	}
	if info.Layers[1].DiffID != "sha256:layer1" || info.Layers[1].CreatedBy != "/bin/sh -c apt-get install -y openssl" {
		t.Errorf("layer 1 = %+v (empty_layer entry must be skipped so commands pair to diff_ids)", info.Layers[1])
	}
}

func TestReadImageInfoMissing(t *testing.T) {
	// No index.json → best-effort nil, never panics (degrades, scan continues).
	if info := readImageInfo(t.TempDir(), "x"); info != nil {
		t.Errorf("want nil for missing layout, got %+v", info)
	}
}

func TestReadBlobJSONRejectsTraversal(t *testing.T) {
	layout := t.TempDir()
	// A digest whose "hex" contains path separators / dots must be rejected, so a malicious
	// image manifest cannot make us read outside the blobs directory.
	for _, bad := range []string{"sha256:../../etc/passwd", "sha256:..", "../x", "sha256:", ":abc", "sha256:a/b"} {
		if _, ok := readBlobJSON[ociConfig](layout, bad); ok {
			t.Errorf("readBlobJSON accepted unsafe digest %q", bad)
		}
	}
}
