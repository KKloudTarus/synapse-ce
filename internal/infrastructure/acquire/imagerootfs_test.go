package acquire

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type layerEntry struct {
	name     string
	typ      byte
	body     string
	linkname string
}

func reg(name, body string) layerEntry { return layerEntry{name: name, typ: tar.TypeReg, body: body} }
func dir(name string) layerEntry       { return layerEntry{name: name, typ: tar.TypeDir} }

// addLayer writes a layer tar (gzipped unless raw) as a blob (reusing writeBlob from image_metadata_test.go)
// and returns its digest.
func addLayer(t *testing.T, layoutDir string, gzipped bool, entries []layerEntry) string {
	t.Helper()
	var buf bytes.Buffer
	var tw *tar.Writer
	var gz *gzip.Writer
	if gzipped {
		gz = gzip.NewWriter(&buf)
		tw = tar.NewWriter(gz)
	} else {
		tw = tar.NewWriter(&buf)
	}
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0o644}
		switch e.typ {
		case tar.TypeDir:
			hdr.Mode = 0o755
		case tar.TypeReg:
			hdr.Size = int64(len(e.body))
		case tar.TypeSymlink:
			hdr.Linkname = e.linkname
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if gz != nil {
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return writeBlob(t, layoutDir, buf.Bytes())
}

// finishLayout writes the image manifest (referencing the layers in order) + index.json, with an empty
// diff_ids array (per-layer attribution disabled).
func finishLayout(t *testing.T, layoutDir string, layerDigests []string) {
	t.Helper()
	finishLayoutWithDiffIDs(t, layoutDir, layerDigests, nil)
}

// finishLayoutWithDiffIDs is finishLayout with an explicit rootfs.diff_ids array in the image config, so a
// test can exercise per-layer attribution. The extractor pairs a diff_id to a layer BY INDEX and never hashes
// content, so sentinel diff_ids (e.g. "sha256:layer0") are sufficient.
func finishLayoutWithDiffIDs(t *testing.T, layoutDir string, layerDigests, diffIDs []string) {
	t.Helper()
	var ds strings.Builder
	for i, d := range diffIDs {
		if i > 0 {
			ds.WriteString(",")
		}
		fmt.Fprintf(&ds, "%q", d)
	}
	cfg := writeBlob(t, layoutDir, []byte(fmt.Sprintf(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[%s]}}`, ds.String())))
	var ls strings.Builder
	for i, d := range layerDigests {
		if i > 0 {
			ls.WriteString(",")
		}
		fmt.Fprintf(&ls, `{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":%q}`, d)
	}
	manifest := fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q},"layers":[%s]}`, cfg, ls.String())
	man := writeBlob(t, layoutDir, []byte(manifest))
	index := fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":%q,"platform":{"os":"linux","architecture":"amd64"}}]}`, man)
	if err := os.WriteFile(filepath.Join(layoutDir, "index.json"), []byte(index), 0o644); err != nil {
		t.Fatal(err)
	}
}

func extractToTemp(t *testing.T, layoutDir string) (string, error) {
	t.Helper()
	dest := filepath.Join(t.TempDir(), "rootfs")
	_, err := extractOCIRootFS(context.Background(), layoutDir, dest, MaxWorkspaceBytes)
	return dest, err
}

func mustNotExist(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Errorf("expected %q to be absent, got err=%v", p, err)
	}
}

func mustContain(t *testing.T, p, want string) {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %q: %v", p, err)
	}
	if string(b) != want {
		t.Errorf("%q = %q, want %q", p, string(b), want)
	}
}

func TestExtractOCIRootFSLayeringAndWhiteout(t *testing.T) {
	layout := t.TempDir()
	l1 := addLayer(t, layout, true, []layerEntry{
		dir("etc/"), reg("etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n"),
		dir("app/"), reg("app/a.txt", "old"),
	})
	l2 := addLayer(t, layout, true, []layerEntry{
		reg("app/.wh.a.txt", ""), // whiteout: deletes app/a.txt
		reg("app/b.txt", "new"),
	})
	finishLayout(t, layout, []string{l1, l2})

	dest, err := extractToTemp(t, layout)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	mustContain(t, filepath.Join(dest, "etc/os-release"), "ID=debian\nVERSION_ID=\"12\"\n")
	mustContain(t, filepath.Join(dest, "app/b.txt"), "new")
	mustNotExist(t, filepath.Join(dest, "app/a.txt")) // whiteout must win over the lower layer
}

func TestExtractOCIRootFSOpaqueDir(t *testing.T) {
	layout := t.TempDir()
	l1 := addLayer(t, layout, true, []layerEntry{dir("d/"), reg("d/old.txt", "old")})
	l2 := addLayer(t, layout, true, []layerEntry{reg("d/.wh..wh..opq", ""), reg("d/new.txt", "new")})
	finishLayout(t, layout, []string{l1, l2})

	dest, err := extractToTemp(t, layout)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	mustNotExist(t, filepath.Join(dest, "d/old.txt")) // opaque clears lower-layer contents
	mustContain(t, filepath.Join(dest, "d/new.txt"), "new")
}

func TestExtractOCIRootFSRejectsTraversal(t *testing.T) {
	layout := t.TempDir()
	l1 := addLayer(t, layout, true, []layerEntry{reg("../escape.txt", "x")})
	finishLayout(t, layout, []string{l1})
	if _, err := extractToTemp(t, layout); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("a traversing layer entry must fail with ErrValidation, got %v", err)
	}
}

func TestExtractOCIRootFSSkipsSymlink(t *testing.T) {
	layout := t.TempDir()
	l1 := addLayer(t, layout, true, []layerEntry{
		reg("real.txt", "hi"),
		{name: "link.txt", typ: tar.TypeSymlink, linkname: "/etc/passwd"},
	})
	finishLayout(t, layout, []string{l1})
	dest, err := extractToTemp(t, layout)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	mustContain(t, filepath.Join(dest, "real.txt"), "hi")
	mustNotExist(t, filepath.Join(dest, "link.txt")) // symlink entry skipped (no redirect out of the tree)
}

func TestExtractOCIRootFSUncompressedLayer(t *testing.T) {
	layout := t.TempDir()
	l1 := addLayer(t, layout, false, []layerEntry{reg("etc/os-release", "ID=alpine\n")}) // raw tar, no gzip
	finishLayout(t, layout, []string{l1})
	dest, err := extractToTemp(t, layout)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	mustContain(t, filepath.Join(dest, "etc/os-release"), "ID=alpine\n")
}

func TestExtractOCIRootFSNoLayers(t *testing.T) {
	layout := t.TempDir()
	finishLayout(t, layout, nil)
	if _, err := extractToTemp(t, layout); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("a layout with no layers must fail with ErrValidation, got %v", err)
	}
}

func TestExtractOCIRootFSMissingLayout(t *testing.T) {
	if _, err := extractToTemp(t, t.TempDir()); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("a layout with no index.json must fail with ErrValidation, got %v", err)
	}
}

func TestExtractOCIRootFSRejectsTraversingWhiteout(t *testing.T) {
	layout := t.TempDir()
	// A whiteout whose victim escapes the tree ("../secret") must be rejected, not delete outside dest.
	l1 := addLayer(t, layout, true, []layerEntry{reg("../.wh.secret", "")})
	finishLayout(t, layout, []string{l1})
	if _, err := extractToTemp(t, layout); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("a traversing whiteout must fail with ErrValidation, got %v", err)
	}
}

func TestExtractOCIRootFSWhiteoutRootVictimSkipped(t *testing.T) {
	layout := t.TempDir()
	// A crafted marker ".wh..." trims to victim ".." – not a valid whiteout target. It must be skipped, never
	// deleting the assembled-tree root; the lower-layer file must survive.
	l1 := addLayer(t, layout, true, []layerEntry{reg("keep.txt", "x")})
	l2 := addLayer(t, layout, true, []layerEntry{reg(".wh...", "")})
	finishLayout(t, layout, []string{l1, l2})
	dest, err := extractToTemp(t, layout)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	mustContain(t, filepath.Join(dest, "keep.txt"), "x") // root not wiped
}

func TestExtractOCIRootFSCapsAcrossLayers(t *testing.T) {
	layout := t.TempDir()
	l1 := addLayer(t, layout, true, []layerEntry{reg("a.txt", "aaaaaaaa")}) // 8 bytes
	l2 := addLayer(t, layout, true, []layerEntry{reg("b.txt", "bbbbbbbb")}) // +8 bytes
	finishLayout(t, layout, []string{l1, l2})
	dest := filepath.Join(t.TempDir(), "rootfs")
	// A 10-byte total cap is exceeded only after the SECOND layer, proving the cap accumulates across layers.
	if _, err := extractOCIRootFS(context.Background(), layout, dest, 10); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("the byte cap must be enforced across layers, got %v", err)
	}
}

func TestExtractOCIRootFSUnsupportedCompression(t *testing.T) {
	layout := t.TempDir()
	zstd := writeBlob(t, layout, []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x01, 0x02}) // zstd magic
	finishLayout(t, layout, []string{zstd})
	if _, err := extractToTemp(t, layout); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("a zstd-compressed layer must fail closed with a clear ErrValidation, got %v", err)
	}
}

func TestExtractOCIRootFSFileDirTransition(t *testing.T) {
	// Across layers a path flips kind: "x" is a regular file below and a directory above; "y" is a directory
	// (with a child) below and a regular file above. The colliding entry is replaced and the surviving entry
	// stays under dest (both replacement RemoveAlls are safeJoin-bounded).
	layout := t.TempDir()
	l1 := addLayer(t, layout, true, []layerEntry{reg("x", "file-first"), dir("y/"), reg("y/child", "below")})
	l2 := addLayer(t, layout, true, []layerEntry{dir("x/"), reg("x/now-a-dir", "ok"), reg("y", "now-a-file")})
	finishLayout(t, layout, []string{l1, l2})
	dest, err := extractToTemp(t, layout)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	mustContain(t, filepath.Join(dest, "x/now-a-dir"), "ok") // file -> dir
	// y became a regular file, so the replaced directory and its child are gone (a file has no children).
	mustContain(t, filepath.Join(dest, "y"), "now-a-file") // dir -> file
}

func TestExtractOCIRootFSGarbageBlob(t *testing.T) {
	layout := t.TempDir()
	garbage := writeBlob(t, layout, []byte("this is not a tar or a known compression")) // no known magic
	finishLayout(t, layout, []string{garbage})
	if _, err := extractToTemp(t, layout); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("a non-tar garbage blob must fail closed with ErrValidation, got %v", err)
	}
}

// addZstdLayer writes a zstd-compressed layer tar as a blob (OCI zstd layers, e.g. Wolfi/Chainguard).
func addZstdLayer(t *testing.T, layoutDir string, entries []layerEntry) string {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0o644}
		switch e.typ {
		case tar.TypeDir:
			hdr.Mode = 0o755
		case tar.TypeReg:
			hdr.Size = int64(len(e.body))
		case tar.TypeSymlink:
			hdr.Linkname = e.linkname
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return writeBlob(t, layoutDir, buf.Bytes())
}

func TestExtractOCIRootFSZstdLayer(t *testing.T) {
	layout := t.TempDir()
	// A zstd-compressed layer (magic 28 b5 2f fd) must decompress and extract, not be rejected.
	l1 := addZstdLayer(t, layout, []layerEntry{dir("etc"), reg("etc/os-release", "ID=wolfi\n")})
	finishLayout(t, layout, []string{l1})
	dest, err := extractToTemp(t, layout)
	if err != nil {
		t.Fatalf("extract zstd layer: %v", err)
	}
	mustContain(t, filepath.Join(dest, "etc/os-release"), "ID=wolfi\n")
}

func TestExtractOCIRootFSZstdLayeredOverGzip(t *testing.T) {
	layout := t.TempDir()
	// Mixed-codec image: a gzip base layer with a zstd layer applied on top (both must extract in order).
	base := addLayer(t, layout, true, []layerEntry{reg("app/version", "1.0\n")})
	top := addZstdLayer(t, layout, []layerEntry{reg("app/patch", "applied\n")})
	finishLayout(t, layout, []string{base, top})
	dest, err := extractToTemp(t, layout)
	if err != nil {
		t.Fatalf("extract mixed-codec image: %v", err)
	}
	mustContain(t, filepath.Join(dest, "app/version"), "1.0\n")
	mustContain(t, filepath.Join(dest, "app/patch"), "applied\n")
}

// TestExtractOCIRootFSPerLayerAttribution asserts the extractor maps each materialized file to the diff_id of
// the layer that last wrote it (the squashed view): a base-layer file gets the base diff_id, an upper-layer
// file gets the upper diff_id, and a file rewritten by an upper layer is attributed to that upper layer.
func TestExtractOCIRootFSPerLayerAttribution(t *testing.T) {
	layout := t.TempDir()
	l0 := addLayer(t, layout, true, []layerEntry{
		reg("etc/os-release", "ID=debian\n"),
		reg("app/base.txt", "base"),
	})
	l1 := addLayer(t, layout, true, []layerEntry{
		reg("app/top.txt", "top"),
		reg("app/base.txt", "overwritten"), // an upper layer rewrites base.txt -> attributed to l1
	})
	finishLayoutWithDiffIDs(t, layout, []string{l0, l1}, []string{"sha256:layer0", "sha256:layer1"})

	dest := filepath.Join(t.TempDir(), "rootfs")
	layers, err := extractOCIRootFS(context.Background(), layout, dest, MaxWorkspaceBytes)
	if err != nil {
		t.Fatalf("extractOCIRootFS: %v", err)
	}
	want := map[string]string{
		"etc/os-release": "sha256:layer0",
		"app/top.txt":    "sha256:layer1",
		"app/base.txt":   "sha256:layer1", // last writer wins
	}
	for path, diff := range want {
		if got := layers[path]; got != diff {
			t.Errorf("%s attributed to %q, want %q (map=%v)", path, got, diff, layers)
		}
	}
}

// TestExtractOCIRootFSAttributionDisabledOnMismatch confirms that when the image config's diff_ids count does
// not match the layer count, attribution is disabled (nil map) but extraction still succeeds.
func TestExtractOCIRootFSAttributionDisabledOnMismatch(t *testing.T) {
	layout := t.TempDir()
	l0 := addLayer(t, layout, true, []layerEntry{reg("a.txt", "x")})
	finishLayoutWithDiffIDs(t, layout, []string{l0}, []string{"sha256:layer0", "sha256:extra"}) // 1 layer, 2 diff_ids

	dest := filepath.Join(t.TempDir(), "rootfs")
	layers, err := extractOCIRootFS(context.Background(), layout, dest, MaxWorkspaceBytes)
	if err != nil {
		t.Fatalf("extraction must still succeed with attribution disabled: %v", err)
	}
	if layers != nil {
		t.Errorf("attribution must be disabled (nil map) on a diff_id count mismatch, got %v", layers)
	}
	if _, err := os.Stat(filepath.Join(dest, "a.txt")); err != nil {
		t.Errorf("file must still be extracted: %v", err)
	}
}

// TestExtractOCIRootFSAttributionMatchesImageInfo locks the core join contract: every diff_id the extractor
// records is a diff_id readImageInfo exposes in ImageInfo.Layers, so attributeImageLayers' by-diff join
// resolves. Both derive from the same image config, so they must agree.
func TestExtractOCIRootFSAttributionMatchesImageInfo(t *testing.T) {
	layout := t.TempDir()
	l0 := addLayer(t, layout, true, []layerEntry{reg("etc/os-release", "ID=debian\n")})
	l1 := addLayer(t, layout, true, []layerEntry{reg("app/x.jar", "x")})
	finishLayoutWithDiffIDs(t, layout, []string{l0, l1}, []string{"sha256:layer0", "sha256:layer1"})

	dest := filepath.Join(t.TempDir(), "rootfs")
	layers, err := extractOCIRootFS(context.Background(), layout, dest, MaxWorkspaceBytes)
	if err != nil {
		t.Fatalf("extractOCIRootFS: %v", err)
	}
	info := readImageInfo(layout, "example.com/img:tag")
	if info == nil {
		t.Fatal("readImageInfo returned nil")
	}
	valid := map[string]bool{}
	for _, l := range info.Layers {
		valid[l.DiffID] = true
	}
	if len(layers) == 0 {
		t.Fatal("expected a non-empty attribution map")
	}
	for path, diff := range layers {
		if !valid[diff] {
			t.Errorf("%s attributed to diff_id %q, absent from ImageInfo.Layers %+v", path, diff, info.Layers)
		}
	}
}

// TestExtractOCIRootFSAttributionEmptyDiffIDSkipsLayer confirms a layer with an empty diff_id contributes no
// attribution (its files stay unmapped) while the layer still extracts and other layers attribute normally.
func TestExtractOCIRootFSAttributionEmptyDiffIDSkipsLayer(t *testing.T) {
	layout := t.TempDir()
	l0 := addLayer(t, layout, true, []layerEntry{reg("base.txt", "b")})
	l1 := addLayer(t, layout, true, []layerEntry{reg("top.txt", "t")})
	finishLayoutWithDiffIDs(t, layout, []string{l0, l1}, []string{"", "sha256:layer1"}) // layer0 has no diff_id

	dest := filepath.Join(t.TempDir(), "rootfs")
	layers, err := extractOCIRootFS(context.Background(), layout, dest, MaxWorkspaceBytes)
	if err != nil {
		t.Fatalf("extractOCIRootFS: %v", err)
	}
	if diff, ok := layers["base.txt"]; ok {
		t.Errorf("a file from a layer with an empty diff_id must not be attributed, got %q", diff)
	}
	if layers["top.txt"] != "sha256:layer1" {
		t.Errorf("top.txt should attribute to layer1, got %q", layers["top.txt"])
	}
	if _, err := os.Stat(filepath.Join(dest, "base.txt")); err != nil {
		t.Errorf("base.txt must still be extracted: %v", err)
	}
}
