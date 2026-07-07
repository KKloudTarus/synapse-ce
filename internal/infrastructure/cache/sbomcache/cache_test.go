package sbomcache

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func sampleSBOM() *sbom.SBOM {
	return &sbom.SBOM{
		ID: "s1", Source: "syft", GeneratorVersion: "1.45.1",
		Components: []sbom.Component{{Name: "lodash", Version: "4.0.0", PURL: "pkg:npm/lodash@4.0.0"}},
		Raw:        []byte(`{"bomFormat":"CycloneDX"}`),
	}
}

func TestStoreLoadRoundTripPreservesRaw(t *testing.T) {
	ws := t.TempDir()
	write(t, ws, "go.mod", "module x\n")
	c := New(t.TempDir())
	ctx := context.Background()

	if err := c.Store(ctx, ws, "syft-1.45.1", sampleSBOM()); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, ok, err := c.Load(ctx, ws, "syft-1.45.1")
	if err != nil || !ok {
		t.Fatalf("want a cache hit, got ok=%v err=%v", ok, err)
	}
	if len(got.Components) != 1 || got.Components[0].Name != "lodash" {
		t.Errorf("components not round-tripped: %+v", got.Components)
	}
	// Raw is json:"-" on the domain type; the cache MUST preserve it so a hit still gives Grype the exact SBOM.
	if string(got.Raw) != `{"bomFormat":"CycloneDX"}` {
		t.Errorf("Raw not preserved: %q", string(got.Raw))
	}
	// Whole-graph guard: a cache hit must be behaviorally identical to a fresh generate, or detection could
	// silently differ. This deep-equal fails loudly if a future SBOM field is added with json:"-" (like Raw)
	// or as an unexported field and is NOT taught to the cache envelope.
	if !reflect.DeepEqual(sampleSBOM(), got) {
		t.Errorf("cache hit is not deep-equal to the original SBOM:\n orig=%+v\n  got=%+v", sampleSBOM(), got)
	}
}

func TestProducerVersionChangeInvalidates(t *testing.T) {
	ws := t.TempDir()
	write(t, ws, "go.mod", "module x\n")
	c := New(t.TempDir())
	ctx := context.Background()
	_ = c.Store(ctx, ws, "syft-1.45.1", sampleSBOM())

	if _, ok, _ := c.Load(ctx, ws, "syft-1.46.0"); ok {
		t.Error("a producer version bump must invalidate the entry (cache miss)")
	}
	if _, ok, _ := c.Load(ctx, ws, "syft-1.45.1"); !ok {
		t.Error("the same producer version must still hit")
	}
}

func TestContentChangeInvalidates(t *testing.T) {
	ws := t.TempDir()
	write(t, ws, "go.mod", "module x\n")
	c := New(t.TempDir())
	ctx := context.Background()
	_ = c.Store(ctx, ws, "v1", sampleSBOM())

	// Change a file's content (and thus size + mtime) → the metadata digest changes → miss.
	time.Sleep(2 * time.Millisecond)
	write(t, ws, "go.mod", "module x\nrequire y v1.0.0\n")
	if _, ok, _ := c.Load(ctx, ws, "v1"); ok {
		t.Error("a changed workspace must invalidate the entry (cache miss)")
	}
}

func TestEmptyProducerVersionNeverCaches(t *testing.T) {
	ws := t.TempDir()
	write(t, ws, "go.mod", "module x\n")
	c := New(t.TempDir())
	ctx := context.Background()

	if err := c.Store(ctx, ws, "", sampleSBOM()); err != nil {
		t.Fatalf("Store with empty version must be a no-op, got %v", err)
	}
	if _, ok, _ := c.Load(ctx, ws, ""); ok {
		t.Error("an unversioned entry must never be served")
	}
}

func TestLoadMissOnAbsent(t *testing.T) {
	ws := t.TempDir()
	write(t, ws, "go.mod", "module x\n")
	if _, ok, err := New(t.TempDir()).Load(context.Background(), ws, "v1"); ok || err != nil {
		t.Errorf("a never-stored workspace must miss cleanly, ok=%v err=%v", ok, err)
	}
}

func TestSymlinkNotFollowed(t *testing.T) {
	ws := t.TempDir()
	write(t, ws, "go.mod", "module x\n")
	// A symlink to an out-of-tree file must be skipped by the digest walk (never followed), not fatal.
	outside := filepath.Join(t.TempDir(), "secret")
	_ = os.WriteFile(outside, []byte("x"), 0o644)
	if err := os.Symlink(outside, filepath.Join(ws, "link")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	c := New(t.TempDir())
	ctx := context.Background()
	if err := c.Store(ctx, ws, "v1", sampleSBOM()); err != nil {
		t.Fatalf("Store with a symlink present must succeed: %v", err)
	}
	if _, ok, _ := c.Load(ctx, ws, "v1"); !ok {
		t.Error("digest must compute (symlink skipped) and hit")
	}
}

func TestCancelledContextMisses(t *testing.T) {
	ws := t.TempDir()
	write(t, ws, "go.mod", "module x\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A cancelled context yields an uncomputable digest → a clean miss, never a panic or error.
	if _, ok, err := New(t.TempDir()).Load(ctx, ws, "v1"); ok || err != nil {
		t.Errorf("cancelled Load must miss cleanly, ok=%v err=%v", ok, err)
	}
}
