package scabench

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func TestTrustedInputArchiveRoundTripsFilesTreesEmptyDirectoriesAndModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not preserve POSIX executable modes")
	}
	root, catalog, spec, store := trustedInputArchiveFixture(t)
	beforeTree, err := HashTree(filepath.Join(root, "databases", "tree"))
	if err != nil {
		t.Fatal(err)
	}
	archive, err := CollectTrustedInputArchive(context.Background(), catalog, spec, root, store)
	if err != nil {
		t.Fatalf("CollectTrustedInputArchive() error = %v", err)
	}
	if err := archive.ValidateForCatalog(catalog, spec); err != nil {
		t.Fatalf("archive validation error = %v", err)
	}
	if got, want := archive.RootManifestDigest, "sha256:"; !strings.HasPrefix(got, want) {
		t.Fatalf("root manifest digest = %q, want sha256", got)
	}
	if afterTree, err := HashTree(filepath.Join(root, "databases", "tree")); err != nil || afterTree != beforeTree {
		t.Fatalf("HashTree changed from %q to %q, error %v", beforeTree, afterTree, err)
	}

	destination := t.TempDir()
	if err := RestoreTrustedInputArchive(context.Background(), catalog, spec, archive, destination, store); err != nil {
		t.Fatalf("RestoreTrustedInputArchive() error = %v", err)
	}
	for _, locator := range []string{
		"databases/tree/empty",
		"databases/tree/nested",
		"evidence-assets/environment",
	} {
		info, err := os.Stat(filepath.Join(destination, filepath.FromSlash(locator)))
		if err != nil || !info.IsDir() {
			t.Fatalf("restored directory %q info = %v, err = %v", locator, info, err)
		}
	}
	engine, err := os.ReadFile(filepath.Join(destination, "tools", "engine"))
	if err != nil || string(engine) != "derived executable\n" {
		t.Fatalf("restored executable = %q, err = %v", engine, err)
	}
	info, err := os.Stat(filepath.Join(destination, "tools", "engine"))
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("restored executable mode = %v, err = %v, want 0755", info.Mode(), err)
	}
	afterTree, err := HashTree(filepath.Join(destination, "databases", "tree"))
	if err != nil || afterTree != beforeTree {
		t.Fatalf("restored tree digest = %q, error = %v, want %q", afterTree, err, beforeTree)
	}
}

func TestTrustedInputArchiveRejectsCorruptLengthAndUnsafeModeObjects(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not preserve POSIX archive modes")
	}
	root, catalog, spec, store := trustedInputArchiveFixture(t)
	archive, err := CollectTrustedInputArchive(context.Background(), catalog, spec, root, store)
	if err != nil {
		t.Fatal(err)
	}
	file := trustedInputArchiveFile(t, archive, "tools/engine")

	t.Run("corrupt object", func(t *testing.T) {
		blob := filepath.Join(store.root, "blobs", strings.TrimPrefix(file.ObjectDigest, "sha256:"))
		if err := os.Chmod(blob, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(blob, []byte(strings.Repeat("x", int(file.Bytes))), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := RestoreTrustedInputArchive(context.Background(), catalog, spec, archive, t.TempDir(), store); err == nil || !strings.Contains(err.Error(), "corrupt") {
			t.Fatalf("RestoreTrustedInputArchive() error = %v, want corruption failure", err)
		}
	})

	// Rebuild the fixture after deliberately corrupting its private store.
	root, catalog, spec, store = trustedInputArchiveFixture(t)
	archive, err = CollectTrustedInputArchive(context.Background(), catalog, spec, root, store)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("manifest length", func(t *testing.T) {
		candidate := cloneTrustedInputArchive(archive)
		for index := range candidate.Inventory {
			if candidate.Inventory[index].Kind == bench.TrustedInputInventoryFile {
				candidate.Inventory[index].Bytes++
				break
			}
		}
		redigestTrustedInputArchive(t, &candidate)
		if err := RestoreTrustedInputArchive(context.Background(), catalog, spec, candidate, t.TempDir(), store); err == nil || !strings.Contains(err.Error(), "length") {
			t.Fatalf("RestoreTrustedInputArchive() error = %v, want length failure", err)
		}
	})
	t.Run("unsafe mode", func(t *testing.T) {
		candidate := cloneTrustedInputArchive(archive)
		candidate.Inventory[0].Mode = 0o1000
		if err := RestoreTrustedInputArchive(context.Background(), catalog, spec, candidate, t.TempDir(), store); err == nil || !strings.Contains(err.Error(), "unsafe mode") {
			t.Fatalf("RestoreTrustedInputArchive() error = %v, want mode failure", err)
		}
	})
}

func TestTrustedInputArchiveRejectsNonemptyTraversalDuplicateAndSymlinkedDestinations(t *testing.T) {
	root, catalog, spec, store := trustedInputArchiveFixture(t)
	archive, err := CollectTrustedInputArchive(context.Background(), catalog, spec, root, store)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("nonempty destination", func(t *testing.T) {
		destination := t.TempDir()
		if err := os.WriteFile(filepath.Join(destination, "present"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := RestoreTrustedInputArchive(context.Background(), catalog, spec, archive, destination, store); err == nil || !strings.Contains(err.Error(), "empty") {
			t.Fatalf("RestoreTrustedInputArchive() error = %v, want nonempty failure", err)
		}
	})
	t.Run("relative destination", func(t *testing.T) {
		if err := RestoreTrustedInputArchive(context.Background(), catalog, spec, archive, "relative-destination", store); err == nil || !strings.Contains(err.Error(), "absolute") {
			t.Fatalf("RestoreTrustedInputArchive() error = %v, want absolute-root failure", err)
		}
	})
	t.Run("traversal path", func(t *testing.T) {
		candidate := cloneTrustedInputArchive(archive)
		candidate.Inventory[0].Locator = "../outside"
		if err := RestoreTrustedInputArchive(context.Background(), catalog, spec, candidate, t.TempDir(), store); err == nil || !strings.Contains(err.Error(), "safe root-relative") {
			t.Fatalf("RestoreTrustedInputArchive() error = %v, want traversal failure", err)
		}
	})
	t.Run("absolute path", func(t *testing.T) {
		candidate := cloneTrustedInputArchive(archive)
		candidate.Inventory[0].Locator = "/outside"
		if err := RestoreTrustedInputArchive(context.Background(), catalog, spec, candidate, t.TempDir(), store); err == nil || !strings.Contains(err.Error(), "safe root-relative") {
			t.Fatalf("RestoreTrustedInputArchive() error = %v, want absolute-path failure", err)
		}
	})
	t.Run("duplicate path", func(t *testing.T) {
		candidate := cloneTrustedInputArchive(archive)
		candidate.Inventory = append(candidate.Inventory, candidate.Inventory[len(candidate.Inventory)-1])
		sort.Slice(candidate.Inventory, func(left, right int) bool {
			return candidate.Inventory[left].Locator < candidate.Inventory[right].Locator
		})
		if err := RestoreTrustedInputArchive(context.Background(), catalog, spec, candidate, t.TempDir(), store); err == nil {
			t.Fatal("duplicate inventory must be rejected")
		}
	})
	t.Run("symlinked root", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("creating symlinks requires additional Windows privileges")
		}
		link := filepath.Join(t.TempDir(), "destination")
		if err := os.Symlink(t.TempDir(), link); err != nil {
			t.Fatal(err)
		}
		if err := RestoreTrustedInputArchive(context.Background(), catalog, spec, archive, link, store); err == nil || !strings.Contains(err.Error(), "real directory") {
			t.Fatalf("RestoreTrustedInputArchive() error = %v, want symlinked-root failure", err)
		}
	})
	t.Run("symlinked parent", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("creating symlinks requires additional Windows privileges")
		}
		destination := t.TempDir()
		if err := os.Symlink(t.TempDir(), filepath.Join(destination, "tools")); err != nil {
			t.Fatal(err)
		}
		if err := RestoreTrustedInputArchive(context.Background(), catalog, spec, archive, destination, store); err == nil {
			t.Fatal("symlinked destination member must be rejected")
		}
	})
}

func TestTrustedInputArchiveCollectorRejectsSymlinksSpecialFilesAndLimits(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Run("symlink", func(t *testing.T) {
			root, catalog, spec, store := trustedInputArchiveFixture(t)
			if err := os.Symlink(filepath.Join(root, "tools", "engine"), filepath.Join(root, "link")); err != nil {
				t.Fatal(err)
			}
			if _, err := CollectTrustedInputArchive(context.Background(), catalog, spec, root, store); err == nil || !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("CollectTrustedInputArchive() error = %v, want symlink failure", err)
			}
		})
	}
	t.Run("depth", func(t *testing.T) {
		root := t.TempDir()
		current := root
		for index := 0; index <= bench.MaxTrustedInputArchiveDepth; index++ {
			current = filepath.Join(current, "x")
			if err := os.Mkdir(current, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := inventoryTrustedInputRoot(context.Background(), root, nil); err == nil || !strings.Contains(err.Error(), "maximum depth") {
			t.Fatalf("inventoryTrustedInputRoot() error = %v, want depth failure", err)
		}
	})
	t.Run("member and aggregate bounds", func(t *testing.T) {
		state := trustedInputInventoryState{entries: make([]bench.TrustedInputInventoryEntry, bench.MaxTrustedInputArchiveEntries)}
		if err := state.add(bench.TrustedInputInventoryEntry{Locator: "one", Kind: bench.TrustedInputInventoryDirectory, Mode: 0o700}); err == nil {
			t.Fatal("member bound must reject an additional inventory entry")
		}
		state = trustedInputInventoryState{bytes: bench.MaxTrustedInputArchiveBytes}
		if err := state.add(bench.TrustedInputInventoryEntry{Locator: "one", Kind: bench.TrustedInputInventoryFile, ObjectDigest: digestOf([]byte("x")), Bytes: 1, Mode: 0o600}); err == nil {
			t.Fatal("aggregate bound must reject an additional byte")
		}
	})
}

func TestTrustedInputArchiveRejectsMissingAndOrphanBindings(t *testing.T) {
	root, catalog, spec, store := trustedInputArchiveFixture(t)
	missing := cloneTrustedInputBindingSpecForInfra(spec)
	missing.Bindings = missing.Bindings[1:]
	if _, err := CollectTrustedInputArchive(context.Background(), catalog, missing, root, store); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("CollectTrustedInputArchive() error = %v, want missing-binding failure", err)
	}
	orphan := cloneTrustedInputBindingSpecForInfra(spec)
	orphan.Bindings[0].Reference = "binary:orphan"
	if _, err := CollectTrustedInputArchive(context.Background(), catalog, orphan, root, store); err == nil || !strings.Contains(err.Error(), "orphaned") {
		t.Fatalf("CollectTrustedInputArchive() error = %v, want orphan-binding failure", err)
	}
}

func trustedInputArchiveFixture(t *testing.T) (string, bench.Catalog, bench.TrustedInputBindingSpec, *PinArchiveStore) {
	t.Helper()
	root := t.TempDir()
	writeTrustedInputFixtureFile(t, root, "tools/engine", []byte("derived executable\n"), 0o755)
	writeTrustedInputFixtureFile(t, root, "databases/tree/nested/data.txt", []byte("tree payload\n"), 0o644)
	if err := os.MkdirAll(filepath.Join(root, "databases", "tree", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTrustedInputFixtureFile(t, root, "evidence-assets/environment/attestation.json", []byte("{}\n"), 0o600)

	fileDigest, _, err := digestTrustedInputFile(filepath.Join(root, "tools", "engine"))
	if err != nil {
		t.Fatal(err)
	}
	treeDigest, err := HashTree(filepath.Join(root, "databases", "tree"))
	if err != nil {
		t.Fatal(err)
	}
	catalog := trustedInputFixtureCatalog(t, fileDigest, treeDigest)
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	spec := bench.TrustedInputBindingSpec{
		SchemaVersion:   bench.TrustedInputBindingSpecSchemaVersion,
		CatalogRevision: catalog.Revision,
		CatalogDigest:   catalogDigest,
		Bindings: []bench.TrustedInputPinBinding{
			{Reference: "binary:derived", Locator: "tools/engine", Kind: bench.TrustedInputPinFile, PinDigest: fileDigest},
			{Reference: "database:derived", Locator: "databases/tree", Kind: bench.TrustedInputPinTree, PinDigest: treeDigest},
		},
	}
	if err := spec.Validate(catalog); err != nil {
		t.Fatal(err)
	}
	return root, catalog, spec, newStore(t)
}

func trustedInputFixtureCatalog(t *testing.T, fileDigest, treeDigest string) bench.Catalog {
	t.Helper()
	file, err := os.Open(filepath.Join("..", "..", "usecase", "scabench", "corpus", "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	catalog, err := bench.DecodeCatalog(file)
	if err != nil {
		t.Fatal(err)
	}
	catalog.Revision = "trusted-input-fixture"
	catalog.Pins = []bench.ArtifactPin{
		{Reference: "binary:derived", Digest: fileDigest, Origin: "https://example.invalid/derived"},
		{Reference: "database:derived", Digest: treeDigest, Origin: "https://example.invalid/database"},
	}
	if err := catalog.Validate(); err != nil {
		t.Fatal(err)
	}
	return catalog
}

func writeTrustedInputFixtureFile(t *testing.T, root, locator string, data []byte, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(locator))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func trustedInputArchiveFile(t *testing.T, archive bench.TrustedInputArchive, locator string) bench.TrustedInputInventoryEntry {
	t.Helper()
	for _, entry := range archive.Inventory {
		if entry.Locator == locator {
			return entry
		}
	}
	t.Fatalf("archive does not contain %q", locator)
	return bench.TrustedInputInventoryEntry{}
}

func cloneTrustedInputArchive(archive bench.TrustedInputArchive) bench.TrustedInputArchive {
	copy := archive
	copy.Bindings = append([]bench.TrustedInputPinBinding(nil), archive.Bindings...)
	copy.Inventory = append([]bench.TrustedInputInventoryEntry(nil), archive.Inventory...)
	return copy
}

func redigestTrustedInputArchive(t *testing.T, archive *bench.TrustedInputArchive) {
	t.Helper()
	digest, err := bench.DigestTrustedInputArchiveRootManifest(*archive)
	if err != nil {
		t.Fatal(err)
	}
	archive.RootManifestDigest = digest
}

func cloneTrustedInputBindingSpecForInfra(spec bench.TrustedInputBindingSpec) bench.TrustedInputBindingSpec {
	copy := spec
	copy.Bindings = append([]bench.TrustedInputPinBinding(nil), spec.Bindings...)
	return copy
}
