package sca

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/cache/sbomcache"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownadvisory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownsbom"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/syft"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Run offline with two genuine Syft release executables, the first pinned to v1.45.1:
// SYNAPSE_PRODUCER_CACHE_INTEGRATION=1 SYNAPSE_TEST_SYFT_PINNED=/absolute/path/to/syft-1.45.1 \
//   SYNAPSE_TEST_SYFT_OTHER=/absolute/path/to/another-release/syft \
//   go test ./internal/usecase/sca -run '^TestRealProducerCacheAcceptance$' -count=1 -v
// The other release must report a distinct version in its CycloneDX output. Configuring
// either path or opting in requires both paths; invalid binaries fail rather than skip.

type countedRealProducer struct {
	generator ports.SBOMGenerator
	identity  ports.SBOMProducerIdentity
	calls     int
}

func (p *countedRealProducer) Generate(ctx context.Context, dir string) (*sbom.SBOM, error) {
	p.calls++
	return p.generator.Generate(ctx, dir)
}

func (p *countedRealProducer) SBOMProducerIdentity(ctx context.Context, dir string) (string, bool, error) {
	return p.identity.SBOMProducerIdentity(ctx, dir)
}

type observedRealCache struct {
	cache               ports.SBOMCache
	loads, hits, stores int
	errs                []error
}

func (c *observedRealCache) Load(ctx context.Context, dir, identity string) (*sbom.SBOM, bool, error) {
	c.loads++
	doc, hit, err := c.cache.Load(ctx, dir, identity)
	if hit {
		c.hits++
	}
	if err != nil {
		c.errs = append(c.errs, err)
	}
	return doc, hit, err
}

func (c *observedRealCache) Store(ctx context.Context, dir, identity string, doc *sbom.SBOM) error {
	c.stores++
	err := c.cache.Store(ctx, dir, identity, doc)
	if err != nil {
		c.errs = append(c.errs, err)
	}
	return err
}

func TestRealProducerCacheAcceptance(t *testing.T) {
	pinned, other := os.Getenv("SYNAPSE_TEST_SYFT_PINNED"), os.Getenv("SYNAPSE_TEST_SYFT_OTHER")
	if os.Getenv("SYNAPSE_PRODUCER_CACHE_INTEGRATION") != "1" && pinned == "" && other == "" {
		t.Skip("set SYNAPSE_PRODUCER_CACHE_INTEGRATION=1 and both Syft binary paths")
	}
	if pinned == "" || other == "" || !filepath.IsAbs(pinned) || !filepath.IsAbs(other) {
		t.Fatal("both SYNAPSE_TEST_SYFT_PINNED and SYNAPSE_TEST_SYFT_OTHER must be absolute executable paths")
	}
	t.Setenv("SYFT_CHECK_FOR_APP_UPDATE", "false")
	ctx := context.Background()
	workspace := t.TempDir()
	for _, path := range []string{pinned, other} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat configured Syft executable %q: %v", path, err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			t.Fatalf("configured Syft path %q is not an executable regular file", path)
		}
	}
	lock := `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"lodash":"^4"}},"node_modules/lodash":{"version":"4.17.0"}}}`
	if err := os.WriteFile(filepath.Join(workspace, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	// Use a private copy so the unavailable-executable case never mutates the supplied binary.
	in, err := os.Open(pinned)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	privatePinned := filepath.Join(t.TempDir(), "syft")
	out, err := os.OpenFile(privatePinned, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		t.Fatal(copyErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}

	registry, err := ownsbom.DefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	owned := &countedRealProducer{generator: registry, identity: registry}
	pinnedGenerator := syft.New(privatePinned)
	firstSyft := &countedRealProducer{generator: pinnedGenerator, identity: pinnedGenerator}
	otherGenerator := syft.New(other)
	secondSyft := &countedRealProducer{generator: otherGenerator, identity: otherGenerator}
	cache := &observedRealCache{cache: sbomcache.New(t.TempDir())}
	store := memory.NewAdvisoryStore()
	service := func(producer *countedRealProducer) *Service {
		svc := NewService(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, nil, nil, nil, nil, nil, nil, nil,
			ports.Provenance{}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAudit{}, shared.SeverityHigh, 0,
			&fakeAcquirer{dir: workspace}, &fakeDetector{}, producer,
			[]ports.DetectionSource{ownadvisory.New(store)}, nil, fakeLic{}, nil)
		svc.SetSBOMCache(cache)
		return svc
	}
	scan := func(producer *countedRealProducer) *ScanResult {
		t.Helper()
		result, err := service(producer).Scan(ctx, "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(cache.errs) != 0 {
			t.Fatalf("cache errors: %v", cache.errs)
		}
		return result
	}
	check := func(result *ScanResult, source, version string) {
		t.Helper()
		if result.SBOM == nil || result.SBOM.Source != source || result.SBOM.GeneratorVersion != version || version == "" {
			t.Fatalf("unexpected producer result: %+v; expected %s %s", result.SBOM, source, version)
		}
		if result.ToolVersions[sbomGeneratorKey] != version || result.Manifest.ToolVersions[sbomGeneratorKey] != version {
			t.Fatalf("producer provenance missing: tools=%v manifest=%v", result.ToolVersions, result.Manifest.ToolVersions)
		}
		for _, component := range result.SBOM.Components {
			if component.Name == "lodash" && component.Version == "4.17.0" {
				return
			}
		}
		t.Fatalf("%s did not catalog lodash@4.17.0: %+v", source, result.SBOM.Components)
	}
	hasFinding := func(result *ScanResult) bool {
		for _, vuln := range result.Vulnerabilities {
			if vuln.ID == "CVE-2019-10744" && vuln.Component == "lodash" {
				return true
			}
		}
		return false
	}

	initial := scan(owned)
	ownedVersion := initial.SBOM.GeneratorVersion
	check(initial, "ownsbom", ownedVersion)
	if hasFinding(initial) {
		t.Fatal("empty advisory store unexpectedly matched")
	}

	if err := store.Upsert(ctx, advisory.Advisory{ID: "CVE-2019-10744", Summary: "Prototype pollution in lodash", Severity: shared.SeverityCritical,
		Affected: []advisory.AffectedPackage{{Ecosystem: "npm", Package: "lodash", Ranges: []advisory.Range{{Type: "SEMVER", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "4.17.12"}}}}, FixedVersion: "4.17.12"}}}); err != nil {
		t.Fatal(err)
	}

	first := scan(firstSyft)
	check(first, "syft", first.SBOM.GeneratorVersion)
	if strings.TrimPrefix(first.SBOM.GeneratorVersion, "v") != "1.45.1" {
		t.Fatalf("pinned Syft version = %q, want 1.45.1", first.SBOM.GeneratorVersion)
	}
	if !hasFinding(first) {
		t.Fatalf("pinned Syft inventory did not match advisory: %+v", first.Vulnerabilities)
	}

	returned := scan(owned)
	check(returned, "ownsbom", ownedVersion)
	if !hasFinding(returned) {
		t.Fatalf("cached owned inventory did not match newly added advisory: %+v", returned.Vulnerabilities)
	}
	if owned.calls != 1 || cache.hits != 1 {
		t.Fatal("fresh advisory matching regenerated the cached owned inventory")
	}

	second := scan(secondSyft)
	check(second, "syft", second.SBOM.GeneratorVersion)
	if second.SBOM.GeneratorVersion == first.SBOM.GeneratorVersion {
		t.Fatalf("Syft releases must have distinct versions: %q", second.SBOM.GeneratorVersion)
	}
	if !hasFinding(second) {
		t.Fatalf("other Syft inventory did not match advisory: %+v", second.Vulnerabilities)
	}

	cachedSyft := scan(firstSyft)
	check(cachedSyft, "syft", first.SBOM.GeneratorVersion)
	if len(first.SBOM.Raw) == 0 || !bytes.Equal(first.SBOM.Raw, cachedSyft.SBOM.Raw) {
		t.Fatal("cached Syft raw provenance differs from generated CycloneDX")
	}
	if firstSyft.calls != 1 {
		t.Fatal("unchanged pinned Syft inventory was regenerated")
	}

	// Updating the executable at the same configured path must not reuse its old inventory.
	if err := os.Remove(privatePinned); err != nil {
		t.Fatal(err)
	}
	updated, err := os.Open(other)
	if err != nil {
		t.Fatal(err)
	}
	defer updated.Close()
	replacement, err := os.OpenFile(privatePinned, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr = io.Copy(replacement, updated)
	closeErr = replacement.Close()
	if copyErr != nil {
		t.Fatal(copyErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	changed := scan(firstSyft)
	check(changed, "syft", second.SBOM.GeneratorVersion)

	if err := os.Remove(privatePinned); err != nil {
		t.Fatal(err)
	}
	if _, _, err := firstSyft.SBOMProducerIdentity(ctx, workspace); err == nil {
		t.Fatal("removed Syft executable still has a usable identity")
	}
	unavailable := scan(firstSyft)
	if unavailable.SBOM == nil || len(unavailable.SBOM.Components) != 0 || unavailable.Completeness.Confident || !strings.Contains(unavailable.Completeness.Warning, "SBOM generation did not run") {
		t.Fatalf("unavailable producer must surface incomplete empty inventory, got SBOM=%+v completeness=%+v", unavailable.SBOM, unavailable.Completeness)
	}
}

func TestRealSyftCacheTracksExternalConfiguration(t *testing.T) {
	bin := os.Getenv("SYNAPSE_TEST_SYFT_PINNED")
	if os.Getenv("SYNAPSE_PRODUCER_CACHE_INTEGRATION") != "1" && bin == "" {
		t.Skip("set SYNAPSE_PRODUCER_CACHE_INTEGRATION=1 and SYNAPSE_TEST_SYFT_PINNED")
	}
	if !filepath.IsAbs(bin) {
		t.Fatal("SYNAPSE_TEST_SYFT_PINNED must be an absolute executable path")
	}
	home, workspace := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("SYFT_EXCLUDE", "")
	if err := os.Unsetenv("SYFT_EXCLUDE"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SYFT_CHECK_FOR_APP_UPDATE", "false")
	lock := `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0"},"node_modules/lodash":{"version":"4.17.0"}}}`
	if err := os.WriteFile(filepath.Join(workspace, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	gen := syft.New(bin)
	producer := &countedRealProducer{generator: gen, identity: gen}
	cache := &observedRealCache{cache: sbomcache.New(t.TempDir())}
	service := NewService(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, nil, nil, nil, nil, nil, nil, nil,
		ports.Provenance{}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAudit{}, shared.SeverityHigh, 0,
		&fakeAcquirer{dir: workspace}, &fakeDetector{}, producer, []ports.DetectionSource{ownadvisory.New(memory.NewAdvisoryStore())}, nil, fakeLic{}, nil)
	service.SetSBOMCache(cache)
	scan := func(wantLodash bool) {
		t.Helper()
		result, err := service.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"})
		if err != nil {
			t.Fatal(err)
		}
		if result.SBOM == nil || result.SBOM.Source != "syft" || strings.TrimPrefix(result.SBOM.GeneratorVersion, "v") != "1.45.1" {
			t.Fatalf("unexpected producer: %+v", result.SBOM)
		}
		found := false
		for _, c := range result.SBOM.Components {
			found = found || c.Name == "lodash"
		}
		if found != wantLodash {
			t.Fatalf("lodash present=%v, want %v", found, wantLodash)
		}
	}
	scan(true)
	scan(true)
	if producer.calls != 1 || cache.hits != 1 {
		t.Fatalf("unchanged configuration did not hit: calls=%d hits=%d", producer.calls, cache.hits)
	}
	if err := os.WriteFile(filepath.Join(home, ".syft.yaml"), []byte("exclude:\n  - '**/package-lock.json'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	scan(false)
	scan(false)
	if producer.calls != 2 || cache.hits != 2 || len(cache.errs) != 0 {
		t.Fatalf("changed configuration was not cached independently: calls=%d hits=%d errors=%v", producer.calls, cache.hits, cache.errs)
	}
	if err := os.Remove(filepath.Join(home, ".syft.yaml")); err != nil {
		t.Fatal(err)
	}
	scan(true)
	t.Setenv("SYFT_EXCLUDE", "**/package*.json")
	scan(false)
	if producer.calls != 3 || cache.hits != 3 || len(cache.errs) != 0 {
		t.Fatalf("environment change did not invalidate inventory: calls=%d hits=%d errors=%v", producer.calls, cache.hits, cache.errs)
	}
	if err := os.Unsetenv("SYFT_EXCLUDE"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".syft.yaml"), []byte("exclude: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loads, stores := cache.loads, cache.stores
	result, err := service.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"})
	if err != nil {
		t.Fatal(err)
	}
	if cache.loads != loads || cache.stores != stores || result.Completeness.Confident || producer.calls != 4 {
		t.Fatalf("invalid configuration masked by cache: loads=%d stores=%d calls=%d completeness=%+v", cache.loads-loads, cache.stores-stores, producer.calls, result.Completeness)
	}
}
