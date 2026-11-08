package sca

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// identifiedGenerator is a producer that can name itself before generating, like the owned parsers
// and the Syft adapter. identityErr models a selected producer whose binary is absent.
type identifiedGenerator struct {
	identity    string
	identityErr error
	source      string
	version     string
	generateErr error
	generated   int
}

func (g *identifiedGenerator) SBOMProducerIdentity(context.Context, string) (string, bool, error) {
	if g.identityErr != nil {
		return "", false, g.identityErr
	}
	return g.identity, true, nil
}

func (g *identifiedGenerator) Generate(context.Context, string) (*sbom.SBOM, error) {
	g.generated++
	if g.generateErr != nil {
		return nil, g.generateErr
	}
	return &sbom.SBOM{Source: g.source, GeneratorVersion: g.version, Components: []sbom.Component{{Name: g.source + "-component"}}}, nil
}

var _ ports.SBOMProducerIdentity = (*identifiedGenerator)(nil)

// legacyGenerator implements only the generation port, like a third-party producer added without
// the identity port.
type legacyGenerator struct{ generated int }

func (g *legacyGenerator) Generate(context.Context, string) (*sbom.SBOM, error) {
	g.generated++
	return &sbom.SBOM{Source: "legacy", Components: []sbom.Component{{Name: "legacy-component"}}}, nil
}

// recordingCache is an in-memory SBOM cache that records every key it is asked for.
type recordingCache struct {
	entries  map[string]*sbom.SBOM
	loadKeys []string
	storeKey []string
}

func newRecordingCache() *recordingCache {
	return &recordingCache{entries: map[string]*sbom.SBOM{}}
}

func (c *recordingCache) Load(_ context.Context, dir, producerVersion string) (*sbom.SBOM, bool, error) {
	c.loadKeys = append(c.loadKeys, producerVersion)
	doc, ok := c.entries[dir+"\x00"+producerVersion]
	return doc, ok, nil
}

func (c *recordingCache) Store(_ context.Context, dir, producerVersion string, doc *sbom.SBOM) error {
	c.storeKey = append(c.storeKey, producerVersion)
	c.entries[dir+"\x00"+producerVersion] = doc
	return nil
}

var _ ports.SBOMCache = (*recordingCache)(nil)

func identityService(gen ports.SBOMGenerator, cache ports.SBOMCache) *Service {
	return &Service{
		sbomGen:   gen,
		sbomCache: cache,
		prov:      ports.Provenance{ToolVersions: map[string]string{"go-enry": "enry/2.9.0", "synapse": "synapse/1.2.3"}},
	}
}

// TestSBOMCacheKeyNamesTheSelectedProducer is the regression for #1638: a cache entry written by one
// producer must never be served to another. The owned producer scans first, the operator then
// selects Syft, and the Syft run must generate rather than inherit the owned inventory.
func TestSBOMCacheKeyNamesTheSelectedProducer(t *testing.T) {
	cache := newRecordingCache()
	owned := &identifiedGenerator{identity: "ownsbom/0.8.0", source: "ownsbom", version: "ownsbom/0.8.0"}
	ctx := context.Background()

	doc, hit, err := identityService(owned, cache).loadOrGenerateSBOM(ctx, "/ws")
	if err != nil || hit || doc.Source != "ownsbom" || owned.generated != 1 {
		t.Fatalf("first owned scan: doc=%+v hit=%v generated=%d err=%v", doc, hit, owned.generated, err)
	}
	doc, hit, err = identityService(owned, cache).loadOrGenerateSBOM(ctx, "/ws")
	if err != nil || !hit || doc.Source != "ownsbom" || owned.generated != 1 {
		t.Fatalf("second owned scan must hit the cache: hit=%v generated=%d err=%v", hit, owned.generated, err)
	}

	syft := &identifiedGenerator{identity: "syft:/usr/bin/syft:100:7", source: "syft", version: "syft/1.20.0"}
	doc, hit, err = identityService(syft, cache).loadOrGenerateSBOM(ctx, "/ws")
	if err != nil {
		t.Fatalf("syft scan: %v", err)
	}
	if hit {
		t.Fatalf("a Syft scan must not be served the owned producer's inventory")
	}
	if doc.Source != "syft" || doc.GeneratorVersion != "syft/1.20.0" || syft.generated != 1 {
		t.Fatalf("syft must actually run: doc=%+v generated=%d", doc, syft.generated)
	}

	// Back to the owned producer: its own entry is still addressable and still attributed to it.
	doc, hit, err = identityService(owned, cache).loadOrGenerateSBOM(ctx, "/ws")
	if err != nil || !hit || doc.Source != "ownsbom" || owned.generated != 1 {
		t.Fatalf("owned scan after syft: hit=%v source=%q generated=%d err=%v", hit, doc.Source, owned.generated, err)
	}
	if len(cache.loadKeys) != 4 || cache.loadKeys[0] == cache.loadKeys[2] {
		t.Fatalf("each producer must look up its own key: %q", cache.loadKeys)
	}
}

// TestSBOMCacheKeyFollowsTheProducerVersion keeps the analyzer-version invalidation: the same
// producer at a new version must not reuse the inventory the old version cataloged.
func TestSBOMCacheKeyFollowsTheProducerVersion(t *testing.T) {
	cache := newRecordingCache()
	ctx := context.Background()
	oldVer := &identifiedGenerator{identity: "ownsbom/0.8.0", source: "ownsbom", version: "ownsbom/0.8.0"}
	if _, _, err := identityService(oldVer, cache).loadOrGenerateSBOM(ctx, "/ws"); err != nil {
		t.Fatal(err)
	}
	newVer := &identifiedGenerator{identity: "ownsbom/0.9.0", source: "ownsbom", version: "ownsbom/0.9.0"}
	doc, hit, err := identityService(newVer, cache).loadOrGenerateSBOM(ctx, "/ws")
	if err != nil {
		t.Fatal(err)
	}
	if hit || newVer.generated != 1 || doc.GeneratorVersion != "ownsbom/0.9.0" {
		t.Fatalf("a producer version bump must regenerate: hit=%v generated=%d doc=%+v", hit, newVer.generated, doc)
	}
}

// TestUnavailableProducerIsNeverServedFromCache is the absent-binary case from the audit: selecting
// a producer that cannot be resolved must surface the producer failure, not a cache hit carrying
// another producer's complete inventory.
func TestUnavailableProducerIsNeverServedFromCache(t *testing.T) {
	cache := newRecordingCache()
	ctx := context.Background()
	owned := &identifiedGenerator{identity: "ownsbom/0.8.0", source: "ownsbom", version: "ownsbom/0.8.0"}
	if _, _, err := identityService(owned, cache).loadOrGenerateSBOM(ctx, "/ws"); err != nil {
		t.Fatal(err)
	}

	absent := &identifiedGenerator{
		identityErr: errors.New(`resolve syft binary "syft": executable file not found in $PATH`),
		generateErr: errors.New(`exec: "syft": executable file not found in $PATH`),
	}
	doc, hit, err := identityService(absent, cache).loadOrGenerateSBOM(ctx, "/ws")
	if err == nil {
		t.Fatalf("an absent producer must fail the SBOM step, got doc=%+v hit=%v", doc, hit)
	}
	if hit {
		t.Fatalf("an unidentified producer must not be served a cached inventory")
	}
	if len(doc.Components) != 0 {
		t.Fatalf("the degraded inventory must be empty, got %d components", len(doc.Components))
	}
	for _, key := range cache.loadKeys[1:] {
		t.Fatalf("no lookup may run for an unidentified producer: %q", key)
	}
	if absent.generated != 1 {
		t.Fatalf("the selected producer must be attempted exactly once, got %d", absent.generated)
	}
}

func TestUnknownProducerNeverUsesProvenanceCache(t *testing.T) {
	cache := newRecordingCache()
	ctx := context.Background()
	known := &identifiedGenerator{identity: "ownsbom/0.8.0", source: "known"}
	svc := identityService(known, cache)
	svc.prov.ToolVersions["sbom-generator"] = "ownsbom/0.8.0"
	if _, _, err := svc.loadOrGenerateSBOM(ctx, "/ws"); err != nil {
		t.Fatal(err)
	}
	unknown := &legacyGenerator{}
	svc = identityService(unknown, cache)
	svc.prov.ToolVersions["sbom-generator"] = "ownsbom/0.8.0"
	for range 2 {
		doc, hit, err := svc.loadOrGenerateSBOM(ctx, "/ws")
		if err != nil || hit || doc.Source != "legacy" {
			t.Fatalf("unknown producer: doc=%+v hit=%v err=%v", doc, hit, err)
		}
	}
	if unknown.generated != 2 || len(cache.loadKeys) != 1 || len(cache.storeKey) != 1 {
		t.Fatalf("unknown producer used cache: generations=%d loads=%v stores=%v", unknown.generated, cache.loadKeys, cache.storeKey)
	}
}
