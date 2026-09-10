package memory

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
)

func adv(id string, affects ...advisory.AffectedPackage) advisory.Advisory {
	return advisory.Advisory{ID: id, CVSSScore: 9.8, Affected: affects}
}

func ap(eco, pkg string) advisory.AffectedPackage {
	return advisory.AffectedPackage{Ecosystem: eco, Package: pkg, FixedVersion: "1.2.0"}
}

// TestAdvisoryStoreUpsertByPackage is the load->lookup round trip the ingester and the owned
// DetectionSource rely on: Upsert indexes by every affected (ecosystem, package); ByPackage returns the
// advisory under each of its keys and nothing under an unaffected key.
func TestAdvisoryStoreUpsertByPackage(t *testing.T) {
	ctx := context.Background()
	s := NewAdvisoryStore()
	if err := s.Upsert(ctx, adv("GHSA-1", ap("Go", "github.com/foo/bar"), ap("npm", "left-pad"))); err != nil {
		t.Fatal(err)
	}

	got, err := s.ByPackage(ctx, "Go", "github.com/foo/bar")
	if err != nil || len(got) != 1 || got[0].ID != "GHSA-1" {
		t.Fatalf("Go key: want 1 GHSA-1, got %+v err=%v", got, err)
	}
	if got, _ := s.ByPackage(ctx, "npm", "left-pad"); len(got) != 1 || got[0].ID != "GHSA-1" {
		t.Fatalf("npm key: want GHSA-1, got %+v", got) // indexed under BOTH affected packages
	}
	if got, _ := s.ByPackage(ctx, "Go", "github.com/safe/pkg"); len(got) != 0 {
		t.Fatalf("unaffected package must return nothing, got %+v", got)
	}
}

// TestAdvisoryStoreReSyncRebuildsIndex pins the idempotent-replace contract: re-upserting an id with a
// CHANGED affected set drops the stale index entries (a key no longer affected stops returning the advisory)
// and adds the new ones – never a duplicate, never a phantom hit on the old package.
func TestAdvisoryStoreReSyncRebuildsIndex(t *testing.T) {
	ctx := context.Background()
	s := NewAdvisoryStore()
	_ = s.Upsert(ctx, adv("GHSA-1", ap("Go", "github.com/foo/bar"), ap("npm", "left-pad")))
	// re-sync: now affects only the npm package (the Go binding was retracted)
	_ = s.Upsert(ctx, adv("GHSA-1", ap("npm", "left-pad")))

	if got, _ := s.ByPackage(ctx, "Go", "github.com/foo/bar"); len(got) != 0 {
		t.Fatalf("retracted Go binding must no longer match, got %+v", got)
	}
	got, _ := s.ByPackage(ctx, "npm", "left-pad")
	if len(got) != 1 || got[0].ID != "GHSA-1" {
		t.Fatalf("npm key must still match exactly once (no dup), got %+v", got)
	}
}

// TestAdvisoryStoreMultiBlockSamePackageIndexedOnce: an advisory with two affected blocks for the same
// (ecosystem, package) is indexed once, so ByPackage returns it a single time.
func TestAdvisoryStoreMultiBlockSamePackageIndexedOnce(t *testing.T) {
	ctx := context.Background()
	s := NewAdvisoryStore()
	_ = s.Upsert(ctx, adv("GHSA-1", ap("Go", "github.com/foo/bar"), ap("Go", "github.com/foo/bar")))
	if got, _ := s.ByPackage(ctx, "Go", "github.com/foo/bar"); len(got) != 1 {
		t.Fatalf("duplicate affected blocks must index once, got %d", len(got))
	}
}

// TestAdvisoryStoreSkipsEmptyKeys: an affected block with no ecosystem or package is not indexed (it can't
// be soundly looked up) – never a phantom empty-key hit.
func TestAdvisoryStoreSkipsEmptyKeys(t *testing.T) {
	ctx := context.Background()
	s := NewAdvisoryStore()
	_ = s.Upsert(ctx, adv("GHSA-1", advisory.AffectedPackage{Ecosystem: "", Package: ""}, ap("Go", "x")))
	if got, _ := s.ByPackage(ctx, "", ""); len(got) != 0 {
		t.Fatalf("empty (ecosystem,package) must not be indexed, got %+v", got)
	}
	if got, _ := s.ByPackage(ctx, "Go", "x"); len(got) != 1 {
		t.Fatalf("the valid block must still index, got %+v", got)
	}
}

// TestAdvisoryStoreReSyncPreservesRiskEnrichment pins the corpus-clobber guard (D1.2 enrichment half): the
// canonical materializer merges KEV/EPSS/PublicExploit onto an advisory, then a bulk-feed re-sync (which
// carries none) must NOT lower them. Base fields still refresh; a narrowed affected set still takes effect.
func TestAdvisoryStoreReSyncPreservesRiskEnrichment(t *testing.T) {
	ctx := context.Background()
	s := NewAdvisoryStore()
	enriched := advisory.Advisory{
		ID:            "CVE-2026-9000",
		Summary:       "enriched by the risk pipeline",
		KEV:           true,
		PublicExploit: true,
		EPSS:          0.88,
		Affected:      []advisory.AffectedPackage{ap("npm", "left-pad")},
	}
	if err := s.Upsert(ctx, enriched); err != nil {
		t.Fatal(err)
	}
	// Bulk feed re-sync: fresh base fields, zero risk signals.
	bare := advisory.Advisory{
		ID:       "CVE-2026-9000",
		Summary:  "refreshed base summary",
		Affected: []advisory.AffectedPackage{ap("npm", "left-pad")},
	}
	if err := s.Upsert(ctx, bare); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ByPackage(ctx, "npm", "left-pad")
	if len(got) != 1 {
		t.Fatalf("want 1 advisory, got %d", len(got))
	}
	a := got[0]
	if !a.KEV || !a.PublicExploit || a.EPSS != 0.88 {
		t.Errorf("risk enrichment clobbered on re-sync: KEV=%v PublicExploit=%v EPSS=%v", a.KEV, a.PublicExploit, a.EPSS)
	}
	if a.Summary != "refreshed base summary" {
		t.Errorf("base summary not refreshed: got %q", a.Summary)
	}
}

func TestAdvisoryStoreAliasEdgesBoundedByIds(t *testing.T) {
	ctx := context.Background()
	s := NewAdvisoryStore()
	_ = s.Upsert(ctx, advisory.Advisory{ID: "CVE-2026-1", Aliases: []string{"GHSA-a", "OSV-9"}, Affected: []advisory.AffectedPackage{ap("npm", "left-pad")}})
	_ = s.Upsert(ctx, advisory.Advisory{ID: "CVE-2026-2", Aliases: []string{"GHSA-b"}, Affected: []advisory.AffectedPackage{ap("npm", "other")}})

	// Query by an ALIAS id: the advisory whose alias is GHSA-a is returned, and its full edge set.
	edges, err := s.AdvisoryAliasEdges(ctx, []string{"GHSA-a"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range edges {
		got[e.AliasID] = e.CanonicalID
	}
	if got["GHSA-a"] != "CVE-2026-1" || got["OSV-9"] != "CVE-2026-1" {
		t.Errorf("alias edges for GHSA-a wrong: %v", got)
	}
	if _, leaked := got["GHSA-b"]; leaked {
		t.Errorf("unrelated advisory CVE-2026-2 must not be returned: %v", got)
	}

	// Query by a CANONICAL id also returns its edges.
	if e2, _ := s.AdvisoryAliasEdges(ctx, []string{"CVE-2026-2"}); len(e2) != 1 || e2[0].AliasID != "GHSA-b" {
		t.Errorf("canonical-id query = %v, want [GHSA-b->CVE-2026-2]", e2)
	}
	// Empty ids -> no edges.
	if e3, _ := s.AdvisoryAliasEdges(ctx, nil); len(e3) != 0 {
		t.Errorf("empty ids must return no edges, got %v", e3)
	}
}
