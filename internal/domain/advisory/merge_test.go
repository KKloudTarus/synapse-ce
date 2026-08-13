package advisory

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func boolPtr(value bool) *bool        { return &value }
func floatPtr(value float64) *float64 { return &value }

func TestMergeIsDeterministicAndPreservesSparseFields(t *testing.T) {
	published := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)
	modified := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	core := Observation{
		SourceType: "osv", SourceID: "osv-main", RecordID: "GHSA-AAAA-BBBB-CCCC", PublishedAt: published,
		ModifiedAt: modified.Add(-time.Hour), Status: StatusActive,
		Advisory: Advisory{
			ID: "ghsa-aaaa-bbbb-cccc", Aliases: []string{"cve-2026-12345"}, Summary: "core summary",
			CVSSVector: "CVSS:3.1/AV:N", CVSSScore: 8.1,
			Affected: []AffectedPackage{{Ecosystem: "Go", Package: "example.com/mod", Versions: []string{"1.0.0", "1.0.0"}}},
		},
	}
	enrichment := Observation{
		SourceType: "epss", SourceID: "epss-public", RecordID: "CVE-2026-12345", ModifiedAt: modified,
		Advisory: Advisory{ID: "CVE-2026-12345"}, KEV: boolPtr(true), EPSS: floatPtr(0.91),
	}
	first, err := Merge([]Observation{core, enrichment})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Merge([]Observation{enrichment, core})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("observation order changed canonical output:\nfirst=%+v\nsecond=%+v", first, second)
	}
	if first.Advisory.ID != "CVE-2026-12345" || first.Advisory.Summary != "core summary" || len(first.Advisory.Affected) != 1 {
		t.Fatalf("sparse enrichment erased core data: %+v", first)
	}
	if first.KEV == nil || !*first.KEV || first.EPSS == nil || *first.EPSS != 0.91 {
		t.Fatalf("enrichment missing: %+v", first)
	}
	firstHash, _ := first.ContentHash()
	secondHash, _ := second.ContentHash()
	if firstHash == "" || firstHash != secondHash {
		t.Fatalf("unstable hash %q != %q", firstHash, secondHash)
	}
}

func TestMergeUsesFieldSpecificPrecedenceAndUnionsAffected(t *testing.T) {
	early := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	late := early.Add(24 * time.Hour)
	observations := []Observation{
		{SourceType: "csaf", SourceID: "vendor", RecordID: "VENDOR-1", PublishedAt: late, ModifiedAt: early,
			Advisory: Advisory{ID: "VENDOR-1", Aliases: []string{"CVE-2025-9999"}, Summary: "vendor summary", CVSSScore: 7.1,
				Affected: []AffectedPackage{{Ecosystem: "npm", Package: "left-pad", Versions: []string{"1.0.0"}}}}},
		{SourceType: "nvd", SourceID: "nvd", RecordID: "CVE-2025-9999", PublishedAt: early, ModifiedAt: late,
			Advisory: Advisory{ID: "CVE-2025-9999", Summary: "nvd summary", CVSSVector: "CVSS:3.1/AV:N", CVSSScore: 9.8}},
		{SourceType: "osv", SourceID: "osv", RecordID: "GHSA-1111-2222-3333",
			Advisory: Advisory{ID: "GHSA-1111-2222-3333", Aliases: []string{"CVE-2025-9999"},
				Affected: []AffectedPackage{{Ecosystem: "Go", Package: "example.com/x", Versions: []string{"v1.2.3"}}}}},
	}
	canonical, err := Merge(observations)
	if err != nil {
		t.Fatal(err)
	}
	if canonical.Advisory.Summary != "vendor summary" {
		t.Fatalf("summary=%q, want vendor authority", canonical.Advisory.Summary)
	}
	if canonical.Advisory.CVSSScore != 9.8 || canonical.Advisory.CVSSVector == "" {
		t.Fatalf("cvss=%q/%v, want NVD", canonical.Advisory.CVSSVector, canonical.Advisory.CVSSScore)
	}
	if !canonical.PublishedAt.Equal(early) || !canonical.ModifiedAt.Equal(late) {
		t.Fatalf("dates=%v/%v", canonical.PublishedAt, canonical.ModifiedAt)
	}
	if len(canonical.Advisory.Affected) != 2 || len(canonical.Sources) != 3 {
		t.Fatalf("union/provenance lost: %+v", canonical)
	}
}

func TestMergeStatusAndAliasConflicts(t *testing.T) {
	for _, status := range []Status{StatusRejected, StatusWithdrawn} {
		canonical, err := Merge([]Observation{{
			SourceType: "nvd", SourceID: "nvd", RecordID: "CVE-2025-1000", Status: status,
			Advisory: Advisory{ID: "CVE-2025-1000", Summary: "retained"},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if canonical.Status != status || canonical.Advisory.Summary != "retained" || !reflect.DeepEqual(canonical.Sources, []string{"nvd"}) {
			t.Fatalf("status/provenance not retained: %+v", canonical)
		}
	}

	conflicts := [][]Observation{
		{{Advisory: Advisory{ID: "CVE-2025-1000"}}, {Advisory: Advisory{ID: "GHSA-AAAA-BBBB-CCCC"}}},
		{{Advisory: Advisory{ID: "CVE-2025-1000", Aliases: []string{"GHSA-AAAA-BBBB-CCCC"}}}, {Advisory: Advisory{ID: "CVE-2025-2000", Aliases: []string{"GHSA-AAAA-BBBB-CCCC"}}}},
	}
	for _, observations := range conflicts {
		if _, err := Merge(observations); !errors.Is(err, ErrAliasConflict) {
			t.Fatalf("expected alias conflict, got %v", err)
		}
	}
}

func TestDiffNamesMaterialChanges(t *testing.T) {
	previous, err := Merge([]Observation{{SourceType: "osv", SourceID: "osv", Advisory: Advisory{ID: "CVE-2025-1000", Summary: "old"}}})
	if err != nil {
		t.Fatal(err)
	}
	next, err := Merge([]Observation{{SourceType: "osv", SourceID: "osv", Advisory: Advisory{ID: "CVE-2025-1000", Summary: "new"}, KEV: boolPtr(true)}})
	if err != nil {
		t.Fatal(err)
	}
	want := []ChangedField{ChangedSummary, ChangedExploitability}
	if got := Diff(previous, next); !reflect.DeepEqual(got, want) {
		t.Fatalf("Diff=%v, want %v", got, want)
	}
}
