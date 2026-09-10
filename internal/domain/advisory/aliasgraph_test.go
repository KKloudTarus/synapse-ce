package advisory

import (
	"reflect"
	"testing"
)

func TestAliasGraphClosureLinksCrossSourceIds(t *testing.T) {
	g := NewAliasGraph([]AliasEdge{
		{AliasID: "GHSA-xxxx", CanonicalID: "CVE-2026-1"},
		{AliasID: "OSV-2026-9", CanonicalID: "CVE-2026-1"},
		{AliasID: "DEBIAN-CVE-2026-1", CanonicalID: "CVE-2026-1"},
	})
	want := []string{"CVE-2026-1", "DEBIAN-CVE-2026-1", "GHSA-XXXX", "OSV-2026-9"}
	for _, probe := range []string{"ghsa-xxxx", "CVE-2026-1", "OSV-2026-9"} {
		if got := g.Closure(probe); !reflect.DeepEqual(got, want) {
			t.Errorf("Closure(%q) = %v, want %v", probe, got, want)
		}
	}
}

func TestAliasGraphResolvesChains(t *testing.T) {
	g := NewAliasGraph([]AliasEdge{
		{AliasID: "GHSA-a", CanonicalID: "CVE-2026-2"},
		{AliasID: "CVE-2026-2", CanonicalID: "CVE-2026-3"},
	})
	if got, want := g.Closure("GHSA-A"), []string{"CVE-2026-2", "CVE-2026-3", "GHSA-A"}; !reflect.DeepEqual(got, want) {
		t.Errorf("chain closure = %v, want %v", got, want)
	}
}

func TestAliasGraphKeepsDistinctCVEsSeparate(t *testing.T) {
	g := NewAliasGraph([]AliasEdge{
		{AliasID: "GHSA-a", CanonicalID: "CVE-2026-4"},
		{AliasID: "GHSA-b", CanonicalID: "CVE-2026-5"},
	})
	if reflect.DeepEqual(g.Closure("CVE-2026-4"), g.Closure("CVE-2026-5")) {
		t.Errorf("distinct CVEs must not share a component")
	}
	if len(g.Closure("CVE-2026-4")) != 2 {
		t.Errorf("component must be {CVE-2026-4, GHSA-A}, got %v", g.Closure("CVE-2026-4"))
	}
}

func TestAliasGraphUnknownIdReturnsItself(t *testing.T) {
	if got := NewAliasGraph(nil).Closure("CVE-2026-6"); !reflect.DeepEqual(got, []string{"CVE-2026-6"}) {
		t.Errorf("unknown id closure = %v, want [CVE-2026-6]", got)
	}
}

func TestAliasGraphCycleSafe(t *testing.T) {
	g := NewAliasGraph([]AliasEdge{
		{AliasID: "CVE-2026-7", CanonicalID: "CVE-2026-8"},
		{AliasID: "CVE-2026-8", CanonicalID: "CVE-2026-7"},
	})
	if got, want := g.Closure("CVE-2026-7"), []string{"CVE-2026-7", "CVE-2026-8"}; !reflect.DeepEqual(got, want) {
		t.Errorf("cycle closure = %v, want %v", got, want)
	}
}

func TestAliasGraphExpandUnionsClosures(t *testing.T) {
	g := NewAliasGraph([]AliasEdge{
		{AliasID: "GHSA-a", CanonicalID: "CVE-2026-9"},
		{AliasID: "GHSA-b", CanonicalID: "CVE-2026-10"},
	})
	got := g.Expand([]string{"GHSA-a", "CVE-2026-10", "UNKNOWN-1"})
	want := []string{"CVE-2026-10", "CVE-2026-9", "GHSA-A", "GHSA-B", "UNKNOWN-1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Expand = %v, want %v", got, want)
	}
}
