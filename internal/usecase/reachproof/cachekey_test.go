package reachproof

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
)

func completeKey() CacheKey {
	return CacheKey{
		SourceHash:      "srchash",
		Symbols:         []string{"a.b", "c.d"},
		Tier:            judgment.Tier2,
		AnalyzerVersion: "v1",
		CoverageModel:   "cov1",
		EnvFingerprint:  "env1",
	}
}

// A key with every verdict-affecting field bound is Complete; dropping any single one makes it incomplete.
func TestCacheKeyComplete(t *testing.T) {
	if !completeKey().Complete() {
		t.Fatal("a fully bound key must be Complete")
	}
	drops := map[string]func(*CacheKey){
		"source hash":      func(k *CacheKey) { k.SourceHash = "" },
		"analyzer version": func(k *CacheKey) { k.AnalyzerVersion = "" },
		"coverage model":   func(k *CacheKey) { k.CoverageModel = "" },
		"env fingerprint":  func(k *CacheKey) { k.EnvFingerprint = "" },
		"tier":             func(k *CacheKey) { k.Tier = "" },
		"whitespace hash":  func(k *CacheKey) { k.SourceHash = "   " },
	}
	for name, drop := range drops {
		k := completeKey()
		drop(&k)
		if k.Complete() {
			t.Fatalf("dropping %s must make the key incomplete", name)
		}
	}
}

// Symbol order and duplicates must not change the fingerprint (subjects arrive in arbitrary order).
func TestCacheKeyFingerprintSymbolOrderInvariant(t *testing.T) {
	a := completeKey()
	b := completeKey()
	b.Symbols = []string{"c.d", "a.b", "a.b", "c.d"} // reordered + duplicated
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatal("symbol order and duplicates must not change the fingerprint")
	}
}

// Any changed verdict-affecting field must change the fingerprint (no stale-key collision).
func TestCacheKeyFingerprintSensitivity(t *testing.T) {
	base := completeKey().Fingerprint()
	cases := map[string]func(*CacheKey){
		"source hash":      func(k *CacheKey) { k.SourceHash = "other" },
		"added symbol":     func(k *CacheKey) { k.Symbols = []string{"a.b", "c.d", "e.f"} },
		"tier":             func(k *CacheKey) { k.Tier = judgment.Tier1 },
		"analyzer version": func(k *CacheKey) { k.AnalyzerVersion = "v2" },
		"coverage model":   func(k *CacheKey) { k.CoverageModel = "cov2" },
		"env fingerprint":  func(k *CacheKey) { k.EnvFingerprint = "env2" },
	}
	for name, mut := range cases {
		k := completeKey()
		mut(&k)
		if k.Fingerprint() == base {
			t.Fatalf("changing %s must change the fingerprint", name)
		}
	}
}

// Length-prefixing must stop field-boundary aliasing: moving a character across two adjacent fields is a
// different key even though the naive concatenation is identical.
func TestCacheKeyFingerprintNoBoundaryCollision(t *testing.T) {
	x := completeKey()
	x.SourceHash = "ab"
	x.AnalyzerVersion = "cd"
	y := completeKey()
	y.SourceHash = "abc"
	y.AnalyzerVersion = "d"
	if x.Fingerprint() == y.Fingerprint() {
		t.Fatal("field boundaries must be unambiguous (length-prefixed)")
	}
}

// The fingerprint is stable across calls (deterministic content addressing).
func TestCacheKeyFingerprintStable(t *testing.T) {
	if completeKey().Fingerprint() != completeKey().Fingerprint() {
		t.Fatal("fingerprint must be deterministic")
	}
}
