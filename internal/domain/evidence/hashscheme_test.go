package evidence

import (
	"testing"
	"time"
)

func TestEvidenceHashSchemesOnFieldBoundaryCollisions(t *testing.T) {
	at := time.Date(2026, 11, 27, 8, 0, 0, 0, time.UTC)
	// StorageRef "x\x1ey" with CreatedBy "z" and StorageRef "x" with CreatedBy "y\x1ez" write the
	// same legacy preimage: the separator inside a field reads as a boundary.
	left := Evidence{Kind: "scan", StorageRef: "x\x1ey", CreatedBy: "z", CreatedAt: at, Content: []byte("c")}
	right := Evidence{Kind: "scan", StorageRef: "x", CreatedBy: "y\x1ez", CreatedAt: at, Content: []byte("c")}
	cases := []struct {
		name       string
		scheme     int
		wantShared bool
	}{
		{name: "legacy encoding shares a preimage", scheme: HashSchemeLegacy, wantShared: true},
		{name: "framed encoding separates the links", scheme: HashSchemeFramed, wantShared: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, r := left, right
			l.HashScheme, r.HashScheme = tc.scheme, tc.scheme
			if (ComputeHash(l) == ComputeHash(r)) != tc.wantShared {
				t.Fatalf("shared hash = %v, want %v", ComputeHash(l) == ComputeHash(r), tc.wantShared)
			}
		})
	}
}

func TestFramedEvidenceBindsContentLength(t *testing.T) {
	at := time.Date(2026, 11, 27, 8, 0, 0, 0, time.UTC)
	// Under the legacy encoding Content trails the last separator unframed, so bytes could move
	// between CreatedBy's terminator and Content. The framed encoding frames Content too.
	a := Evidence{Kind: "k", CreatedBy: "u", CreatedAt: at, Content: []byte("ab"), HashScheme: HashSchemeFramed}
	b := Evidence{Kind: "k", CreatedBy: "u", CreatedAt: at, Content: []byte("a"), HashScheme: HashSchemeFramed}
	if ComputeHash(a) == ComputeHash(b) {
		t.Fatal("different content shares a framed hash")
	}
}

func TestSealWritesTheCurrentSchemeAndChainsVerifyAcrossSchemes(t *testing.T) {
	at := time.Date(2026, 11, 27, 8, 0, 0, 0, time.UTC)
	// A legacy link as an upgraded database returns it: the stored hash and no scheme, or scheme 1.
	legacy := Evidence{Kind: "scan", CreatedBy: "u", CreatedAt: at, Content: []byte("one")}
	legacy.Hash = ComputeHash(legacy)
	explicit := Evidence{Kind: "scan", CreatedBy: "u", CreatedAt: at, Content: []byte("two"), PreviousHash: legacy.Hash, HashScheme: HashSchemeLegacy}
	explicit.Hash = ComputeHash(explicit)

	sealed := Evidence{Kind: "finding", CreatedBy: "u", CreatedAt: at, Content: []byte("three"), PreviousHash: explicit.Hash}.Seal()
	if sealed.HashScheme != CurrentHashScheme {
		t.Fatalf("Seal wrote scheme %d, want %d", sealed.HashScheme, CurrentHashScheme)
	}
	// Seal ignores a scheme the caller set; the scheme a link is written with is the release's.
	other := HashSchemeFramed
	if CurrentHashScheme == HashSchemeFramed {
		other = HashSchemeLegacy
	}
	if stale := (Evidence{Kind: "x", CreatedAt: at, HashScheme: other}).Seal(); stale.HashScheme != CurrentHashScheme {
		t.Fatalf("Seal kept the caller's scheme %d", other)
	}
	framed := Evidence{Kind: "finding", CreatedBy: "u", CreatedAt: at, Content: []byte("four"), PreviousHash: sealed.Hash, HashScheme: HashSchemeFramed}
	framed.Hash = ComputeHash(framed)

	if err := VerifyChain([]Evidence{legacy, explicit, sealed, framed}); err != nil {
		t.Fatalf("mixed chain: %v", err)
	}
	relabelled := framed
	relabelled.HashScheme = HashSchemeLegacy
	if err := VerifyChain([]Evidence{legacy, explicit, sealed, relabelled}); err == nil {
		t.Fatal("a framed link relabelled legacy still verified")
	}
	unknown := framed
	unknown.HashScheme = 7
	if err := VerifyChain([]Evidence{legacy, explicit, sealed, unknown}); err == nil {
		t.Fatal("a link with an unknown scheme verified")
	}
	// An unknown scheme computes ""; a forged link with an empty hash must not match it.
	forged := Evidence{Kind: "finding", CreatedBy: "mallory", CreatedAt: at, Content: []byte("forged"), PreviousHash: sealed.Hash, HashScheme: 9}
	if err := VerifyChain([]Evidence{legacy, explicit, sealed, forged}); err == nil {
		t.Fatal("a link with an empty hash and an unknown scheme verified")
	}
}

func TestEvidenceHashSchemeGoldenVectors(t *testing.T) {
	at := time.Date(2026, 11, 27, 8, 0, 0, 123456789, time.UTC)
	e := Evidence{Kind: "scan", FindingID: "f-1", StorageRef: "sha256:ab", CreatedBy: "ada", CreatedAt: at, Content: []byte("payload"), PreviousHash: "prev"}
	cases := []struct {
		scheme int
		want   string
	}{
		// What the release before schemes computed for this link.
		{scheme: 0, want: "03e7a0b83da175f99afdb8cd5d3a334ddc2d08421595fc7e843d72f371a04c9d"},
		{scheme: HashSchemeLegacy, want: "03e7a0b83da175f99afdb8cd5d3a334ddc2d08421595fc7e843d72f371a04c9d"},
		{scheme: HashSchemeFramed, want: "aff4264c1bcf62a5af5c728df3c5dfec403590759bbeea9f1833a10e167465e1"},
	}
	for _, tc := range cases {
		e.HashScheme = tc.scheme
		if got := ComputeHash(e); got != tc.want {
			t.Errorf("scheme %d = %s, want %s", tc.scheme, got, tc.want)
		}
	}
}
