package sca

import "testing"

func TestSBOMProducerVersion(t *testing.T) {
	// No versions known → empty → the cache stays off (never serve an unversioned SBOM).
	if got := sbomProducerVersion(nil); got != "" {
		t.Errorf("nil map: want empty, got %q", got)
	}
	if got := sbomProducerVersion(map[string]string{"kev-catalog": "2026.07.01"}); got != "" {
		t.Errorf("only non-producer versions: want empty, got %q", got)
	}

	base := map[string]string{"syft": "1.45.1", "go-enry": "v2.9.6", "synapse": "v0.1.0"}
	v1 := sbomProducerVersion(base)
	if v1 == "" {
		t.Fatal("a populated producer map must yield a non-empty version")
	}
	// A producer bump changes the key; a KEV/EPSS DB change (not a producer) must NOT.
	bumped := map[string]string{"syft": "1.46.0", "go-enry": "v2.9.6", "synapse": "v0.1.0"}
	if sbomProducerVersion(bumped) == v1 {
		t.Error("a syft version bump must change the producer version")
	}
	withKEV := map[string]string{"syft": "1.45.1", "go-enry": "v2.9.6", "synapse": "v0.1.0", "kev-catalog": "2026.08.01"}
	if sbomProducerVersion(withKEV) != v1 {
		t.Error("a non-producer DB version must NOT change the producer version (no over-invalidation)")
	}
}
