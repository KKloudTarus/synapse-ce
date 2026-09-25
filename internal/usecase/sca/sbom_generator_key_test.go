package sca

import "testing"

// The SBOM producer's version is keyed by the role it fills, not by one implementation.
//
// It used to be filed under "syft" whatever produced it, so a manifest from the owned parsers read
// `"syft": "ownsbom/0.8.0"`, naming a tool that never ran. Synapse does not use Syft or Grype; the
// owned parsers are the producer, and the provenance record has to say so.
//
// The key is load-bearing: it feeds the SBOM cache key, the run-to-run drift report and the pinned
// input list. A rename that did not read the old key would make every stored manifest look like it
// changed producer, so both are read and the value is identical either way.
func TestSBOMGeneratorVersionReadsBothKeys(t *testing.T) {
	cases := []struct {
		name string
		tv   map[string]string
		want string
	}{
		{"current key", map[string]string{sbomGeneratorKey: "ownsbom/0.8.0"}, "ownsbom/0.8.0"},
		{"manifest written before the rename", map[string]string{legacySBOMGeneratorKey: "ownsbom/0.8.0"}, "ownsbom/0.8.0"},
		{"current key wins when both are present", map[string]string{sbomGeneratorKey: "ownsbom/0.9.0", legacySBOMGeneratorKey: "ownsbom/0.8.0"}, "ownsbom/0.9.0"},
		{"no producer recorded", map[string]string{"go-enry": "v2.9.6"}, ""},
		{"nil map", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sbomGeneratorVersion(tc.tv); got != tc.want {
				t.Fatalf("sbomGeneratorVersion = %q, want %q", got, tc.want)
			}
		})
	}
}

// The cache key must not change when the same run is described under the old key, or every stored
// SBOM would be treated as produced by a different version and re-generated.
func TestSBOMProducerVersionIsStableAcrossTheRename(t *testing.T) {
	current := sbomProducerVersion(map[string]string{sbomGeneratorKey: "ownsbom/0.8.0", "go-enry": "v2.9.6", "synapse": "v0.1.9"})
	legacy := sbomProducerVersion(map[string]string{legacySBOMGeneratorKey: "ownsbom/0.8.0", "go-enry": "v2.9.6", "synapse": "v0.1.9"})
	if current != legacy {
		t.Fatalf("producer version differs across the key rename: %q vs %q", current, legacy)
	}
	if current == "" {
		t.Fatal("producer version is empty, which disables the SBOM cache")
	}
}
