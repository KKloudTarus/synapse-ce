package main

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
)

// The CLI honors SYNAPSE_SBOM_PRODUCER like the server: the owned ownsbom parsers by default (an empty
// value resolves to ownsbom, matching config.Load), the pinned syft binary when asked, and a hard error
// on an unknown value (fail closed, never a silent default). ownsbom is pure-Go so the default needs no
// third-party binary.
func TestSelectSBOMGenerator(t *testing.T) {
	// Empty and "ownsbom" both select the owned default producer.
	for _, p := range []string{"", "ownsbom"} {
		g, err := selectSBOMGenerator(config.Config{SBOMProducer: p})
		if err != nil {
			t.Fatalf("producer %q: unexpected error %v", p, err)
		}
		if g == nil {
			t.Fatalf("producer %q: nil generator", p)
		}
	}

	// syft is the opt-in cross-check.
	g, err := selectSBOMGenerator(config.Config{SBOMProducer: "syft", SyftBin: "syft"})
	if err != nil {
		t.Fatalf("syft: unexpected error %v", err)
	}
	if g == nil {
		t.Fatal("syft: nil generator")
	}

	if _, err := selectSBOMGenerator(config.Config{SBOMProducer: "bogus"}); err == nil {
		t.Fatal("an unknown SBOM producer must be rejected, not silently defaulted")
	}
}
