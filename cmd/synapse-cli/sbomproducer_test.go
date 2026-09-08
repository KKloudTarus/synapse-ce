package main

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
)

// The CLI honors SYNAPSE_SBOM_PRODUCER like the server: syft by default, Synapse's own ownsbom parsers
// when asked, and a hard error on an unknown value (fail closed, never a silent default). ownsbom is
// pure-Go so this needs no third-party binary.
func TestSelectSBOMGenerator(t *testing.T) {
	for _, p := range []string{"", "syft"} {
		g, err := selectSBOMGenerator(config.Config{SBOMProducer: p, SyftBin: "syft"})
		if err != nil {
			t.Fatalf("producer %q: unexpected error %v", p, err)
		}
		if g == nil {
			t.Fatalf("producer %q: nil generator", p)
		}
	}

	g, err := selectSBOMGenerator(config.Config{SBOMProducer: "ownsbom"})
	if err != nil {
		t.Fatalf("ownsbom: unexpected error %v", err)
	}
	if g == nil {
		t.Fatal("ownsbom: nil generator")
	}

	if _, err := selectSBOMGenerator(config.Config{SBOMProducer: "bogus"}); err == nil {
		t.Fatal("an unknown SBOM producer must be rejected, not silently defaulted")
	}
}
