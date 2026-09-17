package scabench

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncodeObservationSetCanonicalizesAndRoundTripsStrictly(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	set := ObservationSet{
		SchemaVersion:   ObservationSchemaVersion,
		CatalogRevision: "r1",
		CatalogDigest:   digest,
		Observations: []Observation{{
			SchemaVersion:      ObservationSchemaVersion,
			CatalogRevision:    "r1",
			CatalogDigest:      digest,
			Engine:             EngineGrype,
			EngineVersion:      "1",
			EngineBinaryDigest: digest,
			DatabaseBuild:      "db",
			DatabaseDigest:     digest,
			EnvironmentID:      "env",
			EnvironmentDigest:  digest,
			TargetID:           "target",
			TargetDigest:       digest,
			SBOMDigest:         digest,
			State:              ObservationComplete,
			RawOutputDigest:    digest,
			ConfigDigest:       digest,
			Findings: []Finding{
				{Component: Component{PURL: "pkg:npm/z@1", Version: "1"}, AdvisoryID: "CVE-2024-0002"},
				{Component: Component{PURL: "pkg:npm/a@1", Version: "1"}, AdvisoryID: "CVE-2024-0001"},
			},
		}},
	}
	var encoded bytes.Buffer
	if err := EncodeObservationSet(&encoded, set); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeObservationSet(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded.Observations[0].Findings[0].Component.PURL; got != "pkg:npm/a@1" {
		t.Fatalf("findings were not canonicalized: %q", got)
	}
}

func TestDigestObservationsSortsNormalizedEquivalentFindingsDeterministically(t *testing.T) {
	catalog := validCatalog()
	first := completeObservation(catalog, EngineOwned)
	first.Findings = []Finding{
		{Component: catalog.Targets[0].Components[0], AdvisoryID: "CVE-2024-0001"},
		{Component: catalog.Targets[0].Components[0], AdvisoryID: "cve-2024-0001"},
	}
	second := first
	second.Findings = []Finding{first.Findings[1], first.Findings[0]}
	left, err := DigestObservations([]Observation{first})
	if err != nil {
		t.Fatal(err)
	}
	right, err := DigestObservations([]Observation{second})
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatalf("normalized-equivalent finding order changed provenance digest: %q != %q", left, right)
	}
	left, err = DigestScoringObservations([]Observation{first})
	if err != nil {
		t.Fatal(err)
	}
	right, err = DigestScoringObservations([]Observation{second})
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatalf("normalized-equivalent finding order changed scoring digest: %q != %q", left, right)
	}
	if first.Findings[0].AdvisoryID != "CVE-2024-0001" || first.Findings[1].AdvisoryID != "cve-2024-0001" {
		t.Fatalf("digest mutated input findings: %+v", first.Findings)
	}
}

func TestEncodeObservationSetRejectsOversizedDocumentBeforeWriting(t *testing.T) {
	catalog := validCatalog()
	observation := completeObservation(catalog, EngineOwned)
	set := ObservationSet{
		SchemaVersion:   ObservationSchemaVersion,
		CatalogRevision: catalog.Revision,
		CatalogDigest:   mustDigestCatalog(catalog),
		Observations:    []Observation{observation},
	}
	encoded, err := CanonicalJSON(set)
	if err != nil {
		t.Fatal(err)
	}
	padding := int(MaxJSONBytes) - len(encoded)
	if padding <= 0 {
		t.Fatalf("observation set is already %d bytes", len(encoded))
	}
	set.Observations[0].EngineVersion += strings.Repeat("x", padding)
	encoded, err = CanonicalJSON(set)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(encoded)) != MaxJSONBytes {
		t.Fatalf("canonical observation set size = %d, want %d", len(encoded), MaxJSONBytes)
	}

	var output bytes.Buffer
	err = EncodeObservationSet(&output, set)
	if err == nil {
		t.Fatal("observation set whose newline exceeds the limit was encoded")
	}
	if !strings.Contains(err.Error(), "8388608") {
		t.Fatalf("oversized observation error = %q", err)
	}
	if output.Len() != 0 {
		t.Fatalf("oversized observation set wrote %d bytes", output.Len())
	}
}
