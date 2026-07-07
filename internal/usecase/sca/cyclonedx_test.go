package sca

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func cdxFixtureSBOM() *sbom.SBOM {
	return &sbom.SBOM{
		Components: []sbom.Component{
			{
				Name: "gin", Version: "v1.9.1", PURL: "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
				Licenses:  []sbom.License{{SPDXID: "MIT"}},
				Checksums: []sbom.Checksum{{Algorithm: "SHA256", Value: strings.Repeat("a", 64)}},
			},
			{
				Name: "log4j-core", Version: "2.14.1", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
				Licenses: []sbom.License{{Name: "Apache-2.0"}},
				SHA1:     strings.Repeat("b", 40),
			},
		},
		Dependencies: []sbom.Dependency{
			{Ref: "pkg:golang/github.com/gin-gonic/gin@v1.9.1", DependsOn: []string{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}},
		},
	}
}

func TestBuildCycloneDXDeterministicAndValid(t *testing.T) {
	created := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	d := buildCycloneDX(cdxFixtureSBOM(), "github.com/org/repo", created)

	if d.BOMFormat != "CycloneDX" || d.SpecVersion != "1.6" || d.Version != 1 {
		t.Errorf("doc header = %q/%q/%d, want CycloneDX/1.6/1", d.BOMFormat, d.SpecVersion, d.Version)
	}
	if d.Metadata.Timestamp != "2026-07-07T00:00:00Z" {
		t.Errorf("timestamp = %q, want the scan time (never time.Now)", d.Metadata.Timestamp)
	}
	if d.Metadata.Component == nil || d.Metadata.Component.Name != "github.com/org/repo" {
		t.Errorf("metadata.component must name the scan target, got %+v", d.Metadata.Component)
	}
	if len(d.Metadata.Tools.Components) != 1 || d.Metadata.Tools.Components[0].Name != "synapse" {
		t.Errorf("metadata.tools should list synapse, got %+v", d.Metadata.Tools)
	}
	// Components sorted by name: gin before log4j-core.
	if len(d.Components) != 2 || d.Components[0].Name != "gin" || d.Components[1].Name != "log4j-core" {
		t.Fatalf("want [gin, log4j-core] sorted, got %+v", d.Components)
	}
	gin := d.Components[0]
	if gin.BOMRef != "pkg:golang/github.com/gin-gonic/gin@v1.9.1" || gin.PURL != gin.BOMRef {
		t.Errorf("gin bom-ref should be its PURL, got %q", gin.BOMRef)
	}
	if gin.Supplier == nil || gin.Supplier.Name == "" {
		t.Errorf("gin supplier should be derived from the PURL namespace, got %+v", gin.Supplier)
	}
	if len(gin.Licenses) != 1 || gin.Licenses[0].License == nil || gin.Licenses[0].License.ID != "MIT" {
		t.Errorf("gin license should be SPDX id MIT, got %+v", gin.Licenses)
	}
	if len(gin.Hashes) != 1 || gin.Hashes[0].Alg != "SHA-256" || gin.Hashes[0].Content != strings.Repeat("a", 64) {
		t.Errorf("gin hash should be SHA-256, got %+v", gin.Hashes)
	}
	log4j := d.Components[1]
	if len(log4j.Licenses) != 1 || log4j.Licenses[0].License == nil || log4j.Licenses[0].License.Name != "Apache-2.0" {
		t.Errorf("log4j free-text license should be a name, got %+v", log4j.Licenses)
	}
	if len(log4j.Hashes) != 1 || log4j.Hashes[0].Alg != "SHA-1" {
		t.Errorf("log4j legacy SHA1 should render as SHA-1, got %+v", log4j.Hashes)
	}
	// Dependency edge maps by bom-ref (PURL) and drops nothing (both endpoints exist).
	if len(d.Dependencies) != 1 || d.Dependencies[0].Ref != "pkg:golang/github.com/gin-gonic/gin@v1.9.1" ||
		len(d.Dependencies[0].DependsOn) != 1 || d.Dependencies[0].DependsOn[0] != "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" {
		t.Errorf("dependency edge should map gin -> log4j by bom-ref, got %+v", d.Dependencies)
	}

	// Deterministic: same input -> byte-identical output.
	a, _ := json.Marshal(buildCycloneDX(cdxFixtureSBOM(), "github.com/org/repo", created))
	b, _ := json.Marshal(buildCycloneDX(cdxFixtureSBOM(), "github.com/org/repo", created))
	if string(a) != string(b) {
		t.Error("buildCycloneDX must be deterministic")
	}
}

func TestCDXDanglingDependencyEdgeDropped(t *testing.T) {
	doc := &sbom.SBOM{
		Components:   []sbom.Component{{Name: "a", Version: "1", PURL: "pkg:npm/a@1"}},
		Dependencies: []sbom.Dependency{{Ref: "pkg:npm/a@1", DependsOn: []string{"pkg:npm/ghost@9"}}},
	}
	d := buildCycloneDX(doc, "t", time.Unix(0, 0).UTC())
	// The edge's target has no component, so dependsOn is emptied (no dangling bom-ref).
	if len(d.Dependencies) != 1 || len(d.Dependencies[0].DependsOn) != 0 {
		t.Errorf("an edge to a missing component must be dropped, got %+v", d.Dependencies)
	}
}

func TestCDXHashesAlgorithmMapping(t *testing.T) {
	c := sbom.Component{Checksums: []sbom.Checksum{
		{Algorithm: "sha-256", Value: strings.Repeat("a", 64)},       // -> SHA-256 (hyphenated, normalized input)
		{Algorithm: "SHA3-256", Value: strings.Repeat("b", 64)},      // -> SHA3-256
		{Algorithm: "SHA224", Value: strings.Repeat("c", 56)},        // dropped: no CycloneDX enum value
		{Algorithm: "ADLER32", Value: strings.Repeat("d", 8)},        // dropped
		{Algorithm: "MD5", Value: strings.Repeat("e", 32)},           // -> MD5
		{Algorithm: "SHA512", Value: strings.Repeat("A", 86) + "=="}, // base64 SRI -> SHA-512, hex content
	}}
	h := cdxHashes(c)
	var algs []string
	for _, x := range h {
		algs = append(algs, x.Alg)
	}
	want := []string{"MD5", "SHA-256", "SHA-512", "SHA3-256"} // sorted; SHA224 + ADLER32 dropped
	if strings.Join(algs, ",") != strings.Join(want, ",") {
		t.Errorf("cdx hash algs = %v, want %v", algs, want)
	}
	for _, x := range h {
		if x.Alg == "SHA-512" && x.Content != strings.Repeat("00", 64) {
			t.Errorf("base64 SRI must decode to lowercase hex, got %q", x.Content)
		}
	}
}
