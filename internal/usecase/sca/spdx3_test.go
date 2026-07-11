package sca

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestBuildSPDX3DeterministicAndValid(t *testing.T) {
	doc := &sbom.SBOM{
		TargetRef: "https://github.com/org/repo",
		Components: []sbom.Component{
			{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},
			{Name: "express", Version: "4.18.2", PURL: "pkg:npm/express@4.18.2"},
		},
	}
	created := time.Date(2026, 6, 21, 0, 0, 0, 0, time.UTC)

	a := buildSPDX3(doc, doc.TargetRef, created)
	ja, _ := json.MarshalIndent(a, "", "  ")
	jb, _ := json.MarshalIndent(buildSPDX3(doc, doc.TargetRef, created), "", "  ")
	if string(ja) != string(jb) {
		t.Fatal("buildSPDX3 must be deterministic")
	}

	// Valid JSON-LD envelope.
	if a.Context != spdx3Context {
		t.Errorf("@context = %q", a.Context)
	}
	// Graph: CreationInfo + SpdxDocument + 2 packages + 1 relationship = 5.
	if len(a.Graph) != 5 {
		t.Fatalf("graph has %d nodes, want 5", len(a.Graph))
	}

	s := string(ja)
	for _, want := range []string{
		`"type": "CreationInfo"`, `"specVersion": "3.0.1"`,
		`"type": "SpdxDocument"`, `"profileConformance"`,
		`"type": "software_Package"`, `"software_packageUrl": "pkg:npm/express@4.18.2"`,
		`"type": "Relationship"`, `"relationshipType": "contains"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("SPDX3 output missing %q", want)
		}
	}

	// Packages are sorted (express before lodash) – find their order in the graph.
	doc0, ok := a.Graph[1].(spdx3Document)
	if !ok {
		t.Fatalf("graph[1] is not the SpdxDocument: %T", a.Graph[1])
	}
	if len(doc0.RootElement) != 2 {
		t.Errorf("document rootElement should list 2 packages, got %d", len(doc0.RootElement))
	}
	pkg0, ok := a.Graph[2].(spdx3Package)
	if !ok || pkg0.Name != "express" {
		t.Errorf("first package should be express (sorted), got %+v", a.Graph[2])
	}
}

func TestBuildSPDX3EmitsSupplierAgent(t *testing.T) {
	doc := &sbom.SBOM{
		TargetRef: "https://github.com/org/repo",
		Components: []sbom.Component{
			{Name: "commons-lang3", Version: "3.12.0", PURL: "pkg:maven/org.apache.commons/commons-lang3@3.12.0"},
		},
	}
	a := buildSPDX3(doc, doc.TargetRef, time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC))

	var agent *spdx3Agent
	var pkg *spdx3Package
	for _, n := range a.Graph {
		switch v := n.(type) {
		case spdx3Agent:
			ag := v
			agent = &ag
		case spdx3Package:
			p := v
			pkg = &p
		}
	}
	if agent == nil {
		t.Fatal("SPDX3 must emit an Organization Agent for the derived supplier")
	}
	if agent.Type != "Organization" || agent.Name != "org.apache.commons" {
		t.Errorf("supplier agent = %+v, want Organization org.apache.commons", agent)
	}
	if pkg == nil || pkg.SuppliedBy != agent.SpdxID {
		t.Errorf("package suppliedBy = %q, want the agent IRI %q", pkgSuppliedBy(pkg), agent.SpdxID)
	}
	// The Agent must also be listed among the document's elements.
	docNode, _ := a.Graph[1].(spdx3Document)
	found := false
	for _, e := range docNode.Element {
		if e == agent.SpdxID {
			found = true
		}
	}
	if !found {
		t.Error("supplier agent IRI must appear in the SpdxDocument.element list")
	}
}

func TestBuildSPDX3EmitsHash(t *testing.T) {
	doc := &sbom.SBOM{
		TargetRef:  "t",
		Components: []sbom.Component{{Name: "a", Version: "1.0", PURL: "pkg:maven/g/a@1.0", SHA1: "0123456789abcdef0123456789abcdef01234567"}},
	}
	a := buildSPDX3(doc, doc.TargetRef, time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC))
	var pkg *spdx3Package
	for _, n := range a.Graph {
		if p, ok := n.(spdx3Package); ok {
			pp := p
			pkg = &pp
		}
	}
	if pkg == nil || len(pkg.VerifiedUsing) != 1 {
		t.Fatalf("SPDX3 package must carry one verifiedUsing Hash, got %+v", pkg)
	}
	h := pkg.VerifiedUsing[0]
	if h.Type != "Hash" || h.Algorithm != "sha1" || h.HashValue != "0123456789abcdef0123456789abcdef01234567" {
		t.Errorf("verifiedUsing Hash = %+v, want {Hash sha1 <hex>} (algorithm lowercase per SPDX 3.0)", h)
	}
}

func pkgSuppliedBy(p *spdx3Package) string {
	if p == nil {
		return "<nil package>"
	}
	return p.SuppliedBy
}

func TestSPDX3HashAlg(t *testing.T) {
	// Every canonical (SPDX 2.3-style) algorithm name the domain gate can emit must map to a valid SPDX 3.0.1
	// HashAlgorithm token: most lower-case cleanly, but the SHA-3 family takes an underscore and BLAKE2b drops
	// the separator. This covers all 15 names, so an override typo or a fallback regression is caught.
	cases := map[string]string{
		"SHA1": "sha1", "SHA224": "sha224", "SHA256": "sha256", "SHA384": "sha384", "SHA512": "sha512",
		"SHA3-256": "sha3_256", "SHA3-384": "sha3_384", "SHA3-512": "sha3_512",
		"BLAKE2b-256": "blake2b256", "BLAKE2b-384": "blake2b384", "BLAKE2b-512": "blake2b512",
		"MD2": "md2", "MD4": "md4", "MD5": "md5", "ADLER32": "adler32",
	}
	for in, want := range cases {
		if got := spdx3HashAlg(in); got != want {
			t.Errorf("spdx3HashAlg(%q) = %q, want %q for the SPDX 3.0.1 vocabulary", in, got, want)
		}
	}
}
