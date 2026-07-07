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

	// Packages are sorted (express before lodash) — find their order in the graph.
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

func pkgSuppliedBy(p *spdx3Package) string {
	if p == nil {
		return "<nil package>"
	}
	return p.SuppliedBy
}
