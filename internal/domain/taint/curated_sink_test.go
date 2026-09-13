package taint

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
)

// TestCuratedSinkFiresOnFlowWithProvenance is the #1052 acceptance: a curated CVE's vulnerable API, modeled
// as a taint sink, fires on an attacker-input -> API flow, and the sink carries provenance through Assemble.
func TestCuratedSinkFiresOnFlowWithProvenance(t *testing.T) {
	prov := SinkProvenance{Advisory: "GHSA-vuln-1", Source: "sme", Curator: "alice", Reference: "https://example/advisory"}
	cat := Catalog{
		Sources: []string{"net/http.Request.FormValue"},
		Sinks:   []Sink{CuratedSink("github.com/vuln/lib.Parse", "CWE-502", "reach-GHSA-vuln-1", prov)},
	}
	// app.handler reads request input and calls the curated vulnerable function.
	g := callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.handler", Callees: []string{"net/http.Request.FormValue", "github.com/vuln/lib.Parse"}},
	}}
	fg, sinkClass := Assemble(g, cat)

	vulns := fg.Vulnerabilities()
	if len(vulns) != 1 || vulns[0].Sink != "app.handler" {
		t.Fatalf("a source->curated-sink flow must fire, got %+v", vulns)
	}
	sinks := sinkClass[vulns[0].Sink]
	if len(sinks) != 1 {
		t.Fatalf("the sink-class index must carry the curated sink, got %+v", sinks)
	}
	s := sinks[0]
	if s.CWE != "CWE-502" || s.Rule != "reach-GHSA-vuln-1" {
		t.Errorf("curated sink class/rule = %s/%s", s.CWE, s.Rule)
	}
	if s.Provenance == nil || s.Provenance.Advisory != "GHSA-vuln-1" || s.Provenance.Curator != "alice" {
		t.Errorf("curated sink must carry provenance, got %+v", s.Provenance)
	}
}
