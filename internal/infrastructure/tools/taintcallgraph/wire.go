// Package taintcallgraph is the adapter that produces a general first-party call graph for E39 taint
// analysis by shelling out to the sandboxed `synapse-callgraph` argv binary (which runs the heavy go/ssa
// builder, internal/infrastructure/tools/ssacallgraph). Keeping the build behind an exec boundary means the
// untrusted target is compiled inside the sandbox – NOT in the api server's address space – and x/tools
// stays OUT of the server's import graph (this package imports neither ssacallgraph nor x/tools).
//
// This file holds the wire protocol shared across that exec boundary: the binary EncodeGraph()s the domain
// callgraph.Graph to stdout, and the adapter parseCallgraph()s it back. The wire structs are deliberately
// local (a process protocol, like govulncheck's message/finding/frame), so neither side pulls the other's
// imports.
package taintcallgraph

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
)

// protocolVersion guards the synapse-callgraph JSON contract: the adapter refuses a stream whose version it
// doesn't recognize rather than mis-parsing a drifted format (fail-closed, mirroring the govulncheck builder).
const protocolVersion = "v1.0.0"

// wireGraph is the JSON envelope synapse-callgraph emits + the adapter parses: the protocol version plus the
// deterministic call graph (entrypoints + edges, "importPath.Symbol" ids).
type wireGraph struct {
	ProtocolVersion string     `json:"protocol_version"`
	Entrypoints     []string   `json:"entrypoints,omitempty"`
	Edges           []wireEdge `json:"edges,omitempty"`
}

type wireEdge struct {
	Caller  string   `json:"caller"`
	Callees []string `json:"callees"`
}

// EncodeGraph writes g as the versioned wire envelope (used by cmd/synapse-callgraph). Deterministic input
// (the builder sorts) ⇒ deterministic bytes.
func EncodeGraph(w io.Writer, g *callgraph.Graph) error {
	wg := wireGraph{ProtocolVersion: protocolVersion, Entrypoints: g.Entrypoints}
	for _, e := range g.Edges {
		wg.Edges = append(wg.Edges, wireEdge{Caller: e.Caller, Callees: e.Callees})
	}
	return json.NewEncoder(w).Encode(wg)
}

// parseCallgraph decodes the synapse-callgraph wire envelope into the domain callgraph.Graph. It fails
// closed on a JSON error or an unrecognized protocol version (a drifted format must not be silently
// mis-parsed into a partial graph – that would drop taint paths). This is the testable core (like
// parseGovulncheck): the exec wrapper just feeds it the captured stdout.
func parseCallgraph(data []byte) (*callgraph.Graph, error) {
	var wg wireGraph
	if err := json.Unmarshal(data, &wg); err != nil {
		return nil, fmt.Errorf("decode synapse-callgraph output: %w", err)
	}
	if wg.ProtocolVersion != "" && wg.ProtocolVersion != protocolVersion {
		return nil, fmt.Errorf("unsupported synapse-callgraph protocol %q (want %s)", wg.ProtocolVersion, protocolVersion)
	}
	g := &callgraph.Graph{Entrypoints: wg.Entrypoints}
	for _, e := range wg.Edges {
		g.Edges = append(g.Edges, callgraph.Edge{Caller: e.Caller, Callees: e.Callees})
	}
	return g, nil
}
