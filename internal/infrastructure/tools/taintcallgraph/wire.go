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
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
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
	// Positions is the OPTIONAL first-party symbol → "relpath:line" table (def-use precision for taint
	// findings). Additive and back/forward compatible: an older binary omits it, an older adapter ignores
	// it — so the protocol version stays v1.0.0 (no hard cutover for a purely additive field).
	Positions map[string]string `json:"positions,omitempty"`
	// ExecFacts is the OPTIONAL value-level exec-sink verdict table (D5.4): a first-party function symbol →
	// the exec sink symbols in it the SSA pass proved safe to de-escalate (constant known-fixed-safe program
	// name at every call site AND a confined *exec.Cmd result). Additive + back/forward compatible like
	// Positions, so the protocol version stays v1.0.0. It only DE-ESCALATES a CWE-78 finding to CWE-88; an
	// absent function or an absent sink keeps CWE-78 (fail-closed). Only proven-safe entries are emitted.
	ExecFacts map[string]wireExecFunc `json:"exec_facts,omitempty"`
}

type wireEdge struct {
	Caller  string   `json:"caller"`
	Callees []string `json:"callees"`
}

// wireExecFunc is the JSON form of taint.ExecFuncFacts: the sorted set of exec sink symbols proven safe to
// de-escalate for the function. A struct (not a bare list) so future value-level facts can be added
// additively without a protocol cutover.
type wireExecFunc struct {
	SafeSinks []string `json:"safe_sinks,omitempty"`
}

// EncodeGraph writes g (no value-level facts) as the versioned wire envelope. Kept for callers that only
// have a graph; the command uses EncodeGraphWithFacts.
func EncodeGraph(w io.Writer, g *callgraph.Graph) error {
	return EncodeGraphWithFacts(w, g, taint.ExecFacts{})
}

// EncodeGraphWithFacts writes g plus the value-level exec-sink facts as the versioned wire envelope (used by
// cmd/synapse-callgraph). Deterministic input (the builder sorts) ⇒ deterministic bytes. Only constant-safe
// verdicts are serialized, so an empty facts table emits no exec_facts key (byte-identical to EncodeGraph).
func EncodeGraphWithFacts(w io.Writer, g *callgraph.Graph, facts taint.ExecFacts) error {
	wg := wireGraph{ProtocolVersion: protocolVersion, Entrypoints: g.Entrypoints, Positions: g.Positions}
	for _, e := range g.Edges {
		wg.Edges = append(wg.Edges, wireEdge{Caller: e.Caller, Callees: e.Callees})
	}
	for sym, f := range facts.Funcs {
		sinks := make([]string, 0, len(f.SafeSinks))
		for sink, ok := range f.SafeSinks {
			if ok && sink != "" {
				sinks = append(sinks, sink)
			}
		}
		if len(sinks) == 0 {
			continue // only proven-safe verdicts ride the wire; absence means keep CWE-78
		}
		sort.Strings(sinks) // deterministic bytes
		if wg.ExecFacts == nil {
			wg.ExecFacts = map[string]wireExecFunc{}
		}
		wg.ExecFacts[sym] = wireExecFunc{SafeSinks: sinks}
	}
	return json.NewEncoder(w).Encode(wg)
}

// parseCallgraph decodes the synapse-callgraph wire envelope into the domain callgraph.Graph plus the
// value-level exec-sink facts. It fails closed on a JSON error or an unrecognized protocol version (a
// drifted format must not be silently mis-parsed into a partial graph – that would drop taint paths). Only
// constant-safe verdicts are carried into the facts (absence = keep CWE-78), so an older binary that omits
// the field yields empty facts and the coordinator keeps every CWE-78 finding. This is the testable core
// (like parseGovulncheck): the exec wrapper just feeds it the captured stdout.
func parseCallgraph(data []byte) (*callgraph.Graph, taint.ExecFacts, error) {
	var wg wireGraph
	if err := json.Unmarshal(data, &wg); err != nil {
		return nil, taint.ExecFacts{}, fmt.Errorf("decode synapse-callgraph output: %w", err)
	}
	if wg.ProtocolVersion != "" && wg.ProtocolVersion != protocolVersion {
		return nil, taint.ExecFacts{}, fmt.Errorf("unsupported synapse-callgraph protocol %q (want %s)", wg.ProtocolVersion, protocolVersion)
	}
	g := &callgraph.Graph{Entrypoints: wg.Entrypoints, Positions: wg.Positions}
	for _, e := range wg.Edges {
		g.Edges = append(g.Edges, callgraph.Edge{Caller: e.Caller, Callees: e.Callees})
	}
	var facts taint.ExecFacts
	for sym, f := range wg.ExecFacts {
		safe := make(map[string]bool, len(f.SafeSinks))
		for _, sink := range f.SafeSinks {
			if sink != "" {
				safe[sink] = true
			}
		}
		if len(safe) == 0 {
			continue
		}
		if facts.Funcs == nil {
			facts.Funcs = map[string]taint.ExecFuncFacts{}
		}
		facts.Funcs[sym] = taint.ExecFuncFacts{SafeSinks: safe}
	}
	return g, facts, nil
}
