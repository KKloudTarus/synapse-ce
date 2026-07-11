// Command synapse-callgraph builds a general first-party call graph from Go source (via go/ssa) and emits it
// as the taintcallgraph wire JSON on stdout. It isolates the heavy go/ssa analysis (golang.org/x/tools) into
// a standalone, sandboxable binary so the api server never imports x/tools and the UNTRUSTED
// target is compiled ONLY inside the sandbox the taintcallgraph adapter runs this binary under. Composition
// root only – the analysis lives in internal/infrastructure/tools/ssacallgraph.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ssacallgraph"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/taintcallgraph"
)

func main() {
	if len(os.Args) != 3 || os.Args[1] != "build-callgraph" {
		fmt.Fprintln(os.Stderr, "usage: synapse-callgraph build-callgraph <go-module-dir>")
		os.Exit(2)
	}
	g, err := ssacallgraph.BuildGraph(context.Background(), os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "synapse-callgraph:", err)
		os.Exit(1)
	}
	if err := taintcallgraph.EncodeGraph(os.Stdout, g); err != nil {
		fmt.Fprintln(os.Stderr, "synapse-callgraph: encode:", err)
		os.Exit(1)
	}
}
