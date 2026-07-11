// Command synapse-ast parses a source tree with language-aware (tree-sitter) grammars and emits
// structural facts as JSON on stdout. Its first capability is accurate per-language function counts
// (`synapse-ast functions <dir>`). It isolates the CGO tree-sitter grammars into a standalone,
// sandboxable binary so the api server and CLI never import them and the UNTRUSTED target is parsed only
// inside the sandbox the ast adapter runs this binary under. Composition root only – the analysis lives
// in internal/infrastructure/tools/astwalk.
//
// Exit codes: 0 = ok (JSON on stdout); 3 = the tree-sitter backend is not built in (CGO-free build), so
// the adapter treats the provider as unavailable rather than failed; 1 = a real error.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/astwalk"
)

func main() {
	if len(os.Args) != 3 || (os.Args[1] != "functions" && os.Args[1] != "metrics") {
		fmt.Fprintln(os.Stderr, "usage: synapse-ast functions|metrics <dir>")
		os.Exit(2)
	}
	var (
		out any
		err error
	)
	switch os.Args[1] {
	case "functions":
		out, err = astwalk.FunctionsFor(context.Background(), os.Args[2])
	case "metrics":
		out, err = astwalk.MetricsFor(context.Background(), os.Args[2])
	}
	if errors.Is(err, astwalk.ErrUnavailable) {
		fmt.Fprintln(os.Stderr, "synapse-ast:", err)
		os.Exit(3)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "synapse-ast:", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "synapse-ast: encode:", err)
		os.Exit(1)
	}
}
