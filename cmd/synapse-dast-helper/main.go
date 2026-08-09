// synapse-dast-helper owns HTTP clients and authenticated session state outside the API process.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/dastengine"
)

func main() {
	if len(os.Args) != 3 || os.Args[1] != "run" || !strings.HasPrefix(os.Args[2], "--config-sha256=") || len(strings.TrimPrefix(os.Args[2], "--config-sha256=")) != 64 {
		fmt.Fprintln(os.Stderr, "usage: synapse-dast-helper run --config-sha256=<hex>")
		os.Exit(2)
	}
	if err := dastengine.RunHelper(context.Background(), os.Stdin, os.Stdout); err != nil {
		// RunHelper errors deliberately omit request headers, response bodies, and secrets.
		fmt.Fprintln(os.Stderr, "synapse-dast-helper:", err)
		os.Exit(1)
	}
}
