// Command synapse-reachability-cycle runs the fixed reachability benchmark lifecycle.
package main

import (
	"context"
	"fmt"
	"io"
	"os"

	cycle "github.com/KKloudTarus/synapse-ce/internal/infrastructure/reachbench"
)

func main() {
	os.Exit(executeCLI(os.Args[1:], os.Stdout, os.Stderr, cycle.RunFromEnvironment))
}

func executeCLI(args []string, stdout, stderr io.Writer, run func(context.Context, []string) (cycle.Result, error)) int {
	if len(args) != 0 {
		_, _ = fmt.Fprintln(stderr, "synapse-reachability-cycle accepts no flags or positional arguments")
		return 1
	}
	if _, err := run(context.Background(), nil); err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-reachability-cycle:", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "reachability benchmark lifecycle completed")
	return 0
}
