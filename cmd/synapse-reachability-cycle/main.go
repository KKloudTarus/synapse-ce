// Command synapse-reachability-cycle runs the fixed reachability benchmark lifecycle.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	cycle "github.com/KKloudTarus/synapse-ce/internal/infrastructure/reachbench"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	if len(os.Args) == 2 && os.Args[1] == "current-go-binary-scorecard" {
		code := executeCurrentScorecard(ctx, os.Stdout, os.Stderr, cycle.RunCurrentGoBinaryScorecardFromEnvironment)
		stop()
		os.Exit(code)
	}
	code := executeCLI(ctx, os.Args[1:], os.Stdout, os.Stderr, cycle.RunFromEnvironment)
	stop()
	os.Exit(code)
}

func executeCurrentScorecard(ctx context.Context, stdout, stderr io.Writer, run func(context.Context) (cycle.CurrentGoBinaryScorecardResult, error)) int {
	result, err := run(ctx)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-reachability-cycle current-go-binary-scorecard:", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, result.Path)
	return 0
}

func executeCLI(ctx context.Context, args []string, stdout, stderr io.Writer, run func(context.Context, []string) (cycle.Result, error)) int {
	if len(args) != 0 {
		_, _ = fmt.Fprintln(stderr, "synapse-reachability-cycle accepts no flags or positional arguments")
		return 1
	}
	if _, err := run(ctx, nil); err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-reachability-cycle:", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "reachability benchmark lifecycle completed")
	return 0
}
