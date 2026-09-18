// Command synapse-reachability-authority curates fixed reachability controller assets.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	reachbench "github.com/KKloudTarus/synapse-ce/internal/infrastructure/reachbench"
)

type prepareBaselineFunc func(context.Context, string, string) error
type deriveCandidateFunc func(context.Context, string, string, string, string, string) error
type prepareCandidateFunc func(context.Context, string) error

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := executeCLI(ctx, os.Args[1:], os.Stdout, os.Stderr, reachbench.PrepareBaselineAuthority, reachbench.DeriveCandidateAuthority, reachbench.PrepareCandidateAuthority)
	stop()
	os.Exit(code)
}

func executeCLI(ctx context.Context, args []string, stdout, stderr io.Writer, prepareBaseline prepareBaselineFunc, deriveCandidate deriveCandidateFunc, prepareCandidate prepareCandidateFunc) int {
	if ctx == nil {
		_, _ = fmt.Fprintln(stderr, "synapse-reachability-authority: context is required")
		return 1
	}
	if len(args) == 0 {
		printUsage(stderr)
		return 1
	}
	var err error
	switch args[0] {
	case "prepare-baseline":
		if len(args) != 3 {
			printUsage(stderr)
			return 1
		}
		err = prepareBaseline(ctx, args[1], args[2])
	case "derive-candidate":
		if len(args) != 6 {
			printUsage(stderr)
			return 1
		}
		err = deriveCandidate(ctx, args[1], args[2], args[3], args[4], args[5])
	case "prepare-candidate":
		if len(args) != 2 {
			printUsage(stderr)
			return 1
		}
		err = prepareCandidate(ctx, args[1])
	default:
		printUsage(stderr)
		return 1
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-reachability-authority:", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "reachability authority %s prepared unsigned, non-authoritative material; external detached review signatures are required before authoritative execution\n", args[0])
	return 0
}

func printUsage(stderr io.Writer) {
	_, _ = fmt.Fprintln(stderr, "usage: synapse-reachability-authority prepare-baseline REVIEW_EVIDENCE_JSON OUTPUT_DIR")
	_, _ = fmt.Fprintln(stderr, "       synapse-reachability-authority derive-candidate BASELINE_PUBLICATION_DIR BASELINE_AUTHORITY_DIR REVIEW_EVIDENCE_JSON DISPOSITION_EVIDENCE_JSON OUTPUT_DIR")
	_, _ = fmt.Fprintln(stderr, "       synapse-reachability-authority prepare-candidate OUTPUT_DIR")
}
