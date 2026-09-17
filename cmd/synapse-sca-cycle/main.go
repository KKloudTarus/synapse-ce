// Command synapse-sca-cycle runs the fixed, trusted SCA benchmark cycle.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	capture "github.com/KKloudTarus/synapse-ce/internal/infrastructure/scabench"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func main() {
	os.Exit(executeCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func executeCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "run" {
		_, _ = fmt.Fprintln(stderr, "usage: synapse-sca-cycle run --corpus-root PATH --trusted-input-root PATH --output-root PATH --raw-retention-root PATH --implementation-commit SHA --run-key RUN/ATTEMPT")
		return 1
	}
	flags := flag.NewFlagSet("synapse-sca-cycle run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	corpusRoot := flags.String("corpus-root", "", "absolute frozen corpus root")
	trustedInputRoot := flags.String("trusted-input-root", "", "absolute trusted input root")
	outputRoot := flags.String("output-root", "", "absolute sanitized output root")
	rawRetentionRoot := flags.String("raw-retention-root", "", "absolute protected raw retention root")
	implementationCommit := flags.String("implementation-commit", "", "exact 40-character implementation SHA")
	runKey := flags.String("run-key", "", "run and attempt identifier")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle: positional arguments are not supported")
		return 1
	}
	_, err := capture.Run(context.Background(), capture.RunInput{
		CorpusRoot: *corpusRoot, TrustedInputRoot: *trustedInputRoot, OutputRoot: *outputRoot,
		RawRetentionRoot: *rawRetentionRoot, ImplementationCommit: *implementationCommit, RunKey: *runKey,
	}, capture.RunnerFactory(productionRunner))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle:", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "SCA benchmark cycle completed")
	return 0
}

func productionRunner(limits capture.RuntimeLimits) (ports.ToolRunner, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("hardened sandbox requires Linux")
	}
	delegatedRoot := os.Getenv("SCA_ACCURACY_DELEGATED_CGROUP_ROOT")
	if strings.TrimSpace(delegatedRoot) == "" {
		return nil, errors.New("hardened sandbox requires SCA_ACCURACY_DELEGATED_CGROUP_ROOT captured from the delegated service")
	}
	ready, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	runner, err := sandbox.NewDirectCgroupRunnerReadyAt(ready, time.Duration(limits.TimeoutSeconds)*time.Second, limits.MaxOutputBytes, limits.MemoryBytes, limits.PIDsMax, 250*time.Millisecond, delegatedRoot)
	if err != nil {
		return nil, err
	}
	if runner.ControlSetIdentity() != capture.SandboxIdentityBubblewrapSeccompCgroupV2 {
		return nil, errors.New("required sandbox control set is unavailable")
	}
	return runner, nil
}
