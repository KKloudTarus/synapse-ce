// synapse-sandbox-check proves the production sandbox runner's confinement posture.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/composition/sandboxcheck"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
)

const (
	exitConformanceFailed = 1
	exitUsage             = 2
	exitUnavailable       = 3
)

func main() {
	if handled, code := runProbe(os.Args[1:], os.Stdout); handled {
		os.Exit(code)
	}

	fs := flag.NewFlagSet("synapse-sandbox-check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	mode := fs.String("mode", "startup", "conformance mode: startup or full")
	strict := fs.Bool("strict", false, "fail when a required control is unenforced")
	output := fs.String("output", "", "JSON report path, or - for stdout")
	readyWait := fs.Duration("ready-wait", 60*time.Second, "in strict mode, how long to wait for delegated cgroup limits to become available at boot")
	if err := fs.Parse(os.Args[1:]); err != nil || fs.NArg() != 0 {
		if err == nil {
			fmt.Fprintln(os.Stderr, "synapse-sandbox-check: positional arguments are not supported")
		}
		os.Exit(exitUsage)
	}
	if *mode != "startup" && *mode != "full" {
		fmt.Fprintln(os.Stderr, "synapse-sandbox-check: -mode must be startup or full")
		os.Exit(exitUsage)
	}

	r, err := sandboxcheck.Run(*mode, *strict, *readyWait)
	if err != nil {
		fmt.Fprintln(os.Stderr, "synapse-sandbox-check:", redact.String(err.Error(), nil))
		if errors.Is(err, sandbox.ErrUnavailable) {
			os.Exit(exitUnavailable)
		}
		os.Exit(exitConformanceFailed)
	}
	if err := sandboxcheck.WriteReport(*output, r, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "synapse-sandbox-check:", redact.String(err.Error(), nil))
		os.Exit(exitConformanceFailed)
	}
	if sandboxcheck.Failed(r) {
		os.Exit(exitConformanceFailed)
	}
}
