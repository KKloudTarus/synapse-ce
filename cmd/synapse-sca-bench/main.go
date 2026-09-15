// Command synapse-sca-bench captures one pinned SCA benchmark observation.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	capture "github.com/KKloudTarus/synapse-ce/internal/infrastructure/scabench"
	"github.com/KKloudTarus/synapse-ce/internal/platform/buildinfo"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

type runnerFactory func(capture.RuntimeLimits) (ports.ToolRunner, error)

func main() {
	os.Exit(executeCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func executeCLI(args []string, stdout, stderr io.Writer) int {
	return executeCLIWithDeps(args, stdout, stderr, productionRunner)
}

func executeCLIWithDeps(args []string, stdout, stderr io.Writer, newRunner runnerFactory) int {
	return executeCLIWithContext(args, stdout, stderr, context.Background(), newRunner)
}

func executeCLIWithContext(args []string, stdout, stderr io.Writer, ctx context.Context, newRunner runnerFactory) int {
	if len(args) > 0 && args[0] == "--owned-helper" {
		return executeOwnedHelper(args[1:], stdout, stderr)
	}
	flags := flag.NewFlagSet("synapse-sca-bench", flag.ContinueOnError)
	flags.SetOutput(stderr)
	catalogPath := flags.String("catalog", "", "versioned SCA benchmark catalog JSON")
	manifestPath := flags.String("manifest", "", "versioned capture manifest JSON")
	outputPath := flags.String("output", "", "new output bundle directory")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if flags.NArg() != 0 || *catalogPath == "" || *manifestPath == "" || *outputPath == "" {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-bench: -catalog, -manifest, and -output are required; positional arguments are not supported")
		return 1
	}
	if _, err := os.Lstat(*outputPath); err == nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-bench: output bundle already exists")
		return 1
	} else if !os.IsNotExist(err) {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-bench: inspect output bundle:", err)
		return 1
	}
	catalog, err := decodeCatalog(*catalogPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-bench:", err)
		return 1
	}
	manifest, err := decodeManifest(*manifestPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-bench:", err)
		return 1
	}
	prepared, err := capture.Prepare(catalog, manifest)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-bench:", err)
		return 1
	}
	defer func() { _ = prepared.Close() }()
	if manifest.Capability != nil {
		result, err := capture.CaptureCapabilityPrepared(prepared)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "synapse-sca-bench:", err)
			return 1
		}
		if result.Observation().State != bench.ObservationUnsupported {
			_, _ = fmt.Fprintln(stderr, "synapse-sca-bench: capability capture did not produce an unsupported observation")
			return 1
		}
		if err := capture.WriteBundle(*outputPath, result); err != nil {
			_, _ = fmt.Fprintln(stderr, "synapse-sca-bench:", err)
			return 1
		}
		_, _ = fmt.Fprintln(stdout, "capability unsupported")
		return 0
	}
	runner, err := newRunner(manifest.Limits)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-bench: hardened sandbox unavailable")
		return 1
	}
	result, err := capture.NewCapturer(runner).CapturePrepared(ctx, prepared)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-bench:", err)
		return 1
	}
	if err := capture.WriteBundle(*outputPath, result); err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-bench:", err)
		return 1
	}
	if result.Observation().State == bench.ObservationIncomplete {
		return 2
	}
	_, _ = fmt.Fprintln(stdout, "capture complete")
	return 0
}

// executeOwnedHelper is an internal sandbox entrypoint, not a user-facing capture mode.
func executeOwnedHelper(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("synapse-sca-bench-owned-helper", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("database", "", "owned advisory corpus directory")
	databaseFormat := flags.String("database-format", "", "declared owned advisory corpus format")
	sbomPath := flags.String("sbom", "", "CycloneDX SBOM")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *databasePath == "" || *databaseFormat == "" || *sbomPath == "" {
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "synapse-sca-bench owned helper:", err)
		} else {
			_, _ = fmt.Fprintln(stderr, "synapse-sca-bench owned helper: -database, -database-format, and -sbom are required")
		}
		return 1
	}
	wire, err := capture.RunOwnedWire(context.Background(), *databasePath, capture.DatabaseFormat(*databaseFormat), *sbomPath, buildinfo.App())
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-bench owned helper:", err)
		return 1
	}
	if _, err := stdout.Write(wire); err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-bench owned helper: write result:", err)
		return 1
	}
	return 0
}

func decodeCatalog(path string) (bench.Catalog, error) {
	file, err := os.Open(path)
	if err != nil {
		return bench.Catalog{}, errors.New("open catalog")
	}
	defer func() { _ = file.Close() }()
	return bench.DecodeCatalog(file)
}

func decodeManifest(path string) (capture.CaptureManifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return capture.CaptureManifest{}, errors.New("open manifest")
	}
	defer func() { _ = file.Close() }()
	return capture.DecodeCaptureManifest(file)
}

func productionRunner(limits capture.RuntimeLimits) (ports.ToolRunner, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("hardened sandbox requires Linux")
	}
	ready, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	runner, err := sandbox.NewDirectCgroupRunnerReady(
		ready,
		time.Duration(limits.TimeoutSeconds)*time.Second,
		limits.MaxOutputBytes,
		limits.MemoryBytes,
		limits.PIDsMax,
		250*time.Millisecond,
	)
	if err != nil {
		return nil, err
	}
	if runner.ControlSetIdentity() != capture.SandboxIdentityBubblewrapSeccompCgroupV2 {
		return nil, errors.New("required sandbox control set is unavailable")
	}
	return runner, nil
}
