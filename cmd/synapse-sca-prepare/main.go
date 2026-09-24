// Command synapse-sca-prepare creates public diagnostic inputs for an SCA benchmark.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	prepare "github.com/KKloudTarus/synapse-ce/internal/infrastructure/scaprepare"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func main() { os.Exit(execute(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }
func execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("synapse-sca-prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	corpus := flags.String("corpus-root", "", "absolute frozen SCA corpus directory")
	offline := flags.String("offline-root", "", "absolute diagnostic input directory")
	raw := flags.String("raw-retention-root", "", "absolute raw provenance directory outside offline root")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if flags.NArg() != 0 || *corpus == "" || *offline == "" || *raw == "" {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-prepare: --corpus-root, --offline-root, and --raw-retention-root are required")
		return 1
	}
	catalog, err := loadCatalog(filepath.Join(*corpus, "catalog.json"))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-prepare:", err)
		return 1
	}
	spec, err := loadSpec(filepath.Join(*corpus, "trusted-input-bindings.json"))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-prepare:", err)
		return 1
	}
	result, err := prepare.Prepare(ctx, catalog, spec, prepare.Config{OfflineRoot: *offline, RawRetentionRoot: *raw})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-prepare:", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "diagnostic preparation complete: %d artifact(s), %d SBOM(s)\n", len(result.Artifacts), len(result.SBOMs))
	if len(result.Pending) > 0 {
		_, _ = fmt.Fprintf(stdout, "mutable database preparation remains fail-closed: %d binding(s)\n", len(result.Pending))
		return 2
	}
	return 0
}
func loadCatalog(path string) (bench.Catalog, error) {
	f, e := os.Open(path)
	if e != nil {
		return bench.Catalog{}, e
	}
	defer f.Close()
	return bench.DecodeCatalog(f)
}
func loadSpec(path string) (bench.TrustedInputBindingSpec, error) {
	f, e := os.Open(path)
	if e != nil {
		return bench.TrustedInputBindingSpec{}, e
	}
	defer f.Close()
	return bench.DecodeTrustedInputBindingSpec(f)
}
