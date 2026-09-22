// Command synapse-sca-archive preserves the exact bytes behind a benchmark catalog's pins.
//
// A catalog pin records a vendor artifact's digest and origin but not its bytes. Vendors republish
// these feeds in place, so once a document is regenerated the pinned bytes are unretrievable and a
// recapture on fresh infrastructure cannot reproduce the pinned digest. This command archives what is
// still retrievable into content-addressed storage and reports exactly which evidence has already
// drifted away, so an operator learns the true reproducibility of a corpus rather than discovering it
// as an unexplained pin mismatch mid-capture.
//
// It is a maintainer tool run outside the ordinary benchmark cycle, alongside oracle and catalog
// preparation. It never writes to the corpus.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	scabench "github.com/KKloudTarus/synapse-ce/internal/infrastructure/scabench"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(executeCLI(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

const usage = "usage: synapse-sca-archive --corpus-root PATH --archive-root PATH [--manifest PATH]"

func executeCLI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("synapse-sca-archive", flag.ContinueOnError)
	flags.SetOutput(stderr)
	corpusRoot := flags.String("corpus-root", "", "absolute frozen corpus root")
	archiveRoot := flags.String("archive-root", "", "absolute content-addressed archive root")
	manifestPath := flags.String("manifest", "", "optional path to write the archive manifest (defaults to <archive-root>/pin-archive.json)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-archive: positional arguments are not supported")
		return 1
	}
	if *corpusRoot == "" || *archiveRoot == "" {
		_, _ = fmt.Fprintln(stderr, usage)
		return 1
	}
	if err := run(ctx, *corpusRoot, *archiveRoot, *manifestPath, stdout); err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-archive:", err)
		return 1
	}
	return 0
}

func run(ctx context.Context, corpusRoot, archiveRoot, manifestPath string, stdout io.Writer) error {
	catalog, err := loadCatalog(filepath.Join(corpusRoot, "catalog.json"))
	if err != nil {
		return err
	}
	store, err := scabench.NewPinArchiveStore(archiveRoot)
	if err != nil {
		return err
	}
	result, err := scabench.ArchiveCatalogPins(ctx, catalog, scabench.NewHTTPPinFetcher(), store, time.Now())
	if err != nil {
		return err
	}
	if manifestPath == "" {
		manifestPath = filepath.Join(archiveRoot, "pin-archive.json")
	}
	if len(result.Archive.Entries) > 0 {
		if err := writeManifest(manifestPath, result.Archive); err != nil {
			return err
		}
	}
	report(stdout, catalog, result, manifestPath)
	// Incomplete coverage is the expected state for a corpus pinned before archival existed, so it is
	// reported rather than treated as a command failure. Exit status reflects whether the command ran,
	// not whether the vendor still serves every pinned byte.
	return nil
}

func loadCatalog(path string) (bench.Catalog, error) {
	file, err := os.Open(path) // #nosec G304 -- operator-supplied corpus path
	if err != nil {
		return bench.Catalog{}, fmt.Errorf("open catalog: %w", err)
	}
	defer func() { _ = file.Close() }()
	catalog, err := bench.DecodeCatalog(file)
	if err != nil {
		return bench.Catalog{}, fmt.Errorf("decode catalog: %w", err)
	}
	return catalog, nil
}

func writeManifest(path string, archive bench.PinArchive) error {
	data, err := json.MarshalIndent(archive, "", "  ")
	if err != nil {
		return fmt.Errorf("encode archive manifest: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write archive manifest: %w", err)
	}
	return nil
}

func report(stdout io.Writer, catalog bench.Catalog, result scabench.ArchiveResult, manifestPath string) {
	archivable := bench.ArchivablePins(catalog)
	_, _ = fmt.Fprintf(stdout, "catalog revision %s: %d of %d fetchable pins archived\n",
		catalog.Revision, len(result.Archive.Entries), len(archivable))
	for _, entry := range result.Unverified {
		// Deliberately not called drift: the pin may describe a file extracted from this download rather
		// than the download itself, and the fetched bytes cannot distinguish that from republication.
		_, _ = fmt.Fprintf(stdout, "  unverified %s\n    pinned  %s\n    fetched %s\n    origin  %s\n",
			entry.Reference, entry.Pinned, entry.Fetched, entry.Origin)
	}
	for _, failure := range result.Failed {
		_, _ = fmt.Fprintf(stdout, "  unreachable %s\n    origin %s\n    reason %s\n",
			failure.Reference, failure.Origin, failure.Reason)
	}
	for _, entry := range result.Unsupported {
		_, _ = fmt.Fprintf(stdout, "  unsupported %s\n    origin %s\n    reason %s\n",
			entry.Reference, entry.Origin, entry.Reason)
	}
	if len(result.Archive.Entries) > 0 {
		_, _ = fmt.Fprintf(stdout, "manifest written to %s\n", manifestPath)
	}
	if err := bench.ValidateArchiveCoverage(catalog, result.Archive); err != nil {
		_, _ = fmt.Fprintf(stdout, "coverage incomplete: %v\n", err)
		return
	}
	_, _ = fmt.Fprintln(stdout, "coverage complete: this corpus is byte-reproducible from the archive")
}
