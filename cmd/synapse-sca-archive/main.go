// Command synapse-sca-archive preserves benchmark evidence in content-addressed storage.
//
// Its direct invocation retains the original raw-origin fetch archive behavior. The collect and
// restore subcommands separately archive an already-prepared trusted input root; they never fetch,
// transform, or claim to recover vendor bytes that were not archived when they were available.
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

const usage = `usage:
  synapse-sca-archive --corpus-root PATH --archive-root PATH [--manifest PATH]
  synapse-sca-archive collect --corpus-root PATH --trusted-input-root PATH --binding-spec PATH --archive-root PATH --manifest PATH
  synapse-sca-archive restore --corpus-root PATH --binding-spec PATH --archive-root PATH --manifest PATH --destination-root PATH`

func executeCLI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "collect":
			return executeCollect(ctx, args[1:], stdout, stderr)
		case "restore":
			return executeRestore(ctx, args[1:], stdout, stderr)
		}
	}
	return executeRawArchive(ctx, args, stdout, stderr)
}

// executeRawArchive preserves the v1 direct-origin invocation for existing operators.
func executeRawArchive(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("synapse-sca-archive", flag.ContinueOnError)
	flags.SetOutput(stderr)
	corpusRoot := flags.String("corpus-root", "", "absolute frozen corpus root")
	archiveRoot := flags.String("archive-root", "", "absolute content-addressed archive root")
	manifestPath := flags.String("manifest", "", "optional path to write the raw-origin archive manifest (defaults to <archive-root>/pin-archive.json)")
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

func executeCollect(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("synapse-sca-archive collect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	corpusRoot := flags.String("corpus-root", "", "absolute frozen corpus root")
	trustedInputRoot := flags.String("trusted-input-root", "", "absolute prepared trusted input root")
	bindingSpecPath := flags.String("binding-spec", "", "trusted input binding specification")
	archiveRoot := flags.String("archive-root", "", "absolute content-addressed archive root")
	manifestPath := flags.String("manifest", "", "output path for the materialized trusted-input archive manifest")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if flags.NArg() != 0 || *corpusRoot == "" || *trustedInputRoot == "" || *bindingSpecPath == "" || *archiveRoot == "" || *manifestPath == "" {
		_, _ = fmt.Fprintln(stderr, usage)
		return 1
	}
	if err := collect(ctx, *corpusRoot, *trustedInputRoot, *bindingSpecPath, *archiveRoot, *manifestPath, stdout); err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-archive collect:", err)
		return 1
	}
	return 0
}

func executeRestore(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("synapse-sca-archive restore", flag.ContinueOnError)
	flags.SetOutput(stderr)
	corpusRoot := flags.String("corpus-root", "", "absolute frozen corpus root")
	bindingSpecPath := flags.String("binding-spec", "", "trusted input binding specification")
	archiveRoot := flags.String("archive-root", "", "absolute content-addressed archive root")
	manifestPath := flags.String("manifest", "", "materialized trusted-input archive manifest")
	destinationRoot := flags.String("destination-root", "", "absolute existing empty trusted input destination root")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if flags.NArg() != 0 || *corpusRoot == "" || *bindingSpecPath == "" || *archiveRoot == "" || *manifestPath == "" || *destinationRoot == "" {
		_, _ = fmt.Fprintln(stderr, usage)
		return 1
	}
	if err := restore(ctx, *corpusRoot, *bindingSpecPath, *archiveRoot, *manifestPath, *destinationRoot, stdout); err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-archive restore:", err)
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
	// Incomplete coverage is expected for a corpus pinned before raw archival existed. Exit status
	// reports whether the command ran rather than whether vendors still retain every old byte.
	return nil
}

func collect(ctx context.Context, corpusRoot, trustedInputRoot, bindingSpecPath, archiveRoot, manifestPath string, stdout io.Writer) error {
	catalog, err := loadCatalog(filepath.Join(corpusRoot, "catalog.json"))
	if err != nil {
		return err
	}
	spec, err := loadTrustedInputBindingSpec(bindingSpecPath)
	if err != nil {
		return err
	}
	store, err := scabench.NewPinArchiveStore(archiveRoot)
	if err != nil {
		return err
	}
	archive, err := scabench.CollectTrustedInputArchive(ctx, catalog, spec, trustedInputRoot, store)
	if err != nil {
		return err
	}
	if err := writeTrustedInputArchiveManifest(manifestPath, archive); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "materialized trusted-input archive written to %s\n", manifestPath)
	_, _ = fmt.Fprintf(stdout, "catalog revision %s: %d inventory member(s), root manifest %s\n", archive.CatalogRevision, len(archive.Inventory), archive.RootManifestDigest)
	return nil
}

func restore(ctx context.Context, corpusRoot, bindingSpecPath, archiveRoot, manifestPath, destinationRoot string, stdout io.Writer) error {
	catalog, err := loadCatalog(filepath.Join(corpusRoot, "catalog.json"))
	if err != nil {
		return err
	}
	spec, err := loadTrustedInputBindingSpec(bindingSpecPath)
	if err != nil {
		return err
	}
	archive, err := loadTrustedInputArchive(manifestPath)
	if err != nil {
		return err
	}
	store, err := scabench.NewPinArchiveStore(archiveRoot)
	if err != nil {
		return err
	}
	if err := scabench.RestoreTrustedInputArchive(ctx, catalog, spec, archive, destinationRoot, store); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "materialized trusted-input archive restored to %s\n", destinationRoot)
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

func loadTrustedInputBindingSpec(path string) (bench.TrustedInputBindingSpec, error) {
	file, err := os.Open(path) // #nosec G304 -- operator-supplied binding specification
	if err != nil {
		return bench.TrustedInputBindingSpec{}, fmt.Errorf("open trusted input binding spec: %w", err)
	}
	defer func() { _ = file.Close() }()
	spec, err := bench.DecodeTrustedInputBindingSpec(file)
	if err != nil {
		return bench.TrustedInputBindingSpec{}, err
	}
	return spec, nil
}

func loadTrustedInputArchive(path string) (bench.TrustedInputArchive, error) {
	file, err := os.Open(path) // #nosec G304 -- operator-supplied archive manifest
	if err != nil {
		return bench.TrustedInputArchive{}, fmt.Errorf("open trusted input archive manifest: %w", err)
	}
	defer func() { _ = file.Close() }()
	archive, err := bench.DecodeTrustedInputArchive(file)
	if err != nil {
		return bench.TrustedInputArchive{}, err
	}
	return archive, nil
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

func writeTrustedInputArchiveManifest(path string, archive bench.TrustedInputArchive) error {
	data, err := bench.EncodeTrustedInputArchive(archive)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("trusted input archive manifest parent must be a real directory")
	}
	temporary, err := os.CreateTemp(directory, ".trusted-input-manifest-*")
	if err != nil {
		return fmt.Errorf("create trusted input archive manifest: %w", err)
	}
	name := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(name)
	}()
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write trusted input archive manifest: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync trusted input archive manifest: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close trusted input archive manifest: %w", err)
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return fmt.Errorf("seal trusted input archive manifest: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("publish trusted input archive manifest: %w", err)
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
