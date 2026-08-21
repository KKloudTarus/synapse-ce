// Command synapse-release-evidence creates and verifies deterministic release
// asset manifests. Detached-signature and GitHub attestation verification are
// deliberately separate trust-boundary steps.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/releaseevidence"
)

func main() {
	if err := execute(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "synapse-release-evidence: %s\n", err)
		os.Exit(1)
	}
}

func execute(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return errors.New("a generate or verify command is required")
	}
	switch args[0] {
	case "generate":
		return runGenerate(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runGenerate(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("generate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", "", "directory containing the complete release asset set")
	output := flags.String("output", "", "manifest path (default: <dir>/release-evidence.json)")
	repository, revision, release := identityFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("generate does not accept positional arguments")
	}
	if strings.TrimSpace(*dir) == "" {
		return errors.New("--dir is required")
	}
	path := strings.TrimSpace(*output)
	if path == "" {
		path = filepath.Join(*dir, releaseevidence.DefaultManifest)
	}
	manifest, err := releaseevidence.Generate(*dir, path, identity(*repository, *revision, *release))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "generated %s with %d release assets\n", path, len(manifest.Artifacts))
	return err
}

func runVerify(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", "", "directory containing the downloaded release asset set")
	manifestPath := flags.String("manifest", "", "manifest path (default: <dir>/release-evidence.json)")
	repository, revision, release := identityFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("verify does not accept positional arguments")
	}
	if strings.TrimSpace(*dir) == "" {
		return errors.New("--dir is required")
	}
	path := strings.TrimSpace(*manifestPath)
	if path == "" {
		path = filepath.Join(*dir, releaseevidence.DefaultManifest)
	}
	manifest, err := releaseevidence.Verify(*dir, path, identity(*repository, *revision, *release))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "verified %s at %s with %d release assets\n",
		manifest.Identity.Release, manifest.Identity.SourceRevision, len(manifest.Artifacts))
	return err
}

func identityFlags(flags *flag.FlagSet) (*string, *string, *string) {
	repository := flags.String("repository", "", "expected GitHub repository in owner/name form")
	revision := flags.String("revision", "", "expected lowercase source commit digest")
	release := flags.String("release", "", "expected v-prefixed release identifier")
	return repository, revision, release
}

func identity(repository, revision, release string) releaseevidence.Identity {
	return releaseevidence.Identity{
		Repository: strings.TrimSpace(repository), SourceRevision: strings.TrimSpace(revision), Release: strings.TrimSpace(release),
	}
}

func printUsage(output io.Writer) {
	_, _ = fmt.Fprintln(output, "usage: synapse-release-evidence <generate|verify> [flags]")
}
