package scabench

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

// restoreCandidateBundle verifies a retained candidate's input archive and restores it directly
// into this run's protected capture root. Its archived host attestation is replaced before binding.
func restoreCandidateBundle(ctx context.Context, bundleRoot, attestationPath, captureRoot string) error {
	if _, err := candidatePhysicalDirectory("input bundle root", bundleRoot); err != nil {
		return err
	}
	if _, err := candidatePhysicalDirectory("archived candidate corpus", filepath.Join(bundleRoot, "candidate-corpus")); err != nil {
		return err
	}
	catalogBody, err := readPinnedBundleFile(bundleRoot, "candidate-corpus/catalog.json", candidateCorpusFileBytes)
	if err != nil {
		return fmt.Errorf("read archived candidate catalog: %w", err)
	}
	catalog, err := bench.DecodeCatalog(bytes.NewReader(catalogBody))
	if err != nil {
		return fmt.Errorf("decode archived candidate catalog: %w", err)
	}
	specBody, err := readPinnedBundleFile(bundleRoot, "candidate-corpus/trusted-input-bindings.json", bench.MaxTrustedInputArchiveManifestBytes)
	if err != nil {
		return fmt.Errorf("read archived input bindings: %w", err)
	}
	spec, err := bench.DecodeTrustedInputBindingSpec(bytes.NewReader(specBody))
	if err != nil {
		return fmt.Errorf("decode archived input bindings: %w", err)
	}
	manifestBody, err := readPinnedBundleFile(bundleRoot, "input-archive.json", bench.MaxTrustedInputArchiveManifestBytes)
	if err != nil {
		return fmt.Errorf("read archived input manifest: %w", err)
	}
	archive, err := bench.DecodeTrustedInputArchive(bytes.NewReader(manifestBody))
	if err != nil {
		return fmt.Errorf("decode archived input manifest: %w", err)
	}
	attestation, err := readPinnedBundleFile(filepath.Dir(attestationPath), filepath.Base(attestationPath), candidateAttestationBytes)
	if err != nil {
		return fmt.Errorf("read current host attestation: %w", err)
	}
	if len(attestation) == 0 {
		return errors.New("current host attestation must not be empty")
	}
	store, err := OpenPinArchiveStoreReadOnly(filepath.Join(bundleRoot, "input-cas"))
	if err != nil {
		return fmt.Errorf("open archived input objects: %w", err)
	}
	if err := RestoreTrustedInputArchive(ctx, catalog, spec, archive, captureRoot, store); err != nil {
		return fmt.Errorf("restore pinned input objects: %w", err)
	}
	if _, err := os.Lstat(filepath.Join(captureRoot, "repository", "reviews")); err == nil {
		return errors.New("candidate input bundle must not include trusted review or disposition captures")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect candidate review inputs: %w", err)
	}
	if err := replaceCandidateHostAttestation(filepath.Join(captureRoot, filepath.FromSlash(trustedEnvironmentAttestationLocator)), attestation); err != nil {
		return err
	}
	return nil
}

func replaceCandidateHostAttestation(destination string, body []byte) (returnErr error) {
	info, err := os.Lstat(destination)
	if err != nil {
		return fmt.Errorf("inspect restored environment attestation: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("restored environment attestation must be a regular file")
	}
	parent := filepath.Dir(destination)
	parentInfo, err := os.Lstat(parent)
	if err != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return errors.New("restored environment directory must be a real directory")
	}
	parentMode := parentInfo.Mode().Perm()
	if err := os.Chmod(parent, parentMode|0o700); err != nil {
		return fmt.Errorf("open restored environment directory for attestation replacement: %w", err)
	}
	defer func() {
		returnErr = errors.Join(returnErr, os.Chmod(parent, parentMode))
	}()
	temporary, err := os.CreateTemp(parent, ".current-attestation-*")
	if err != nil {
		return fmt.Errorf("create current host attestation: %w", err)
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write current host attestation: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync current host attestation: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close current host attestation: %w", err)
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return fmt.Errorf("protect current host attestation: %w", err)
	}
	if err := os.Rename(name, destination); err != nil {
		return fmt.Errorf("replace archived host attestation: %w", err)
	}
	return nil
}
