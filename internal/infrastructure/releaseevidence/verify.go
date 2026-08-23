package releaseevidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Verify parses a canonical manifest, checks its expected identity, hashes all
// listed files, and rejects any unlisted release asset.
func Verify(root, manifestPath string, expected Identity) (Manifest, error) {
	root, manifestPath, err := validatePaths(root, manifestPath)
	if err != nil {
		return Manifest{}, err
	}
	if err := validateIdentity(expected); err != nil {
		return Manifest{}, fmt.Errorf("invalid expected identity: %w", err)
	}
	manifest, err := loadManifest(manifestPath)
	if err != nil {
		return Manifest{}, err
	}
	if manifest.Identity != expected {
		return Manifest{}, errors.New("release evidence identity does not match the expected repository, revision, and release")
	}

	actual, err := inventory(root, filepath.Base(manifestPath), true)
	if err != nil {
		return Manifest{}, err
	}
	if len(actual) != len(manifest.Artifacts) {
		return Manifest{}, fmt.Errorf("release asset set mismatch: manifest has %d assets, directory has %d", len(manifest.Artifacts), len(actual))
	}
	for i := range actual {
		want := manifest.Artifacts[i]
		got := actual[i]
		if want.Name != got.Name {
			return Manifest{}, fmt.Errorf("release asset set mismatch at %q", got.Name)
		}
		if want.Kind != got.Kind || want.Size != got.Size || want.SHA256 != got.SHA256 {
			return Manifest{}, fmt.Errorf("release asset %q failed integrity verification", got.Name)
		}
	}
	return manifest, nil
}

func loadManifest(path string) (Manifest, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("inspect release evidence: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Manifest{}, errors.New("release evidence must be a regular, non-symlink file")
	}
	if info.Size() > maxManifestBytes {
		return Manifest{}, fmt.Errorf("release evidence exceeds %d bytes", maxManifestBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("open release evidence: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return Manifest{}, fmt.Errorf("inspect open release evidence: %w", err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return Manifest{}, errors.New("release evidence changed while it was being opened")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxManifestBytes+1))
	if err != nil {
		return Manifest{}, fmt.Errorf("read release evidence: %w", err)
	}
	if len(content) > maxManifestBytes {
		return Manifest{}, fmt.Errorf("release evidence exceeds %d bytes", maxManifestBytes)
	}
	after, err := file.Stat()
	if err != nil {
		return Manifest{}, fmt.Errorf("inspect release evidence after read: %w", err)
	}
	current, err := os.Lstat(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("reinspect release evidence: %w", err)
	}
	if !os.SameFile(opened, after) || !os.SameFile(opened, current) ||
		after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return Manifest{}, errors.New("release evidence changed while it was being read")
	}

	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode release evidence: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Manifest{}, errors.New("release evidence contains trailing JSON data")
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, fmt.Errorf("validate release evidence: %w", err)
	}
	canonical, err := encodeManifest(manifest)
	if err != nil {
		return Manifest{}, fmt.Errorf("canonicalize release evidence: %w", err)
	}
	if !bytes.Equal(content, canonical) {
		return Manifest{}, errors.New("release evidence is not canonically encoded")
	}
	return manifest, nil
}
