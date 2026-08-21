// Package releaseevidence creates and verifies deterministic manifests for
// promoted release assets. The manifest binds a complete asset set to one
// repository, release identifier, and source revision.
package releaseevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	SchemaVersion    = "synapse-release-evidence-v1"
	DefaultManifest  = "release-evidence.json"
	maxArtifactCount = 4096
	maxManifestBytes = 4 << 20
	maxArtifactName  = 255
	manifestFilePerm = 0o600
)

var (
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	releasePattern    = regexp.MustCompile(`^v[0-9A-Za-z][0-9A-Za-z._+-]*$`)
	assetNamePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
)

// Kind identifies the role an entry plays in release verification.
type Kind string

const (
	KindArtifact  Kind = "artifact"
	KindChecksum  Kind = "checksum"
	KindSBOM      Kind = "sbom"
	KindSignature Kind = "signature"
)

// Identity binds an evidence manifest to its trusted source.
type Identity struct {
	Repository     string `json:"repository"`
	SourceRevision string `json:"source_revision"`
	Release        string `json:"release"`
}

// Artifact is one regular file in the promoted release asset set.
type Artifact struct {
	Name   string `json:"name"`
	Kind   Kind   `json:"kind"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest is the canonical, timestamp-free release evidence document.
// Artifact entries are always sorted by name.
type Manifest struct {
	SchemaVersion string     `json:"schema_version"`
	Identity      Identity   `json:"identity"`
	Artifacts     []Artifact `json:"artifacts"`
}

// Generate inventories root and creates manifestPath without overwriting an
// existing file. manifestPath must be a direct child of root so verification
// can prove that no unlisted release asset exists.
func Generate(root, manifestPath string, identity Identity) (Manifest, error) {
	root, manifestPath, err := validatePaths(root, manifestPath)
	if err != nil {
		return Manifest{}, err
	}
	if err := validateIdentity(identity); err != nil {
		return Manifest{}, err
	}
	if _, err := os.Lstat(manifestPath); err == nil {
		return Manifest{}, fmt.Errorf("create release evidence: %s already exists", filepath.Base(manifestPath))
	} else if !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, fmt.Errorf("inspect release evidence output: %w", err)
	}

	artifacts, err := inventory(root, filepath.Base(manifestPath), false)
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		Identity:      identity,
		Artifacts:     artifacts,
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	encoded, err := encodeManifest(manifest)
	if err != nil {
		return Manifest{}, fmt.Errorf("encode release evidence: %w", err)
	}
	if err := writeNewFile(manifestPath, encoded); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func inventory(root, manifestName string, permitManifestSignature bool) ([]Artifact, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read release asset directory: %w", err)
	}
	if len(entries) > maxArtifactCount+2 {
		return nil, fmt.Errorf("release asset directory contains more than %d entries", maxArtifactCount)
	}

	artifacts := make([]Artifact, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == manifestName || (permitManifestSignature && name == manifestName+".sig") {
			continue
		}
		if err := validateAssetName(name); err != nil {
			return nil, err
		}
		path := filepath.Join(root, name)
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect release asset %q: %w", name, err)
		}
		if entry.Type()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("release asset %q is not a regular file", name)
		}
		digest, size, err := hashRegularFile(path, info)
		if err != nil {
			return nil, fmt.Errorf("hash release asset %q: %w", name, err)
		}
		artifacts = append(artifacts, Artifact{
			Name: name, Kind: classify(name), SHA256: digest, Size: size,
		})
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Name < artifacts[j].Name })
	return artifacts, nil
}

func hashRegularFile(path string, expected os.FileInfo) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
		return "", 0, errors.New("file changed while it was being opened")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	after, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if !os.SameFile(opened, after) || !os.SameFile(opened, current) ||
		after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) || size != opened.Size() {
		return "", 0, errors.New("file changed while it was being hashed")
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func classify(name string) Kind {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".sig"), strings.HasSuffix(lower, ".asc"):
		return KindSignature
	case strings.HasSuffix(lower, ".sbom.json"):
		return KindSBOM
	case lower == "sha256sums", strings.HasSuffix(lower, "checksums.txt"), strings.HasSuffix(lower, ".sha256"):
		return KindChecksum
	default:
		return KindArtifact
	}
}

func validatePaths(root, manifestPath string) (string, string, error) {
	root = filepath.Clean(strings.TrimSpace(root))
	if root == "." || root == "" {
		return "", "", errors.New("release asset directory is required")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return "", "", fmt.Errorf("inspect release asset directory: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return "", "", errors.New("release asset path must be a non-symlink directory")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", "", fmt.Errorf("resolve release asset directory: %w", err)
	}

	manifestPath = filepath.Clean(strings.TrimSpace(manifestPath))
	if manifestPath == "." || manifestPath == "" {
		manifestPath = filepath.Join(absRoot, DefaultManifest)
	}
	absManifest, err := filepath.Abs(manifestPath)
	if err != nil {
		return "", "", fmt.Errorf("resolve release evidence path: %w", err)
	}
	if filepath.Dir(absManifest) != absRoot {
		return "", "", errors.New("release evidence must be a direct child of the asset directory")
	}
	if err := validateAssetName(filepath.Base(absManifest)); err != nil {
		return "", "", fmt.Errorf("invalid release evidence name: %w", err)
	}
	return absRoot, absManifest, nil
}

func validateIdentity(identity Identity) error {
	if len(identity.Repository) > 200 || !repositoryPattern.MatchString(identity.Repository) {
		return errors.New("repository must use the owner/name form")
	}
	if !isSourceRevision(identity.SourceRevision) {
		return errors.New("source revision must be a lowercase 40- or 64-character hexadecimal digest")
	}
	if len(identity.Release) > 128 || !releasePattern.MatchString(identity.Release) {
		return errors.New("release must be a portable v-prefixed identifier")
	}
	return nil
}

func validateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported release evidence schema %q", manifest.SchemaVersion)
	}
	if err := validateIdentity(manifest.Identity); err != nil {
		return err
	}
	if len(manifest.Artifacts) == 0 {
		return errors.New("release evidence contains no assets")
	}
	if len(manifest.Artifacts) > maxArtifactCount {
		return fmt.Errorf("release evidence contains more than %d assets", maxArtifactCount)
	}
	primary := 0
	previous := ""
	for i, artifact := range manifest.Artifacts {
		if err := validateAssetName(artifact.Name); err != nil {
			return err
		}
		if i > 0 && artifact.Name <= previous {
			return errors.New("release evidence assets must have unique names in lexical order")
		}
		previous = artifact.Name
		switch artifact.Kind {
		case KindArtifact:
			primary++
		case KindChecksum, KindSBOM, KindSignature:
		default:
			return fmt.Errorf("release asset %q has unsupported kind %q", artifact.Name, artifact.Kind)
		}
		if artifact.Kind != classify(artifact.Name) {
			return fmt.Errorf("release asset %q has kind %q, expected %q", artifact.Name, artifact.Kind, classify(artifact.Name))
		}
		if !isSHA256(artifact.SHA256) {
			return fmt.Errorf("release asset %q has an invalid SHA-256 digest", artifact.Name)
		}
		if artifact.Size < 0 {
			return fmt.Errorf("release asset %q has a negative size", artifact.Name)
		}
	}
	if primary == 0 {
		return errors.New("release evidence contains no primary artifact")
	}
	return nil
}

func validateAssetName(name string) error {
	if len(name) == 0 || len(name) > maxArtifactName || !assetNamePattern.MatchString(name) ||
		name == "." || name == ".." || filepath.Base(name) != name {
		return fmt.Errorf("release asset name %q is not portable", name)
	}
	return nil
}

func isSourceRevision(value string) bool {
	return (len(value) == 40 || len(value) == 64) && isLowerHex(value)
}

func isSHA256(value string) bool {
	return len(value) == sha256.Size*2 && isLowerHex(value)
}

func isLowerHex(value string) bool {
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func encodeManifest(manifest Manifest) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(manifest); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func writeNewFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, manifestFilePerm)
	if err != nil {
		return fmt.Errorf("create release evidence: %w", err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("write release evidence: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync release evidence: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close release evidence: %w", err)
	}
	ok = true
	return nil
}
