package reachbench

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

const maxAuthorityPublicationFiles = 16

// authorityGitEnvironment drops every inherited Git selector before permitting
// only the non-interactive, config-isolated environment required for inspection.
func authorityGitEnvironment() []string {
	environment := make([]string, 0, len(os.Environ())+7)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(strings.ToUpper(name), "GIT_") || strings.EqualFold(name, "GCM_INTERACTIVE") {
			continue
		}
		environment = append(environment, entry)
	}
	return append(environment,
		"GIT_ASKPASS=",
		"GIT_CONFIG_COUNT=0",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_PARAMETERS=",
		"GIT_NO_REPLACE_OBJECTS=1",
		"GIT_TERMINAL_PROMPT=0",
	)
}

func runAuthorityGit(ctx context.Context, binary string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, binary, args...)
	command.Env = authorityGitEnvironment()
	return command.Output()
}

func authorityPublicationLimits() benchcycle.PublicationLimits {
	return benchcycle.PublicationLimits{
		MaxFileBytes:  benchmark.MaxJSONBytes,
		MaxTotalBytes: benchmark.MaxJSONBytes * maxAuthorityPublicationFiles,
		MaxFiles:      maxAuthorityPublicationFiles,
	}
}

func (curator *AuthorityCurator) publishAuthority(ctx context.Context, output string, protectedDirectories []string, assets []authorityAsset, cleanup benchcycle.PublicationCleanup, verify func(context.Context, string) error) (err error) {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := validateAuthorityOutputDestination(output, protectedDirectories...); err != nil {
		return err
	}
	publication, err := benchcycle.BeginPublication(output, authorityPublicationLimits(), cleanup, func(verifyCtx context.Context, stage string, _ []benchcycle.FileIdentity) error {
		return verify(verifyCtx, stage)
	})
	if err != nil {
		return fmt.Errorf("begin authority publication: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if abortErr := publication.Abort(); abortErr != nil {
			err = errors.Join(err, abortErr)
		}
	}()
	for _, asset := range assets {
		if err := contextError(ctx); err != nil {
			return err
		}
		if _, err := publication.WriteBytes(ctx, asset.path, asset.body); err != nil {
			return fmt.Errorf("stage authority asset %q: %w", asset.path, err)
		}
	}
	if err := publication.Commit(ctx); err != nil {
		return fmt.Errorf("publish authority assets: %w", err)
	}
	committed = true
	return nil
}

func validateAuthorityOutputDestination(directory string, protectedDirectories ...string) error {
	if err := benchcycle.ValidateAbsolutePath("authority output directory", directory); err != nil {
		return err
	}
	output, err := filepath.Abs(directory)
	if err != nil {
		return fmt.Errorf("resolve authority output directory: %w", err)
	}
	if err := benchcycle.EnsureAbsent(output, "authority output directory"); err != nil {
		return err
	}
	for _, protected := range protectedDirectories {
		if pathsOverlap(output, protected) {
			return errors.New("authority output directory must not overlap an input directory")
		}
	}
	return nil
}

func (curator *AuthorityCurator) revalidateCheckout(ctx context.Context, captured authorityCheckout) error {
	current, err := curator.inspectCheckout(ctx)
	if err != nil {
		return fmt.Errorf("reinspect authority checkout before publication: %w", err)
	}
	if current.root != captured.root || current.harness != captured.harness || current.baselineAnalyzer != captured.baselineAnalyzer {
		return errors.New("authority checkout changed before publication")
	}
	return nil
}

func (curator *AuthorityCurator) assertNoReplacementRefs(ctx context.Context, root string) error {
	refs, err := curator.git(ctx, root, "for-each-ref", "--format=%(refname)", "refs/replace")
	if err != nil {
		return fmt.Errorf("inspect Git replacement refs: %w", err)
	}
	if strings.TrimSpace(string(refs)) != "" {
		return errors.New("authority curator rejects Git replacement refs")
	}
	for _, item := range []struct {
		name  string
		label string
	}{
		{name: "objects/info/alternates", label: "Git alternate object database"},
		{name: "info/grafts", label: "Git graft files"},
	} {
		pathOutput, err := curator.git(ctx, root, "rev-parse", "--git-path", item.name)
		if err != nil {
			return fmt.Errorf("resolve %s path: %w", item.label, err)
		}
		path := strings.TrimSpace(string(pathOutput))
		if path == "" {
			return fmt.Errorf("git did not return a %s path", item.label)
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, filepath.FromSlash(path))
		}
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("authority curator rejects %s", item.label)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect %s path: %w", item.label, err)
		}
	}
	return nil
}

func (curator *AuthorityCurator) loadCommittedCandidateAuthority(ctx context.Context, checkout authorityCheckout) (candidateAuthority, error) {
	capture, err := curator.captureCommittedCandidateAuthorityFiles(ctx, checkout)
	if err != nil {
		return candidateAuthority{}, err
	}
	stage, err := os.MkdirTemp("", "synapse-reachability-authority-source-")
	if err != nil {
		return candidateAuthority{}, fmt.Errorf("create private candidate authority source: %w", err)
	}
	defer func() { _ = os.RemoveAll(stage) }()
	assets := make([]authorityAsset, 0, len(capture.files))
	for _, relative := range expectedCandidateAuthorityFiles() {
		assets = append(assets, authorityAsset{path: relative, body: capture.files[relative]})
	}
	if err := stageAuthorityAssets(stage, []string{authoritySupportingDirectory}, assets); err != nil {
		return candidateAuthority{}, fmt.Errorf("stage captured candidate authority source: %w", err)
	}
	authority, err := loadCandidateAuthority(ctx, stage)
	if err != nil {
		return candidateAuthority{}, err
	}
	authority.inventoryDigest = capture.inventoryDigest
	return authority, nil
}

type committedCandidateAuthorityCapture struct {
	files           map[string][]byte
	inventoryDigest string
}

func (curator *AuthorityCurator) captureCommittedCandidateAuthorityFiles(ctx context.Context, checkout authorityCheckout) (committedCandidateAuthorityCapture, error) {
	if err := contextError(ctx); err != nil {
		return committedCandidateAuthorityCapture{}, err
	}
	if _, err := authorityDirectoryInCheckout(ctx, checkout.root, TrustedBundleRelativePath); err != nil {
		return committedCandidateAuthorityCapture{}, err
	}
	entries, err := curator.git(ctx, checkout.root, "ls-tree", "-r", "-z", "--full-tree", checkout.harness.Tree, "--", TrustedBundleRelativePath)
	if err != nil {
		return committedCandidateAuthorityCapture{}, fmt.Errorf("inspect committed candidate authority tree: %w", err)
	}
	expected := expectedCandidateAuthorityEntries()
	actual, err := parseAuthorityTreeEntries(entries, TrustedBundleRelativePath)
	if err != nil {
		return committedCandidateAuthorityCapture{}, err
	}
	if len(actual) != len(expected) {
		return committedCandidateAuthorityCapture{}, errors.New("committed candidate authority inventory is not exact")
	}
	if err := curator.assertCandidateAuthorityIndex(ctx, checkout); err != nil {
		return committedCandidateAuthorityCapture{}, err
	}
	files := make(map[string][]byte, len(expected))
	inventory := make([]candidateAuthorityInventoryEntry, 0, len(expected))
	for _, relative := range expectedCandidateAuthorityFiles() {
		entry, found := actual[relative]
		if !found || entry.mode != "100644" || entry.objectType != "blob" || !benchcycle.FullSHA(entry.object) {
			return committedCandidateAuthorityCapture{}, errors.New("committed candidate authority requires ordinary 100644 blobs with exact inventory")
		}
		body, err := curator.git(ctx, checkout.root, "cat-file", "blob", entry.object)
		if err != nil {
			return committedCandidateAuthorityCapture{}, fmt.Errorf("read committed candidate authority blob %q: %w", relative, err)
		}
		if int64(len(body)) > benchmark.MaxJSONBytes {
			return committedCandidateAuthorityCapture{}, fmt.Errorf("committed candidate authority blob %q exceeds JSON size bound", relative)
		}
		files[relative] = body
		inventory = append(inventory, candidateAuthorityInventoryEntry{Path: relative, Mode: entry.mode, Digest: benchmark.SHA256Digest(body)})
	}
	inventoryDigest, err := candidateAuthorityInventoryDigest(inventory)
	if err != nil {
		return committedCandidateAuthorityCapture{}, err
	}
	return committedCandidateAuthorityCapture{files: files, inventoryDigest: inventoryDigest}, nil
}

type authorityTreeEntry struct {
	mode       string
	objectType string
	object     string
}

func expectedCandidateAuthorityEntries() map[string]struct{} {
	entries := make(map[string]struct{}, len(expectedCandidateAuthorityFiles()))
	for _, relative := range expectedCandidateAuthorityFiles() {
		entries[relative] = struct{}{}
	}
	return entries
}

func parseAuthorityTreeEntries(raw []byte, root string) (map[string]authorityTreeEntry, error) {
	prefix := root + "/"
	entries := make(map[string]authorityTreeEntry)
	for len(raw) > 0 {
		index := bytes.IndexByte(raw, 0)
		if index < 0 {
			return nil, errors.New("git tree inventory is not NUL terminated")
		}
		record := raw[:index]
		raw = raw[index+1:]
		metadata, location, found := bytes.Cut(record, []byte{'\t'})
		if !found {
			return nil, errors.New("git tree inventory record is malformed")
		}
		parts := strings.Fields(string(metadata))
		if len(parts) != 3 {
			return nil, errors.New("git tree inventory metadata is malformed")
		}
		gitPath := string(location)
		if !strings.HasPrefix(gitPath, prefix) {
			return nil, errors.New("git tree authority path escapes its fixed root")
		}
		relative := strings.TrimPrefix(gitPath, prefix)
		if relative == "" || path.IsAbs(relative) || path.Clean(relative) != relative || strings.HasPrefix(relative, "../") {
			return nil, errors.New("git tree authority path is invalid")
		}
		if _, duplicate := entries[relative]; duplicate {
			return nil, errors.New("git tree authority inventory contains duplicate paths")
		}
		entries[relative] = authorityTreeEntry{mode: parts[0], objectType: parts[1], object: parts[2]}
	}
	return entries, nil
}

func (curator *AuthorityCurator) assertCandidateAuthorityIndex(ctx context.Context, checkout authorityCheckout) error {
	output, err := curator.git(ctx, checkout.root, "ls-files", "-v", "-z", "--", TrustedBundleRelativePath)
	if err != nil {
		return fmt.Errorf("inspect candidate authority index flags: %w", err)
	}
	expected := expectedCandidateAuthorityEntries()
	seen := make(map[string]struct{}, len(expected))
	prefix := TrustedBundleRelativePath + "/"
	for len(output) > 0 {
		index := bytes.IndexByte(output, 0)
		if index < 0 {
			return errors.New("git index inventory is not NUL terminated")
		}
		record := string(output[:index])
		output = output[index+1:]
		if len(record) < 3 || record[1] != ' ' || !strings.HasPrefix(record[2:], prefix) {
			return errors.New("git index authority inventory is malformed")
		}
		relative := strings.TrimPrefix(record[2:], prefix)
		if _, expected := expected[relative]; !expected || record[0] != 'H' {
			return errors.New("candidate authority has hidden or ambiguous Git index state")
		}
		if _, duplicate := seen[relative]; duplicate {
			return errors.New("candidate authority index contains duplicate paths")
		}
		seen[relative] = struct{}{}
	}
	if len(seen) != len(expected) {
		return errors.New("candidate authority index inventory is not exact")
	}
	return nil
}

func authorityDirectoryInCheckout(ctx context.Context, root, relative string) (string, error) {
	if err := contextError(ctx); err != nil {
		return "", err
	}
	if path.IsAbs(relative) || path.Clean(relative) != relative {
		return "", errors.New("candidate authority path must be a clean repository-relative path")
	}
	current := root
	for _, segment := range strings.Split(relative, "/") {
		if segment == "" || strings.EqualFold(segment, ".git") {
			return "", errors.New("candidate authority path must not enter .git")
		}
		current = filepath.Join(current, segment)
		info, err := os.Lstat(current)
		if err != nil {
			return "", fmt.Errorf("inspect candidate authority path: %w", err)
		}
		reparse, err := authorityPathIsReparsePoint(current)
		if err != nil {
			return "", fmt.Errorf("inspect candidate authority reparse path: %w", err)
		}
		if reparse || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", errors.New("candidate authority path contains a symlink or reparse point")
		}
	}
	return current, nil
}

func sameCandidateAuthority(left, right candidateAuthority) bool {
	return left.inventoryDigest == right.inventoryDigest && sameCanonical(left.assets, right.assets) && sameCanonical(left.manifest, right.manifest) &&
		sameCanonical(left.repeat, right.repeat) && sameCanonical(left.provenance, right.provenance) &&
		left.reviewEvidence.Reference == right.reviewEvidence.Reference && left.dispositionEvidence.Reference == right.dispositionEvidence.Reference &&
		bytes.Equal(left.baselineInputFile, right.baselineInputFile) && bytes.Equal(left.candidateInputFile, right.candidateInputFile) &&
		bytes.Equal(left.baselineAllowlistFile, right.baselineAllowlistFile) && bytes.Equal(left.bundleFile, right.bundleFile)
}
