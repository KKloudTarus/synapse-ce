package scabench

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

// VerifyFreshCycleAssets resolves the frozen public sources and candidate
// citations before any capture is allowed. It rejects paths, symlinks, missing
// files, and digest mismatches rather than trusting a locator string.
func VerifyFreshCycleAssets(repositoryRoot string, freeze bench.SourceFreeze, candidate bench.OracleCandidate) error {
	if err := freeze.Validate(); err != nil {
		return err
	}
	if err := candidate.Validate(); err != nil {
		return err
	}
	freezeDigest, err := bench.DigestSourceFreeze(freeze)
	if err != nil {
		return err
	}
	if candidate.SourceFreezeDigest != freezeDigest {
		return fmt.Errorf("oracle candidate does not bind the source freeze")
	}
	if err := VerifyRepositoryAssets(repositoryRoot, freeze.Assets); err != nil {
		return fmt.Errorf("verify frozen sources: %w", err)
	}
	for _, item := range candidate.Cases {
		if err := VerifyRepositoryAssets(repositoryRoot, item.Citations); err != nil {
			return fmt.Errorf("verify citations for oracle candidate case %q: %w", item.ID, err)
		}
	}
	return nil
}

// VerifyRepositoryAssets verifies content-addressed public evidence beneath one
// real repository root. This path is used only for fresh-cycle inputs; historic
// fixture citations are intentionally not migrated to it.
func VerifyRepositoryAssets(repositoryRoot string, assets []bench.ContentReference) error {
	if strings.TrimSpace(repositoryRoot) == "" || !filepath.IsAbs(repositoryRoot) {
		return fmt.Errorf("repository root must be an absolute path")
	}
	rootInfo, err := os.Lstat(repositoryRoot)
	if err != nil {
		return fmt.Errorf("lstat repository root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return fmt.Errorf("repository root must be a real directory")
	}
	if len(assets) == 0 {
		return fmt.Errorf("at least one repository asset is required")
	}
	seen := make(map[string]struct{}, len(assets))
	for _, asset := range assets {
		if err := asset.Validate(); err != nil {
			return err
		}
		if _, exists := seen[asset.Locator]; exists {
			return fmt.Errorf("duplicate repository asset %q", asset.Locator)
		}
		seen[asset.Locator] = struct{}{}
		if err := verifyRepositoryAsset(repositoryRoot, asset); err != nil {
			return err
		}
	}
	return nil
}

// ReadVerifiedRepositoryAsset returns the exact bytes addressed by a frozen
// repository reference. The digest and size checks apply to the bytes returned
// to the caller, not only to a separate preflight read.
func ReadVerifiedRepositoryAsset(repositoryRoot string, asset bench.ContentReference) ([]byte, error) {
	if err := VerifyRepositoryAssets(repositoryRoot, []bench.ContentReference{asset}); err != nil {
		return nil, err
	}
	path := repositoryRoot
	for _, segment := range strings.Split(asset.Locator, "/") {
		path = filepath.Join(path, segment)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read repository asset %q: %w", asset.Locator, err)
	}
	if int64(len(body)) != asset.Size || bench.SHA256Digest(body) != asset.Digest {
		return nil, fmt.Errorf("repository asset %q changed during verified read", asset.Locator)
	}
	return body, nil
}

// VerifyAccountableReviewCapture verifies both immutable capture bytes and their
// semantic provenance binding before any scanner-capable runner is constructed.
func VerifyAccountableReviewCapture(repositoryRoot string, review bench.AccountableReview) error {
	body, err := ReadVerifiedRepositoryAsset(repositoryRoot, review.ReviewCapture)
	if err != nil {
		return fmt.Errorf("read immutable accountable review capture: %w", err)
	}
	capture, err := bench.DecodeGitHubReviewCapture(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("decode sanitized github review capture: %w", err)
	}
	if err := capture.ValidateAgainstAccountableReview(review); err != nil {
		return fmt.Errorf("bind sanitized github review capture: %w", err)
	}
	return nil
}

func verifyRepositoryAsset(repositoryRoot string, asset bench.ContentReference) error {
	segments := strings.Split(asset.Locator, "/")
	path := repositoryRoot
	for _, segment := range segments {
		path = filepath.Join(path, segment)
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("repository asset %q is missing", asset.Locator)
			}
			return fmt.Errorf("lstat repository asset %q: %w", asset.Locator, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("repository asset %q traverses a symlink", asset.Locator)
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("lstat repository asset %q: %w", asset.Locator, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("repository asset %q is not a regular file", asset.Locator)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open repository asset %q: %w", asset.Locator, err)
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return fmt.Errorf("hash repository asset %q: %w", asset.Locator, err)
	}
	if size != asset.Size {
		return fmt.Errorf("repository asset %q size does not match", asset.Locator)
	}
	actual := fmt.Sprintf("sha256:%x", hash.Sum(nil))
	if actual != asset.Digest {
		return fmt.Errorf("repository asset %q digest does not match", asset.Locator)
	}
	return nil
}
