package sourceartifact

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.ProjectSourceArtifactPublisher = (*Store)(nil)

// PublishArchive consumes an untrusted tar stream into the server-owned artifact namespace.
// The destination directory is claimed with an atomic mkdir, so a second publisher can never
// replace an existing snapshot. manifest.json is written last and the use case attaches the
// manifest to the analysis only after this method returns successfully.
func (s *Store) PublishArchive(ctx context.Context, tenantID, projectID shared.ID, analysisID string, writer projectanalysis.SourceWriter, allowedPaths []string, src io.Reader) (projectanalysis.SourceCapture, error) {
	unavailable := func(reason projectanalysis.UnavailableReason) projectanalysis.SourceCapture {
		return projectanalysis.SourceCapture{Capabilities: unavailableCapabilities(reason)}
	}
	if err := s.validateAnalysisContext(projectID, analysisID); err != nil {
		return unavailable(projectanalysis.UnavailableCaptureFailed), err
	}
	if err := s.validateWriteRoot(); err != nil {
		return unavailable(projectanalysis.UnavailableCaptureFailed), err
	}
	if err := s.cleanupBeforeWrite(ctx); err != nil {
		return unavailable(projectanalysis.UnavailableCaptureFailed), err
	}
	if err := writer.Validate(); err != nil {
		return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("%w: %v", shared.ErrValidation, err)
	}
	if src == nil {
		return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("%w: source archive is required", shared.ErrValidation)
	}
	allowed := make(map[string]struct{}, len(allowedPaths))
	for _, candidate := range allowedPaths {
		canonical, err := measure.CanonicalPath(candidate)
		if err != nil || canonical == "" || canonical != candidate {
			return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("%w: analysis source path is invalid", shared.ErrValidation)
		}
		if sourcepolicy.RetainPath(canonical) {
			allowed[canonical] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		return unavailable(projectanalysis.UnavailableNotRetained), fmt.Errorf("%w: analysis has no retainable source files", shared.ErrValidation)
	}
	if err := ctx.Err(); err != nil {
		return unavailable(projectanalysis.UnavailableCaptureFailed), err
	}

	captureRoot := s.analysisDir(tenantID, projectID, analysisID)
	if err := os.MkdirAll(filepath.Dir(captureRoot), 0o700); err != nil {
		return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("create source artifact parent: %w", err)
	}
	if err := os.Mkdir(captureRoot, 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return unavailable(projectanalysis.UnavailableAlreadyRetained), shared.ErrConflict
		}
		return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("claim source artifact: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(captureRoot)
		}
	}()
	if err := os.Mkdir(filepath.Join(captureRoot, "blobs"), 0o700); err != nil {
		return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("create source blob directory: %w", err)
	}

	manifest := projectanalysis.SourceManifest{Writer: &writer}
	seen := make(map[string]struct{}, len(allowed))
	var total int64
	tr := tar.NewReader(src)
	for {
		if err := ctx.Err(); err != nil {
			return unavailable(projectanalysis.UnavailableCaptureFailed), err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("read source archive: %w", err)
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("%w: source archive contains a non-regular entry", shared.ErrValidation)
		}
		canonical, err := measure.CanonicalPath(hdr.Name)
		if err != nil || canonical == "" || canonical != hdr.Name {
			return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("%w: source archive path is invalid", shared.ErrValidation)
		}
		if _, ok := allowed[canonical]; !ok || !sourcepolicy.RetainPath(canonical) {
			continue
		}
		if _, duplicate := seen[canonical]; duplicate {
			return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("%w: duplicate source archive path %q", shared.ErrValidation, canonical)
		}
		seen[canonical] = struct{}{}
		if len(manifest.Files) >= s.maxFiles {
			manifest.Truncated = true
			continue
		}
		if hdr.Size < 0 || hdr.Size > s.maxFileBytes {
			manifest.Files = append(manifest.Files, unavailableFile(canonical, max(hdr.Size, 0), projectanalysis.UnavailableLimitExceeded))
			manifest.Truncated = true
			continue
		}
		if total+hdr.Size > s.maxBytes {
			manifest.Files = append(manifest.Files, unavailableFile(canonical, hdr.Size, projectanalysis.UnavailableLimitExceeded))
			manifest.Truncated = true
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("read source file %q: %w", canonical, err)
		}
		if int64(len(data)) != hdr.Size {
			return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("%w: source archive entry size mismatch", shared.ErrValidation)
		}
		if !utf8.Valid(data) || bytesContainNUL(data) {
			manifest.Files = append(manifest.Files, unavailableFile(canonical, int64(len(data)), binaryReason(data)))
			continue
		}
		digest := sha256.Sum256(data)
		digestHex := hex.EncodeToString(digest[:])
		if err := writeGzip(filepath.Join(captureRoot, "blobs", digestHex+".gz"), data); err != nil && !errors.Is(err, fs.ErrExist) {
			return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("write source artifact: %w", err)
		}
		manifest.Files = append(manifest.Files, projectanalysis.SourceFile{
			Path: canonical, Digest: digestHex, Bytes: int64(len(data)), Lines: lineCount(data), Generated: isGenerated(canonical, data), Available: true,
		})
		total += int64(len(data))
	}

	for candidate := range allowed {
		if _, ok := seen[candidate]; ok {
			continue
		}
		if len(manifest.Files) >= s.maxFiles {
			manifest.Truncated = true
			break
		}
		manifest.Files = append(manifest.Files, unavailableFile(candidate, 0, projectanalysis.UnavailableNotRetained))
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	retained := false
	for _, file := range manifest.Files {
		if file.Available {
			retained = true
			break
		}
	}
	if !retained {
		return unavailable(projectanalysis.UnavailableNotRetained), fmt.Errorf("%w: source archive retained no analysis files", shared.ErrValidation)
	}
	manifest.SetArtifactDigest()
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("marshal source manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(captureRoot, "manifest.json"), manifestData, 0o600); err != nil {
		return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("write source manifest: %w", err)
	}
	committed = true
	return projectanalysis.SourceCapture{Capabilities: availableCapabilities(), Manifest: manifest}, nil
}

// DiscardPublished removes only the v2 directory claimed by PublishArchive. It is used as a
// compensation action when the subsequent analysis+audit transaction fails; legacy capture
// locations are deliberately untouched.
func (s *Store) DiscardPublished(ctx context.Context, tenantID, projectID shared.ID, analysisID string) error {
	if err := s.validateAnalysisContext(projectID, analysisID); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.RemoveAll(s.analysisDir(tenantID, projectID, analysisID)); err != nil {
		return fmt.Errorf("discard published source artifact: %w", err)
	}
	return nil
}
