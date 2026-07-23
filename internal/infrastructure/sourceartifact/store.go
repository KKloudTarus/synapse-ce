// Package sourceartifact stores immutable Project analysis source on local disk.
package sourceartifact

import (
	"bytes"
	"compress/gzip"
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
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	defaultMaxFileBytes = int64(2 << 20)
	defaultMaxFiles     = 10_000
	defaultMaxBytes     = int64(500 << 20)
)

var (
	ErrNotRetained = projectanalysis.ErrSourceNotRetained
	ErrIntegrity   = projectanalysis.ErrSourceIntegrity
)

type Store struct {
	root         string
	maxFileBytes int64
	maxFiles     int
	maxBytes     int64
}

func New(root string, maxFileBytes int64, maxFiles int, maxBytes int64) *Store {
	if maxFileBytes <= 0 {
		maxFileBytes = defaultMaxFileBytes
	}
	if maxFiles <= 0 {
		maxFiles = defaultMaxFiles
	}
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	return &Store{root: root, maxFileBytes: maxFileBytes, maxFiles: maxFiles, maxBytes: maxBytes}
}

var _ ports.ProjectSourceArtifactStore = (*Store)(nil)

func (s *Store) Capture(ctx context.Context, tenantID, projectID shared.ID, analysisID, sourceDir string) (projectanalysis.SourceCapture, error) {
	unavailable := func(reason projectanalysis.UnavailableReason) projectanalysis.SourceCapture {
		return projectanalysis.SourceCapture{Capabilities: unavailableCapabilities(reason)}
	}
	if err := s.validateAnalysisContext(projectID, analysisID); err != nil || strings.TrimSpace(sourceDir) == "" {
		return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("%w: source capture context is required", shared.ErrValidation)
	}
	if err := ctx.Err(); err != nil {
		return unavailable(projectanalysis.UnavailableCaptureFailed), err
	}

	captureRoot := s.analysisDir(tenantID, projectID, analysisID)
	if err := os.MkdirAll(filepath.Dir(captureRoot), 0o700); err != nil {
		return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("create source artifact root: %w", err)
	}
	tmp, err := os.MkdirTemp(filepath.Dir(captureRoot), ".source-capture-*")
	if err != nil {
		return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("create source capture directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if err := os.MkdirAll(filepath.Join(tmp, "blobs"), 0o700); err != nil {
		return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("create source blob directory: %w", err)
	}

	manifest := projectanalysis.SourceManifest{}
	var total int64
	walkErr := filepath.WalkDir(sourceDir, func(full string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if full == sourceDir {
			return nil
		}
		if entry.IsDir() && entry.Name() == ".git" {
			return filepath.SkipDir
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() || !entry.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(sourceDir, full)
		if err != nil {
			return err
		}
		path, err := measure.CanonicalPath(filepath.ToSlash(rel))
		if err != nil || path == "" {
			return fmt.Errorf("invalid source path: %w", err)
		}
		if len(manifest.Files) >= s.maxFiles {
			manifest.Truncated = true
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > s.maxFileBytes {
			manifest.Files = append(manifest.Files, unavailableFile(path, info.Size(), projectanalysis.UnavailableLimitExceeded))
			manifest.Truncated = true
			return nil
		}
		if total+info.Size() > s.maxBytes {
			manifest.Files = append(manifest.Files, unavailableFile(path, info.Size(), projectanalysis.UnavailableLimitExceeded))
			manifest.Truncated = true
			return nil
		}
		data, err := os.ReadFile(full) // #nosec G304 -- full is enumerated below the acquired workspace root
		if err != nil {
			return err
		}
		if !utf8.Valid(data) || bytesContainNUL(data) {
			manifest.Files = append(manifest.Files, unavailableFile(path, int64(len(data)), binaryReason(data)))
			return nil
		}
		digest := sha256.Sum256(data)
		digestHex := hex.EncodeToString(digest[:])
		if err := writeGzip(filepath.Join(tmp, "blobs", digestHex+".gz"), data); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		manifest.Files = append(manifest.Files, projectanalysis.SourceFile{
			Path: path, Digest: digestHex, Bytes: int64(len(data)), Lines: lineCount(data), Generated: isGenerated(path, data), Available: true,
		})
		total += int64(len(data))
		return nil
	})
	if walkErr != nil {
		return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("capture project source: %w", walkErr)
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	manifest.SetArtifactDigest()
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("marshal source manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "manifest.json"), manifestData, 0o600); err != nil {
		return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("write source manifest: %w", err)
	}
	if err := os.RemoveAll(captureRoot); err != nil {
		return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("replace source artifact: %w", err)
	}
	if err := os.Rename(tmp, captureRoot); err != nil {
		return unavailable(projectanalysis.UnavailableCaptureFailed), fmt.Errorf("publish source artifact: %w", err)
	}
	return projectanalysis.SourceCapture{Capabilities: availableCapabilities(), Manifest: manifest}, nil
}

func (s *Store) Load(ctx context.Context, tenantID, projectID shared.ID, analysisID, path string) ([]byte, projectanalysis.SourceFile, error) {
	return s.load(ctx, tenantID, projectID, analysisID, "", path)
}

// CaptureBase stores only the base-side files selected by the normalized Git diff.
// It is independent from the head capture so deleted files remain renderable later.
func (s *Store) CaptureBase(ctx context.Context, tenantID, projectID shared.ID, analysisID string, files map[string][]byte) (projectanalysis.SourceManifest, error) {
	manifest := projectanalysis.SourceManifest{}
	if err := s.validateAnalysisContext(projectID, analysisID); err != nil {
		return manifest, err
	}
	if len(files) == 0 {
		manifest.SetArtifactDigest()
		return manifest, nil
	}
	root := filepath.Join(s.analysisDir(tenantID, projectID, analysisID), "base")
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		return manifest, fmt.Errorf("create base source parent: %w", err)
	}
	tmp, err := os.MkdirTemp(filepath.Dir(root), ".base-capture-*")
	if err != nil {
		return manifest, fmt.Errorf("create base source directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if err := os.MkdirAll(filepath.Join(tmp, "blobs"), 0o700); err != nil {
		return manifest, fmt.Errorf("create base source blobs: %w", err)
	}
	paths := make([]string, 0, len(files))
	for path := range files {
		canonical, err := measure.CanonicalPath(path)
		if err != nil || canonical == "" || canonical != path {
			return projectanalysis.SourceManifest{}, fmt.Errorf("%w: base source path is invalid", shared.ErrValidation)
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var total int64
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return projectanalysis.SourceManifest{}, err
		}
		if len(manifest.Files) >= s.maxFiles {
			manifest.Truncated = true
			break
		}
		data := files[path]
		if int64(len(data)) > s.maxFileBytes || total+int64(len(data)) > s.maxBytes {
			manifest.Files = append(manifest.Files, unavailableFile(path, int64(len(data)), projectanalysis.UnavailableLimitExceeded))
			manifest.Truncated = true
			continue
		}
		if !utf8.Valid(data) || bytesContainNUL(data) {
			manifest.Files = append(manifest.Files, unavailableFile(path, int64(len(data)), binaryReason(data)))
			continue
		}
		digest := sha256.Sum256(data)
		digestHex := hex.EncodeToString(digest[:])
		if err := writeGzip(filepath.Join(tmp, "blobs", digestHex+".gz"), data); err != nil && !errors.Is(err, fs.ErrExist) {
			return projectanalysis.SourceManifest{}, fmt.Errorf("write base source artifact: %w", err)
		}
		manifest.Files = append(manifest.Files, projectanalysis.SourceFile{Path: path, Digest: digestHex, Bytes: int64(len(data)), Lines: lineCount(data), Generated: isGenerated(path, data), Available: true})
		total += int64(len(data))
	}
	manifest.SetArtifactDigest()
	data, err := json.Marshal(manifest)
	if err != nil {
		return projectanalysis.SourceManifest{}, err
	}
	if err := os.WriteFile(filepath.Join(tmp, "manifest.json"), data, 0o600); err != nil {
		return projectanalysis.SourceManifest{}, fmt.Errorf("write base source manifest: %w", err)
	}
	if err := os.RemoveAll(root); err != nil {
		return projectanalysis.SourceManifest{}, fmt.Errorf("replace base source artifact: %w", err)
	}
	if err := os.Rename(tmp, root); err != nil {
		return projectanalysis.SourceManifest{}, fmt.Errorf("publish base source artifact: %w", err)
	}
	return manifest, nil
}

func (s *Store) LoadBase(ctx context.Context, tenantID, projectID shared.ID, analysisID, path string) ([]byte, projectanalysis.SourceFile, error) {
	return s.load(ctx, tenantID, projectID, analysisID, "base", path)
}

func (s *Store) load(ctx context.Context, tenantID, projectID shared.ID, analysisID, side, path string) ([]byte, projectanalysis.SourceFile, error) {
	if err := s.validateAnalysisContext(projectID, analysisID); err != nil {
		return nil, projectanalysis.SourceFile{}, err
	}
	canonical, err := measure.CanonicalPath(path)
	if err != nil || canonical == "" || canonical != path {
		return nil, projectanalysis.SourceFile{}, fmt.Errorf("%w: source path is invalid", shared.ErrValidation)
	}
	root := s.analysisDir(tenantID, projectID, analysisID)
	if side != "" {
		root = filepath.Join(root, side)
	}
	if _, err := os.Stat(s.analysisDir(tenantID, projectID, analysisID)); err == nil {
		return s.loadFrom(ctx, root, canonical)
	} else if !os.IsNotExist(err) {
		return nil, projectanalysis.SourceFile{}, projectanalysis.ErrSourceTransient
	}
	if legacy := s.legacyAnalysisDir(tenantID, projectID, analysisID); legacy != "" {
		if side != "" {
			legacy = filepath.Join(legacy, side)
		}
		return s.loadFrom(ctx, legacy, canonical)
	}
	return nil, projectanalysis.SourceFile{}, ErrNotRetained
}

func (s *Store) loadFrom(ctx context.Context, root, canonical string) ([]byte, projectanalysis.SourceFile, error) {
	manifestData, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, projectanalysis.SourceFile{}, ErrNotRetained
		}
		return nil, projectanalysis.SourceFile{}, projectanalysis.ErrSourceTransient
	}
	var manifest projectanalysis.SourceManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, projectanalysis.SourceFile{}, projectanalysis.ErrSourceIntegrity
	}
	if manifest.Digest != "" && manifest.Digest != manifest.ArtifactDigest() {
		return nil, projectanalysis.SourceFile{}, projectanalysis.ErrSourceIntegrity
	}
	for _, file := range manifest.Files {
		if file.Path != canonical {
			continue
		}
		if !file.Available {
			switch file.Reason {
			case projectanalysis.UnavailableBinary, projectanalysis.UnavailableNonUTF8:
				return nil, file, projectanalysis.ErrSourceUnsupported
			case projectanalysis.UnavailableLimitExceeded:
				return nil, file, projectanalysis.ErrSourceLimit
			default:
				return nil, file, ErrNotRetained
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, projectanalysis.SourceFile{}, err
		}
		if !validDigest(file.Digest) {
			return nil, projectanalysis.SourceFile{}, projectanalysis.ErrSourceIntegrity
		}
		data, err := readGzip(filepath.Join(root, "blobs", file.Digest+".gz"), s.maxFileBytes)
		if err != nil {
			if os.IsNotExist(err) || errors.Is(err, projectanalysis.ErrSourceIntegrity) {
				return nil, projectanalysis.SourceFile{}, projectanalysis.ErrSourceIntegrity
			}
			return nil, projectanalysis.SourceFile{}, projectanalysis.ErrSourceTransient
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != file.Digest || int64(len(data)) != file.Bytes {
			return nil, projectanalysis.SourceFile{}, ErrIntegrity
		}
		return data, file, nil
	}
	return nil, projectanalysis.SourceFile{}, ErrNotRetained
}

func (s *Store) DeleteAnalysis(_ context.Context, tenantID, projectID shared.ID, analysisID string) error {
	if err := s.validateAnalysisContext(projectID, analysisID); err != nil {
		return err
	}
	for _, root := range []string{s.analysisDir(tenantID, projectID, analysisID), s.legacyAnalysisDir(tenantID, projectID, analysisID)} {
		if root != "" {
			if err := os.RemoveAll(root); err != nil {
				return fmt.Errorf("delete source analysis artifacts: %w", err)
			}
		}
	}
	return nil
}

func (s *Store) DeleteProject(_ context.Context, tenantID, projectID shared.ID) error {
	if err := s.validateProjectContext(projectID); err != nil {
		return err
	}
	for _, root := range []string{s.projectDir(tenantID, projectID), s.legacyProjectDir(tenantID, projectID)} {
		if root != "" {
			if err := os.RemoveAll(root); err != nil {
				return fmt.Errorf("delete project source artifacts: %w", err)
			}
		}
	}
	return nil
}

func (s *Store) CleanupExpired(_ context.Context, before time.Time) error {
	if err := s.cleanupExpiredAt(s.v2Root(), before); err != nil {
		return err
	}
	return s.cleanupExpiredAt(s.root, before)
}

func (s *Store) cleanupExpiredAt(root string, before time.Time) error {
	tenants, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("list source artifact root: %w", err)
	}
	for _, tenant := range tenants {
		if !tenant.IsDir() || tenant.Name() == "v2" {
			continue
		}
		projects, err := os.ReadDir(filepath.Join(root, tenant.Name()))
		if err != nil {
			return fmt.Errorf("list project source artifacts: %w", err)
		}
		for _, project := range projects {
			if !project.IsDir() {
				continue
			}
			analysisRoot := filepath.Join(root, tenant.Name(), project.Name())
			analyses, err := os.ReadDir(analysisRoot)
			if err != nil {
				return fmt.Errorf("list analysis source artifacts: %w", err)
			}
			for _, analysis := range analyses {
				if !analysis.IsDir() {
					continue
				}
				analysisDir := filepath.Join(analysisRoot, analysis.Name())
				if _, err := os.Stat(filepath.Join(analysisDir, "manifest.json")); os.IsNotExist(err) {
					continue
				} else if err != nil {
					return fmt.Errorf("stat source artifact manifest: %w", err)
				}
				info, err := analysis.Info()
				if err != nil {
					return err
				}
				if info.ModTime().Before(before) {
					if err := os.RemoveAll(analysisDir); err != nil {
						return fmt.Errorf("remove expired source artifacts: %w", err)
					}
				}
			}
		}
	}
	return nil
}

func (s *Store) validateProjectContext(projectID shared.ID) error {
	if strings.TrimSpace(s.root) == "" || projectID.IsZero() {
		return fmt.Errorf("%w: source capture context is required", shared.ErrValidation)
	}
	return nil
}

func (s *Store) validateAnalysisContext(projectID shared.ID, analysisID string) error {
	if err := s.validateProjectContext(projectID); err != nil || strings.TrimSpace(analysisID) == "" {
		return fmt.Errorf("%w: source capture context is required", shared.ErrValidation)
	}
	return nil
}

func (s *Store) v2Root() string { return filepath.Join(s.root, "v2") }

func (s *Store) projectDir(tenantID, projectID shared.ID) string {
	return filepath.Join(s.v2Root(), "t-"+hashID(tenantID.String()), "p-"+hashID(projectID.String()))
}

func (s *Store) analysisDir(tenantID, projectID shared.ID, analysisID string) string {
	return filepath.Join(s.projectDir(tenantID, projectID), "a-"+hashID(analysisID))
}

func (s *Store) legacyProjectDir(tenantID, projectID shared.ID) string {
	if !safeLegacyComponent(tenantID.String()) || !safeLegacyComponent(projectID.String()) {
		return ""
	}
	return filepath.Join(s.root, tenantID.String(), projectID.String())
}

func (s *Store) legacyAnalysisDir(tenantID, projectID shared.ID, analysisID string) string {
	if !safeLegacyComponent(analysisID) {
		return ""
	}
	root := s.legacyProjectDir(tenantID, projectID)
	if root == "" {
		return ""
	}
	return filepath.Join(root, analysisID)
}

func hashID(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func safeLegacyComponent(value string) bool {
	return strings.TrimSpace(value) != "" && value != "." && value != ".." && !strings.ContainsAny(value, `/\\`)
}

func availableCapabilities() projectanalysis.SourceCapabilities {
	return projectanalysis.SourceCapabilities{
		Source:       projectanalysis.Capability{Available: true},
		Comparison:   projectanalysis.Capability{Reason: projectanalysis.UnavailableFirstAnalysis},
		UnifiedDiff:  projectanalysis.Capability{Reason: projectanalysis.UnavailableFirstAnalysis},
		SplitDiff:    projectanalysis.Capability{Reason: projectanalysis.UnavailableFirstAnalysis},
		Highlighting: projectanalysis.Capability{Available: true},
	}
}

func unavailableCapabilities(reason projectanalysis.UnavailableReason) projectanalysis.SourceCapabilities {
	return projectanalysis.SourceCapabilities{
		Source: projectanalysis.Capability{Reason: reason}, Comparison: projectanalysis.Capability{Reason: reason},
		UnifiedDiff: projectanalysis.Capability{Reason: reason}, SplitDiff: projectanalysis.Capability{Reason: reason}, Highlighting: projectanalysis.Capability{Reason: reason},
	}
}

func unavailableFile(path string, bytes int64, reason projectanalysis.UnavailableReason) projectanalysis.SourceFile {
	return projectanalysis.SourceFile{Path: path, Bytes: bytes, Available: false, Reason: reason}
}

func binaryReason(data []byte) projectanalysis.UnavailableReason {
	if bytesContainNUL(data) {
		return projectanalysis.UnavailableBinary
	}
	return projectanalysis.UnavailableNonUTF8
}

func bytesContainNUL(data []byte) bool {
	for _, b := range data {
		if b == 0 {
			return true
		}
	}
	return false
}

func isGenerated(path string, data []byte) bool {
	name := strings.ToLower(filepath.Base(path))
	if strings.HasSuffix(name, ".min.js") || strings.HasSuffix(name, ".min.css") || strings.HasSuffix(name, ".generated.go") || strings.Contains(name, ".gen.") {
		return true
	}
	prefix := string(data)
	if len(prefix) > 1024 {
		prefix = prefix[:1024]
	}
	prefix = strings.ToLower(prefix)
	return strings.Contains(prefix, "code generated") && strings.Contains(prefix, "do not edit") ||
		strings.Contains(prefix, "@generated") || strings.Contains(prefix, "auto-generated")
}

func lineCount(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	lines := bytes.Count(data, []byte{'\n'})
	if data[len(data)-1] != '\n' {
		lines++
	}
	return lines
}

func writeGzip(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	writer := gzip.NewWriter(file)
	if _, err := writer.Write(data); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return file.Close()
}

func readGzip(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	reader, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	data, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, projectanalysis.ErrSourceIntegrity
	}
	return data, nil
}
