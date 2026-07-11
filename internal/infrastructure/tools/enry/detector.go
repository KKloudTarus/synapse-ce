// Package enry adapts source-language detection to the LanguageDetector port,
// backed by go-enry (the GitHub Linguist port). Pure-Go, no external binary.
//
// Safety: this adapter only *reads* the target to classify it (never executes
// it), refuses to follow symlinks and to open non-regular files (devices, FIFOs,
// sockets), honors context cancellation, and bounds per-file reads + file count.
// Full workspace isolation + total-size cap + cleanup land with Target
// acquisition and the per-scan timeout/limits land with the queue
// ; until then these local guards are the line of defense.
package enry

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	enry "github.com/go-enry/go-enry/v2"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	// maxFileBytes caps how much of a file is read for classification.
	maxFileBytes = 1 << 20 // 1 MiB
	// readChunk is the per-iteration read size (lets us poll ctx mid-read).
	readChunk = 64 << 10 // 64 KiB
	// maxFiles bounds walk time on hostile/huge trees; the real size cap is
	// owed upstream by Target acquisition / the queue.
	maxFiles = 100_000
)

// skipDirs are directory names never descended into.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
	"dist": true, "bin": true, ".idea": true, ".vscode": true,
}

// Detector implements ports.LanguageDetector using go-enry.
type Detector struct{}

// New returns a new detector.
func New() *Detector { return &Detector{} }

var _ ports.LanguageDetector = (*Detector)(nil)

// Detect walks targetPath and aggregates file sizes per programming/markup
// language into percentages, following Linguist conventions. Only local,
// regular files are read; symlinks and special files are skipped (not followed).
func (d *Detector) Detect(ctx context.Context, targetPath string) ([]ports.DetectedLanguage, error) {
	// Lstat (not Stat) so a symlinked target root is not followed.
	root, err := os.Lstat(targetPath)
	if err != nil {
		return nil, fmt.Errorf("stat target: %w", err)
	}

	tally := make(map[string]int64)

	if !root.IsDir() {
		if err := classify(ctx, targetPath, root, tally); err != nil {
			return nil, err
		}
		return toPercentages(tally), nil
	}

	visited := 0
	err = filepath.WalkDir(targetPath, func(path string, dirent fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if path == targetPath {
				return fmt.Errorf("walk target root: %w", walkErr)
			}
			return nil // unreadable child entry: skip, don't fail the whole scan
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if dirent.IsDir() {
			if path != targetPath && skipDirs[dirent.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !dirent.Type().IsRegular() { // skips symlinks, devices, FIFOs, sockets
			return nil
		}
		if visited >= maxFiles {
			return filepath.SkipAll // bound walk time; full cap owed upstream
		}
		visited++
		fi, ierr := dirent.Info()
		if ierr != nil {
			return nil
		}
		return classify(ctx, path, fi, tally)
	})
	if err != nil {
		return nil, fmt.Errorf("walk target: %w", err)
	}
	return toPercentages(tally), nil
}

// classify reads a capped sample of a regular file and, if it is a programming
// or markup language (and not vendored/generated/binary/config/docs), adds its
// full size to the per-language tally. Non-regular files are refused.
func classify(ctx context.Context, path string, fi os.FileInfo, tally map[string]int64) error {
	if !fi.Mode().IsRegular() { // refuse symlinks/devices/FIFOs/sockets/dirs
		return nil
	}
	if enry.IsVendor(path) || enry.IsDotFile(path) ||
		enry.IsConfiguration(path) || enry.IsDocumentation(path) {
		return nil
	}
	content, err := readCapped(ctx, path)
	if err != nil {
		if ctx.Err() != nil {
			return err // propagate cancellation
		}
		return nil // unreadable file: skip
	}
	if enry.IsBinary(content) || enry.IsGenerated(path, content) {
		return nil
	}
	lang := enry.GetLanguage(filepath.Base(path), content)
	if lang == "" {
		return nil
	}
	switch enry.GetLanguageType(lang) {
	case enry.Programming, enry.Markup:
		// Classify on the (capped) sample, but weight by the full file size –
		// Linguist-style. Don't "fix" this to len(content); it would break weighting.
		tally[lang] += fi.Size()
	}
	return nil
}

// readCapped reads up to maxFileBytes from a regular file in chunks, polling ctx
// between chunks so a cancelled scan stops promptly.
func readCapped(ctx context.Context, path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- path verified as a regular file via Lstat; isolation lands in P3
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, 0, readChunk)
	chunk := make([]byte, readChunk)
	for int64(len(buf)) < maxFileBytes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := f.Read(chunk)
		if n > 0 {
			if remaining := maxFileBytes - int64(len(buf)); int64(n) > remaining {
				n = int(remaining)
			}
			buf = append(buf, chunk[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return buf, nil
}

func toPercentages(tally map[string]int64) []ports.DetectedLanguage {
	var total int64
	for _, b := range tally {
		total += b
	}
	out := make([]ports.DetectedLanguage, 0, len(tally))
	if total == 0 {
		return out
	}
	for lang, b := range tally {
		out = append(out, ports.DetectedLanguage{
			Name:    lang,
			Percent: float64(b) / float64(total) * 100,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Percent != out[j].Percent {
			return out[i].Percent > out[j].Percent
		}
		return out[i].Name < out[j].Name
	})
	return out
}
