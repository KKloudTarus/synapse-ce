// Command synapse-fptriage-curate converts explicitly reviewed AI-triage outcomes
// into an offline evaluation dataset after privacy and label-quality approval.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aitriagereview"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

type reviewExport struct {
	Reviews []aitriagereview.Review `json:"reviews"`
}

func main() {
	reviewsPath := flag.String("reviews", "", "tenant-scoped AI-triage review-list JSON exported from the API")
	manifestPath := flag.String("manifest", "", "offline feedback-curation manifest JSON")
	outputPath := flag.String("output", "", "new private path for the curated evaluation dataset (required unless printing digests)")
	printDigests := flag.Bool("print-review-digests", false, "print approval digests for the manifest without producing a dataset")
	flag.Parse()

	if err := run(*reviewsPath, *manifestPath, *outputPath, *printDigests, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "synapse-fptriage-curate: %v\n", err)
		os.Exit(1)
	}
}

func run(reviewsPath, manifestPath, outputPath string, printDigests bool, stdout io.Writer) error {
	reviewsPath = strings.TrimSpace(reviewsPath)
	manifestPath = strings.TrimSpace(manifestPath)
	outputPath = strings.TrimSpace(outputPath)
	if reviewsPath == "" || manifestPath == "" {
		return fmt.Errorf("--reviews and --manifest are required")
	}
	if !printDigests && (outputPath == "" || outputPath == "-") {
		return fmt.Errorf("--output must be a new private file path; curated source is never written to stdout")
	}
	if !printDigests && (sameFilePath(outputPath, reviewsPath) || sameFilePath(outputPath, manifestPath)) {
		return fmt.Errorf("--output must differ from the review export and curation manifest")
	}

	var exported reviewExport
	if err := readStrictJSON(reviewsPath, &exported); err != nil {
		return fmt.Errorf("read review export: %w", err)
	}
	var manifest sca.AIEvaluationFeedbackManifest
	if err := readStrictJSON(manifestPath, &manifest); err != nil {
		return fmt.Errorf("read curation manifest: %w", err)
	}

	if printDigests {
		digests, err := sca.AIEvaluationFeedbackReviewDigests(exported.Reviews, manifest)
		if err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{"review_digests": digests})
	}

	dataset, err := sca.CurateAIEvaluationFeedback(exported.Reviews, manifest)
	if err != nil {
		return err
	}
	return writePrivateJSONFile(outputPath, dataset)
}

// writePrivateJSONFile publishes a curated dataset without following or replacing
// an existing path. The temporary file is created in the destination directory,
// written with mode 0600, synced, closed, then hard-linked into place. os.Link is
// an atomic create-only operation: an existing file, symlink, or directory causes
// the publish to fail instead of being truncated or followed.
func writePrivateJSONFile(path string, value any) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	if base == "." || base == string(filepath.Separator) || base == "" {
		return fmt.Errorf("invalid curated dataset output path %q", path)
	}
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return fmt.Errorf("create private curated dataset temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	published := false
	defer func() {
		if !published {
			_ = tmp.Close()
		}
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("protect curated dataset temporary file: %w", err)
	}
	if err := writeJSON(tmp, value); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync curated dataset temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close curated dataset temporary file: %w", err)
	}
	if err := os.Link(tmpPath, path); err != nil {
		return fmt.Errorf("publish curated dataset without replacing an existing path: %w", err)
	}
	published = true
	// Publication already succeeded. Temporary-link cleanup is best effort so a
	// cleanup failure cannot be reported as a failed dataset materialization.
	_ = os.Remove(tmpPath)
	return nil
}

func sameFilePath(a, b string) bool {
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	if errA == nil && errB == nil {
		a, b = aa, bb
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

func readStrictJSON(path string, dst any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("trailing JSON content")
	}
	return nil
}

func writeJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return fmt.Errorf("write curated feedback output: %w", err)
	}
	return nil
}
