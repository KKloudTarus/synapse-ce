//go:build ignore

// Verify a completed SCA publication from a protected binary outside the cycle checkout.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	capture "github.com/KKloudTarus/synapse-ce/internal/infrastructure/scabench"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

const maxPublicationFile = 16 << 20

func main() {
	root := flag.String("publication", "", "completed publication directory")
	source := flag.String("source-sha", "", "authorized implementation commit")
	runKey := flag.String("run-key", "", "authorized workflow run and attempt")
	flag.Parse()
	if flag.NArg() != 0 || *root == "" || *source == "" || *runKey == "" {
		fatal(errors.New("publication, source-sha, and run-key are required"))
	}
	if err := verify(*root, *source, *runKey); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "SCA publication verification:", err)
	os.Exit(1)
}

func verify(root, source, runKey string) error {
	catalogBytes, err := read(root, "catalog.json")
	if err != nil {
		return err
	}
	catalog, err := bench.DecodeCatalog(bytes.NewReader(catalogBytes))
	if err != nil {
		return fmt.Errorf("catalog: %w", err)
	}
	expected := map[string]struct{}{}
	for _, name := range []string{"catalog.json", "oracle.json", "ratchet.json", "cycle-policy.json", "run.json", "result.json", "report.md", "reviews/review.json", "reviews/disposition.json"} {
		expected[name] = struct{}{}
	}
	for _, target := range catalog.Targets {
		path := "sboms/" + target.ID + ".cdx.json"
		body, readErr := read(root, path)
		if readErr != nil || bench.SHA256Digest(body) != target.SBOMDigest {
			return fmt.Errorf("SBOM %q does not match the catalog", target.ID)
		}
		expected[path] = struct{}{}
	}
	if err := exactFiles(root, expected); err != nil {
		return err
	}
	oracleBytes, err := read(root, "oracle.json")
	if err != nil {
		return err
	}
	oracle, err := bench.DecodeOracle(bytes.NewReader(oracleBytes))
	if err != nil {
		return fmt.Errorf("oracle: %w", err)
	}
	if err := bench.Validate(catalog, oracle); err != nil {
		return fmt.Errorf("catalog and oracle: %w", err)
	}
	ratchetBytes, err := read(root, "ratchet.json")
	if err != nil {
		return err
	}
	ratchet, err := bench.DecodeRatchet(bytes.NewReader(ratchetBytes))
	if err != nil {
		return fmt.Errorf("ratchet: %w", err)
	}
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		return err
	}
	oracleDigest, err := bench.DigestOracle(oracle)
	if err != nil {
		return err
	}
	ratchetDigest, err := bench.DigestRatchet(ratchet)
	if err != nil {
		return err
	}
	if ratchet.CatalogDigest != catalogDigest || ratchet.OracleDigest != oracleDigest {
		return errors.New("ratchet does not bind the catalog and oracle")
	}
	runBytes, err := read(root, "run.json")
	if err != nil {
		return err
	}
	var run capture.RunResult
	if err := json.Unmarshal(runBytes, &run); err != nil {
		return fmt.Errorf("run: %w", err)
	}
	canonicalRun, err := bench.CanonicalJSON(run)
	if err != nil || !bytes.Equal(runBytes, canonicalRun) {
		return errors.New("run is not canonical")
	}
	if run.SchemaVersion != "synapse-sca-benchmark-run-v1" || run.ImplementationCommit != source || run.RunKey != runKey || run.Repetitions != 2 || !run.Cleanup.RawRunRemoved || !run.Cleanup.DockerCleaned {
		return errors.New("run identity or lifecycle does not match")
	}
	policy, err := read(root, "cycle-policy.json")
	if err != nil {
		return err
	}
	review, err := read(root, "reviews/review.json")
	if err != nil {
		return err
	}
	disposition, err := read(root, "reviews/disposition.json")
	if err != nil {
		return err
	}
	if run.InputDigests.Catalog != catalogDigest || run.InputDigests.Oracle != oracleDigest || run.InputDigests.Ratchet != ratchetDigest || run.InputDigests.Policy != digest(policy) || run.InputDigests.Review != digest(review) || run.InputDigests.Disposition != digest(disposition) {
		return errors.New("run input digests do not bind publication files")
	}
	matrixCells := len(catalog.Targets) * len(bench.Engines())
	targetIDs := make([]string, 0, len(catalog.Targets))
	for _, target := range catalog.Targets {
		targetIDs = append(targetIDs, target.ID)
	}
	if len(run.Observations) != 2 || len(run.RawBundles) != 2 || len(run.Comparisons) != matrixCells {
		return errors.New("run is missing a fixed matrix cell")
	}
	if err := capture.ValidateStagedCycleOrder(run, catalog, oracle); err != nil {
		return fmt.Errorf("run cycle order or comparison: %w", err)
	}
	resultBytes, err := read(root, "result.json")
	if err != nil {
		return err
	}
	reportBytes, err := read(root, "report.md")
	if err != nil {
		return err
	}
	for index, observations := range run.Observations {
		if len(observations) != matrixCells || len(run.RawBundles[index]) != matrixCells {
			return errors.New("repetition is missing a fixed matrix cell")
		}
		result, reduceErr := bench.Reduce(catalog, oracle, observations)
		if reduceErr != nil {
			return fmt.Errorf("reduce repetition %d: %w", index+1, reduceErr)
		}
		result, reduceErr = bench.ApplyRatchet(result, ratchet)
		if reduceErr != nil || result.Gate == nil || !result.Gate.Passed {
			return fmt.Errorf("repetition %d failed the ratchet: %v", index+1, reduceErr)
		}
		if err := bench.ValidateMeasuredPerTargetRecallParity(result, targetIDs); err != nil {
			return fmt.Errorf("repetition %d failed measured per-target recall parity: %w", index+1, err)
		}
		var encodedResult, renderedReport bytes.Buffer
		if err := bench.EncodeResult(&encodedResult, result); err != nil {
			return err
		}
		if err := bench.RenderResult(&renderedReport, result); err != nil {
			return err
		}
		if !bytes.Equal(encodedResult.Bytes(), resultBytes) || !bytes.Equal(renderedReport.Bytes(), reportBytes) {
			return errors.New("published result or report differs from replayed observations")
		}
	}
	var encodedRunResult bytes.Buffer
	if err := bench.EncodeResult(&encodedRunResult, run.Result); err != nil || !bytes.Equal(encodedRunResult.Bytes(), resultBytes) {
		return errors.New("run result differs from replayed observations")
	}
	return nil
}

func read(root, relative string) ([]byte, error) {
	path := filepath.Join(root, filepath.FromSlash(relative))
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxPublicationFile {
		return nil, fmt.Errorf("publication file %q is absent, unsafe, or too large", relative)
	}
	return os.ReadFile(path)
}

func exactFiles(root string, expected map[string]struct{}) error {
	seen := map[string]struct{}{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("publication contains a symlink: %s", relative)
		}
		if entry.IsDir() {
			if relative != "reviews" && relative != "sboms" {
				return fmt.Errorf("publication contains an unexpected directory: %s", relative)
			}
			return nil
		}
		name := filepath.ToSlash(relative)
		if _, allowed := expected[name]; !allowed || !entry.Type().IsRegular() {
			return fmt.Errorf("publication contains an unexpected file: %s", name)
		}
		seen[name] = struct{}{}
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return errors.New("publication is missing a required file")
	}
	return nil
}

func digest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}
