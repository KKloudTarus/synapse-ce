//go:build linux

package scabench

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func TestRunCandidateRetainsFailedTwentyFourCellDiagnostic(t *testing.T) {
	sourceRoot, corpusRoot, commit := candidateTestSource(t)
	catalog, err := decodeCatalogFile(filepath.Join(corpusRoot, "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := decodeCandidateInputBindingSpec(filepath.Join(corpusRoot, "trusted-input-bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	offlineRoot := t.TempDir()
	writeCandidateOfflineInput(t, offlineRoot, spec)
	for _, name := range []string{"owned-debian", "owned-sles", "owned-redhat"} {
		if err := os.Remove(filepath.Join(offlineRoot, "databases", name, "fixture")); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"grype", "trivy", "osv-scanner"} {
		if err := os.Chmod(filepath.Join(offlineRoot, "tools", name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range catalog.Targets {
		components := make([]struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		}, 0, len(target.Components))
		for _, component := range target.Components {
			components = append(components, struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				PURL    string `json:"purl"`
			}{Name: "component", Version: component.Version, PURL: component.PURL})
		}
		sbom, err := json.Marshal(struct {
			BomFormat   string `json:"bomFormat"`
			SpecVersion string `json:"specVersion"`
			Components  any    `json:"components"`
		}{BomFormat: "CycloneDX", SpecVersion: "1.6", Components: components})
		if err != nil {
			t.Fatal(err)
		}
		writeCandidateOfflineFile(t, offlineRoot, fixedTrustedSBOMLocators[target.ID], sbom)
	}

	factoryCalls := 0
	runnerFactory := func(RuntimeLimits) (ports.ToolRunner, error) {
		factoryCalls++
		return &fakeRunner{resultForSpec: func(spec ports.ToolSpec) ports.ToolResult {
			if len(spec.Args) == 0 {
				t.Error("scanner received no argv")
				return ports.ToolResult{}
			}
			var output []byte
			switch spec.Args[0] {
			case "--owned-helper":
				output = []byte(`{"schema_version":"synapse-sca-benchmark-owned-wire-v2","engine_version":"devel","advisories_ingested":1,"advisories_skipped":0,"findings":[]}`)
			case "sbom":
				output = []byte(`{"SchemaVersion":2,"Trivy":{"Version":"0.74.0"},"Results":[]}`)
			case "--version":
				output = osvVersionProbeOutput("v2.5.1")
			case "scan":
				output = []byte(`{"results":[]}`)
			default:
				if strings.HasPrefix(spec.Args[0], "sbom:") {
					output = []byte(`{"descriptor":{"name":"grype","version":"0.115.0"},"matches":[]}`)
				} else {
					t.Errorf("unexpected scanner argv: %q", spec.Args)
				}
			}
			return ports.ToolResult{Stdout: output}
		}}, nil
	}

	result, runErr := RunCandidate(context.Background(), CandidateInput{
		SourceRoot: sourceRoot, CorpusRoot: corpusRoot, OfflineInputRoot: offlineRoot,
		EvidenceRoot: t.TempDir(), ImplementationCommit: commit, RunKey: "candidate/matrix",
	}, runnerFactory)
	if runErr == nil || !strings.Contains(runErr.Error(), "candidate gate failed") {
		t.Fatalf("RunCandidate() error = %v; want retained candidate numeric failure (evidence %q)", runErr, result.EvidencePath)
	}
	var candidateErr *CandidateError
	if !errors.As(runErr, &candidateErr) || candidateErr.EvidencePath != result.EvidencePath {
		t.Fatalf("candidate failure lacks retained evidence path: %v", runErr)
	}
	if result.RetainedAttemptRecords != fixedRepetitions*fixedMatrixCells {
		t.Fatalf("retained %d attempt records; want 24", result.RetainedAttemptRecords)
	}
	if result.Repetitions != fixedRepetitions || len(result.Comparisons) != fixedMatrixCells || factoryCalls != fixedRepetitions*(fixedMatrixCells-2) {
		t.Fatalf("matrix repetitions=%d comparisons=%d dispatched=%d; want 2, 12, 20", result.Repetitions, len(result.Comparisons), factoryCalls)
	}
	if result.Candidate == nil || result.Historical == nil || result.Candidate.Gate == nil || result.Historical.Gate == nil || result.Gate.CandidatePassed || result.Gate.HistoricalPassed || result.Gate.Accepted {
		t.Fatalf("candidate/historical diagnostic gates are missing or accepted: %+v", result.Gate)
	}
	for repetition, observations := range result.Observations {
		if len(observations) != fixedMatrixCells || len(result.RawBundles[repetition]) != fixedMatrixCells {
			t.Fatalf("repetition %d has %d observations, %d bundles", repetition+1, len(observations), len(result.RawBundles[repetition]))
		}
	}
	reportBytes, err := os.ReadFile(filepath.Join(result.EvidencePath, "candidate-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report CandidateResult
	if err := json.Unmarshal(reportBytes, &report); err != nil {
		t.Fatal(err)
	}
	if report.Candidate == nil || report.Historical == nil || report.Gate.CandidatePassed || report.Gate.Accepted {
		t.Fatalf("retained candidate report lost failed gates: %+v", report.Gate)
	}
	validated := 0
	if err := filepath.WalkDir(filepath.Join(result.EvidencePath, "attempts"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Name() == "observation.json" {
			if err := ValidateBundle(filepath.Dir(path)); err != nil {
				return err
			}
			validated++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if validated != fixedRepetitions*fixedMatrixCells {
		t.Fatalf("retained %d validated bundles, want %d", validated, fixedRepetitions*fixedMatrixCells)
	}
	for _, observation := range result.Observations[0] {
		if observation.Engine == bench.EngineOSVScanner && observation.TargetID != fixedTargetIDs[0] && observation.State != bench.ObservationUnsupported {
			t.Fatalf("unsupported capability cell was dispatched or mislabeled: %+v", observation)
		}
	}

	partialCalls := 0
	partialFactory := func(limits RuntimeLimits) (ports.ToolRunner, error) {
		partialCalls++
		if partialCalls == 2 {
			return nil, errors.New("simulated runner-factory failure")
		}
		return runnerFactory(limits)
	}
	partial, partialErr := RunCandidate(context.Background(), CandidateInput{
		SourceRoot: sourceRoot, CorpusRoot: corpusRoot, OfflineInputRoot: offlineRoot,
		EvidenceRoot: t.TempDir(), ImplementationCommit: commit, RunKey: "candidate/partial",
	}, partialFactory)
	if partialErr == nil || !strings.Contains(partialErr.Error(), "simulated runner-factory failure") {
		t.Fatalf("partial RunCandidate() error = %v; want planned mid-cycle failure", partialErr)
	}
	if partial.RetainedAttemptRecords < 1 || partial.RetainedAttemptRecords >= fixedRepetitions*fixedMatrixCells {
		t.Fatalf("partial run retained %d attempt records; want a strict subset of 24", partial.RetainedAttemptRecords)
	}
	partialReportBytes, err := os.ReadFile(filepath.Join(partial.EvidencePath, "candidate-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var partialReport CandidateResult
	if err := json.Unmarshal(partialReportBytes, &partialReport); err != nil {
		t.Fatal(err)
	}
	if partialReport.RetainedAttemptRecords != partial.RetainedAttemptRecords || partialReport.Gate.Accepted {
		t.Fatalf("partial report misstates retained attempts or acceptance: %+v", partialReport)
	}
}
