package reachbench

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

type frozenReviewEvidence struct {
	SchemaVersion string           `json:"schema_version"`
	ID            string           `json:"id"`
	Harness       HarnessIdentity  `json:"harness"`
	Analyzer      RevisionIdentity `json:"analyzer"`
	SourceDelta   json.RawMessage  `json:"source_delta"`
	Checkpoints   json.RawMessage  `json:"checkpoints"`
	CurrentChecks json.RawMessage  `json:"current_checks"`
	Findings      []string         `json:"findings"`
}

type frozenDispositionEvidence struct {
	SchemaVersion     string                        `json:"schema_version"`
	ID                string                        `json:"id"`
	BaselineResult    measurement.ArtifactReference `json:"baseline_result"`
	LifecycleManifest measurement.ArtifactReference `json:"lifecycle_manifest"`
	SemanticRepeat    measurement.ArtifactReference `json:"semantic_repeat"`
	AllowlistResult   measurement.ArtifactReference `json:"allowlist_result"`
	Decision          string                        `json:"decision"`
	Producer          string                        `json:"producer"`
	Reviewer          string                        `json:"reviewer"`
	Maintainer        string                        `json:"maintainer"`
	Checks            json.RawMessage               `json:"checks"`
}

type frozenCandidateAssetsProvenance struct {
	SchemaVersion       string                        `json:"schema_version"`
	BaselineHarness     HarnessIdentity               `json:"baseline_harness"`
	BaselineAnalyzer    RevisionIdentity              `json:"baseline_analyzer"`
	ReviewEvidence      measurement.ArtifactReference `json:"review_evidence"`
	DispositionEvidence measurement.ArtifactReference `json:"disposition_evidence"`
	LifecycleManifest   measurement.ArtifactReference `json:"lifecycle_manifest"`
	SemanticRepeat      measurement.ArtifactReference `json:"semantic_repeat"`
	BaselineInput       measurement.ArtifactReference `json:"baseline_input"`
	CandidateInput      measurement.ArtifactReference `json:"candidate_input"`
	BaselineAllowlist   measurement.ArtifactReference `json:"baseline_allowlist"`
	AllowlistResult     measurement.ArtifactReference `json:"allowlist_result"`
	BaselineReport      measurement.ArtifactReference `json:"baseline_report"`
	Checkpoint          measurement.ArtifactReference `json:"checkpoint"`
	Ratchet             measurement.ArtifactReference `json:"ratchet"`
	Bundle              measurement.ArtifactReference `json:"bundle"`
}

func TestCheckedInTrustedCandidateAssetsLoadAndBindAuthority(t *testing.T) {
	root := checkedInTrustedAssetRoot(t)
	assertTrustedAssetInventory(t, root)

	runner := &Runner{}
	bundle, bundleRef, err := runner.loadBundle(root, RouteCandidate)
	if err != nil {
		t.Fatalf("load checked-in trusted bundle: %v", err)
	}
	baselineInput, err := runner.loadInputTemplate(root, bundle.BaselineInput, measurement.BaselineMeasurement)
	if err != nil {
		t.Fatalf("load checked-in baseline input: %v", err)
	}
	candidateInput, err := runner.loadInputTemplate(root, *bundle.CandidateInput, measurement.CandidateAcceptance)
	if err != nil {
		t.Fatalf("load checked-in candidate input: %v", err)
	}

	authorityRoot := filepath.Join(root, "authority")
	var baseline measurement.MeasurementReport
	baselineJSON := readTrustedAsset(t, filepath.Join(authorityRoot, "baseline-report.json"), &baseline)
	if err := baseline.Validate(); err != nil {
		t.Fatalf("validate checked-in baseline report: %v", err)
	}
	var checkpoint measurement.ProceduralBaselineCheckpoint
	checkpointJSON := readTrustedAsset(t, filepath.Join(authorityRoot, "baseline-checkpoint.json"), &checkpoint)
	if err := checkpoint.Validate(baselineInput.Policy, baseline); err != nil {
		t.Fatalf("validate checked-in baseline checkpoint: %v", err)
	}
	var ratchet measurement.CandidateRatchet
	ratchetJSON := readTrustedAsset(t, filepath.Join(authorityRoot, "candidate-ratchet.json"), &ratchet)
	if err := ratchet.Validate(); err != nil {
		t.Fatalf("validate checked-in candidate ratchet: %v", err)
	}
	if candidateInput.Baseline == nil || !sameCanonical(*candidateInput.Baseline, baseline) {
		t.Fatal("candidate input does not embed the checked-in baseline report")
	}
	if candidateInput.Checkpoint == nil || !sameCanonical(*candidateInput.Checkpoint, checkpoint) {
		t.Fatal("candidate input does not embed the checked-in baseline checkpoint")
	}
	if candidateInput.Ratchet == nil || !sameCanonical(*candidateInput.Ratchet, ratchet) {
		t.Fatal("candidate input does not embed the checked-in candidate ratchet")
	}

	var allowlist BaselineAllowlist
	allowlistJSON := readTrustedAsset(t, filepath.Join(root, "baseline-allowlist.json"), &allowlist)
	if err := allowlist.Validate(); err != nil {
		t.Fatalf("validate checked-in baseline allowlist: %v", err)
	}
	var allowlistResult BaselineAllowlistResult
	allowlistResultJSON := readTrustedAsset(t, filepath.Join(authorityRoot, "baseline-allowlist-result.json"), &allowlistResult)
	if err := allowlistResult.Validate(); err != nil {
		t.Fatalf("validate checked-in baseline allowlist result: %v", err)
	}
	var manifest LifecycleManifest
	manifestJSON := readTrustedAsset(t, filepath.Join(authorityRoot, "baseline-lifecycle-manifest.json"), &manifest)
	if err := manifest.Validate(); err != nil {
		t.Fatalf("validate checked-in baseline lifecycle manifest: %v", err)
	}
	var repeat SemanticRepeatResult
	repeatJSON := readTrustedAsset(t, filepath.Join(authorityRoot, "baseline-semantic-repeat.json"), &repeat)
	if err := repeat.Validate(); err != nil {
		t.Fatalf("validate checked-in semantic repeat: %v", err)
	}
	if manifest.BaselineAllowlist == nil || !sameCanonical(*manifest.BaselineAllowlist, allowlistResult) {
		t.Fatal("baseline lifecycle manifest does not bind the checked-in allowlist result")
	}
	if len(manifest.ReportIDs) != 2 || manifest.ReportIDs[0] != baseline.ID || manifest.ReportIDs[1] != baseline.ID ||
		len(repeat.ReportIDs) != 2 || repeat.ReportIDs[0] != baseline.ID || repeat.ReportIDs[1] != baseline.ID {
		t.Fatal("baseline lifecycle evidence does not bind two identical report IDs")
	}

	var review frozenReviewEvidence
	reviewJSON := readTrustedAsset(t, filepath.Join(authorityRoot, "baseline-review-evidence.json"), &review)
	var disposition frozenDispositionEvidence
	dispositionJSON := readTrustedAsset(t, filepath.Join(authorityRoot, "baseline-disposition-evidence.json"), &disposition)
	if manifest.Harness != review.Harness || manifest.Analyzer != review.Analyzer {
		t.Fatal("baseline review evidence does not bind lifecycle identities")
	}
	if checkpoint.ReviewEvidence != trustedAssetReference(review.ID, reviewJSON) ||
		checkpoint.DispositionEvidence != trustedAssetReference(disposition.ID, dispositionJSON) {
		t.Fatal("baseline checkpoint does not bind review and disposition evidence")
	}
	if disposition.Producer == disposition.Reviewer || disposition.Producer == disposition.Maintainer || disposition.Reviewer == disposition.Maintainer {
		t.Fatal("baseline disposition actors are not distinct")
	}

	baselineInputJSON := readTrustedAsset(t, filepath.Join(root, "baseline-input.json"), &measurement.MeasurementInput{})
	candidateInputJSON := readTrustedAsset(t, filepath.Join(root, "candidate-input.json"), &measurement.MeasurementInput{})
	bundleJSON := readTrustedAsset(t, filepath.Join(root, "trusted-bundle.json"), &TrustedBundle{})
	var provenance frozenCandidateAssetsProvenance
	readTrustedAsset(t, filepath.Join(authorityRoot, "candidate-assets-provenance.json"), &provenance)
	wantReferences := map[string]struct {
		got  measurement.ArtifactReference
		want measurement.ArtifactReference
	}{
		"baseline input":     {provenance.BaselineInput, trustedAssetReference("baseline-input.json", baselineInputJSON)},
		"candidate input":    {provenance.CandidateInput, trustedAssetReference("candidate-input.json", candidateInputJSON)},
		"baseline allowlist": {provenance.BaselineAllowlist, trustedAssetReference(allowlist.ID, allowlistJSON)},
		"allowlist result":   {provenance.AllowlistResult, trustedAssetReference("baseline-allowlist-result.json", allowlistResultJSON)},
		"baseline report":    {provenance.BaselineReport, trustedAssetReference(baseline.ID, baselineJSON)},
		"checkpoint":         {provenance.Checkpoint, trustedAssetReference(checkpoint.ID, checkpointJSON)},
		"ratchet":            {provenance.Ratchet, trustedAssetReference(ratchet.ID, ratchetJSON)},
		"review evidence":    {provenance.ReviewEvidence, trustedAssetReference(review.ID, reviewJSON)},
		"disposition":        {provenance.DispositionEvidence, trustedAssetReference(disposition.ID, dispositionJSON)},
		"lifecycle manifest": {provenance.LifecycleManifest, trustedAssetReference("baseline-lifecycle-manifest.json", manifestJSON)},
		"semantic repeat":    {provenance.SemanticRepeat, trustedAssetReference("baseline-semantic-repeat.json", repeatJSON)},
		"bundle":             {provenance.Bundle, bundleRef},
	}
	for name, references := range wantReferences {
		if references.got != references.want {
			t.Fatalf("%s provenance = %+v, want %+v", name, references.got, references.want)
		}
	}
	if bundleRef.Digest != benchmark.SHA256Digest(bundleJSON) || provenance.BaselineHarness != manifest.Harness || provenance.BaselineAnalyzer != manifest.Analyzer {
		t.Fatal("candidate asset provenance does not bind bundle and baseline identities")
	}
}

func checkedInTrustedAssetRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate trusted asset test source")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "usecase", "reachbench", "trusted")
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("resolve checked-in trusted asset root: %v", err)
	}
	return resolved
}

func assertTrustedAssetInventory(t *testing.T, root string) {
	t.Helper()
	want := []string{
		"authority/baseline-allowlist-result.json",
		"authority/baseline-checkpoint.json",
		"authority/baseline-disposition-evidence.json",
		"authority/baseline-lifecycle-manifest.json",
		"authority/baseline-report.json",
		"authority/baseline-review-evidence.json",
		"authority/baseline-semantic-repeat.json",
		"authority/candidate-assets-provenance.json",
		"authority/candidate-ratchet.json",
		"baseline-allowlist.json",
		"baseline-input.json",
		"candidate-input.json",
		"trusted-bundle.json",
	}
	var got []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			t.Fatalf("trusted asset inventory contains symlink %q", path)
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			t.Fatalf("trusted asset inventory contains special file %q", path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		got = append(got, filepath.ToSlash(relative))
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, marker := range [][]byte{
			[]byte("C:/Users/"), []byte(`C:\Users\`), []byte("/Users/"), []byte("/home/"),
			[]byte("/tmp/"), []byte("AppData"), []byte("synapse-reachability/private"),
		} {
			if bytes.Contains(raw, marker) {
				t.Fatalf("trusted asset %q leaks private marker %q", relative, marker)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect trusted asset inventory: %v", err)
	}
	sort.Strings(got)
	if !sameCanonical(got, want) {
		t.Fatalf("trusted asset inventory = %v, want %v", got, want)
	}
}

func readTrustedAsset(t *testing.T, path string, destination any) []byte {
	t.Helper()
	encoded, err := readCanonicalJSON(path, destination)
	if err != nil {
		t.Fatalf("read trusted asset %s: %v", path, err)
	}
	return encoded
}

func trustedAssetReference(id string, encoded []byte) measurement.ArtifactReference {
	return measurement.ArtifactReference{ID: id, Digest: benchmark.SHA256Digest(encoded)}
}
