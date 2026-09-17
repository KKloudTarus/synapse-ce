package reachbench

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

const artifactManifestPath = "artifact-manifest.json"

func writeSanitizedBundle(stage string, manifest LifecycleManifest, repeat SemanticRepeatResult, inputs []measurement.MeasurementInput, reports []measurement.MeasurementReport) error {
	if len(inputs) != fixedRepetitions || len(reports) != fixedRepetitions {
		return errors.New("sanitary bundle requires exactly two inputs and reports")
	}
	files := make([]PublishedArtifact, 0, maxArtifactFiles)
	for index := range inputs {
		prefix := fmt.Sprintf("repetition-%d", index+1)
		for _, artifact := range []struct {
			name  string
			value any
		}{
			{"inventory.json", inputs[index].Inventory},
			{"corpus.json", inputs[index].Corpus},
			{"oracle.json", inputs[index].Oracle},
			{"policy.json", inputs[index].Policy},
			{"exceptions.json", inputs[index].Exceptions},
			{"input.json", inputs[index]},
		} {
			path := prefix + "/" + artifact.name
			if err := writeCanonicalArtifact(stage, path, artifact.value); err != nil {
				return err
			}
			entry, err := artifactEntry(stage, path)
			if err != nil {
				return err
			}
			files = append(files, entry)
		}
		path := prefix + "/report.json"
		if err := writeReportArtifact(stage, path, reports[index]); err != nil {
			return err
		}
		entry, err := artifactEntry(stage, path)
		if err != nil {
			return err
		}
		files = append(files, entry)
	}
	if manifest.BaselineAllowlist != nil {
		if err := writeCanonicalArtifact(stage, baselineAllowlistResultPath(), *manifest.BaselineAllowlist); err != nil {
			return err
		}
		entry, err := artifactEntry(stage, baselineAllowlistResultPath())
		if err != nil {
			return err
		}
		files = append(files, entry)
	}
	for _, artifact := range []struct {
		name  string
		value any
	}{
		{"lifecycle-manifest.json", manifest},
		{"semantic-repeat.json", repeat},
	} {
		if err := writeCanonicalArtifact(stage, artifact.name, artifact.value); err != nil {
			return err
		}
		entry, err := artifactEntry(stage, artifact.name)
		if err != nil {
			return err
		}
		files = append(files, entry)
	}
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	if len(files) > maxArtifactFiles {
		return errors.New("sanitized artifact inventory exceeds lifecycle bound")
	}
	if err := writeCanonicalArtifact(stage, artifactManifestPath, ArtifactManifest{SchemaVersion: ArtifactSchemaVersion, Files: files}); err != nil {
		return err
	}
	return benchcycle.SyncDirectory(stage)
}

func writeCanonicalArtifact(stage, relative string, value any) error {
	encoded, err := benchmark.CanonicalJSON(value)
	if err != nil {
		return fmt.Errorf("encode %s: %w", relative, err)
	}
	var body bytes.Buffer
	if err := benchmark.WriteCanonicalJSON(&body, encoded); err != nil {
		return fmt.Errorf("write %s: %w", relative, err)
	}
	if err := benchcycle.WriteNewFile(filepath.Join(stage, filepath.FromSlash(relative)), body.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write %s without overwrite: %w", relative, err)
	}
	return nil
}

func writeReportArtifact(stage, relative string, report measurement.MeasurementReport) error {
	var body bytes.Buffer
	if err := measurement.EncodeMeasurementReport(&body, report); err != nil {
		return fmt.Errorf("encode %s: %w", relative, err)
	}
	if err := benchcycle.WriteNewFile(filepath.Join(stage, filepath.FromSlash(relative)), body.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write %s without overwrite: %w", relative, err)
	}
	return nil
}

func encodeReport(report measurement.MeasurementReport) ([]byte, error) {
	var body bytes.Buffer
	if err := measurement.EncodeMeasurementReport(&body, report); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

func artifactEntry(stage, relative string) (PublishedArtifact, error) {
	raw, err := readRegularFile(filepath.Join(stage, filepath.FromSlash(relative)))
	if err != nil {
		return PublishedArtifact{}, fmt.Errorf("digest %s: %w", relative, err)
	}
	return PublishedArtifact{Path: relative, Digest: benchmark.SHA256Digest(raw)}, nil
}

func replaySanitizedBundle(stage string, expectedManifest LifecycleManifest, expectedRepeat SemanticRepeatResult, facts runtimeFacts) error {
	manifestRaw, err := readRegularFile(filepath.Join(stage, artifactManifestPath))
	if err != nil {
		return fmt.Errorf("reopen artifact manifest: %w", err)
	}
	var artifacts ArtifactManifest
	if _, err := readCanonicalJSON(filepath.Join(stage, artifactManifestPath), &artifacts); err != nil {
		return fmt.Errorf("replay artifact manifest: %w", err)
	}
	if err := artifacts.Validate(); err != nil {
		return err
	}
	if err := verifyArtifactInventory(stage, artifacts); err != nil {
		return err
	}
	if err := verifyNoPrivateLeak(stage, append(artifacts.Files, PublishedArtifact{Path: artifactManifestPath, Digest: benchmark.SHA256Digest(manifestRaw)}), facts); err != nil {
		return err
	}

	var manifest LifecycleManifest
	if _, err := readCanonicalJSON(filepath.Join(stage, "lifecycle-manifest.json"), &manifest); err != nil {
		return fmt.Errorf("replay lifecycle manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return err
	}
	if !sameCanonical(manifest, expectedManifest) {
		return errors.New("replayed lifecycle manifest differs from staged manifest")
	}
	if manifest.BaselineAllowlist != nil {
		var allowlist BaselineAllowlistResult
		if _, err := readCanonicalJSON(filepath.Join(stage, baselineAllowlistResultPath()), &allowlist); err != nil {
			return fmt.Errorf("replay baseline allowlist result: %w", err)
		}
		if err := allowlist.Validate(); err != nil || !sameCanonical(allowlist, *manifest.BaselineAllowlist) {
			return errors.New("replayed baseline allowlist result does not bind the lifecycle manifest")
		}
	}
	var repeat SemanticRepeatResult
	if _, err := readCanonicalJSON(filepath.Join(stage, "semantic-repeat.json"), &repeat); err != nil {
		return fmt.Errorf("replay semantic repeat result: %w", err)
	}
	if err := repeat.Validate(); err != nil {
		return err
	}
	if !sameCanonical(repeat, expectedRepeat) {
		return errors.New("replayed semantic repeat result differs from staged result")
	}

	reportIDs := make([]string, 0, fixedRepetitions)
	for repetition := 1; repetition <= fixedRepetitions; repetition++ {
		input, report, err := replayRepetition(stage, repetition)
		if err != nil {
			return err
		}
		recomputed, err := measurement.EvaluateMeasurement(input)
		if err != nil {
			return fmt.Errorf("re-evaluate repetition %d input: %w", repetition, err)
		}
		if !sameCanonical(recomputed, report) {
			return fmt.Errorf("replayed report for repetition %d does not match deterministic evaluation", repetition)
		}
		reportIDs = append(reportIDs, report.ID)
	}
	if !equalStrings(reportIDs, manifest.ReportIDs) || !equalStrings(reportIDs, repeat.ReportIDs) {
		return errors.New("public report identifiers are not bound across lifecycle artifacts")
	}
	return nil
}

func replayRepetition(stage string, repetition int) (measurement.MeasurementInput, measurement.MeasurementReport, error) {
	prefix := fmt.Sprintf("repetition-%d", repetition)
	var inventory measurement.ProductionInventory
	if _, err := readCanonicalJSON(filepath.Join(stage, prefix, "inventory.json"), &inventory); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, fmt.Errorf("replay repetition %d inventory: %w", repetition, err)
	}
	if err := inventory.Validate(); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, err
	}
	var corpus measurement.ContractCorpus
	if _, err := readCanonicalJSON(filepath.Join(stage, prefix, "corpus.json"), &corpus); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, fmt.Errorf("replay repetition %d corpus: %w", repetition, err)
	}
	if err := corpus.Validate(); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, err
	}
	var oracle measurement.ReachabilityOracle
	if _, err := readCanonicalJSON(filepath.Join(stage, prefix, "oracle.json"), &oracle); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, fmt.Errorf("replay repetition %d oracle: %w", repetition, err)
	}
	if err := oracle.ValidateAgainst(corpus); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, err
	}
	var policy measurement.MeasurementPolicy
	if _, err := readCanonicalJSON(filepath.Join(stage, prefix, "policy.json"), &policy); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, fmt.Errorf("replay repetition %d policy: %w", repetition, err)
	}
	if err := policy.Validate(); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, err
	}
	var exceptions measurement.ExceptionManifest
	if _, err := readCanonicalJSON(filepath.Join(stage, prefix, "exceptions.json"), &exceptions); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, fmt.Errorf("replay repetition %d exceptions: %w", repetition, err)
	}
	if err := exceptions.Validate(); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, err
	}
	var input measurement.MeasurementInput
	if _, err := readCanonicalJSON(filepath.Join(stage, prefix, "input.json"), &input); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, fmt.Errorf("replay repetition %d input: %w", repetition, err)
	}
	if err := input.Validate(); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, err
	}
	if !sameCanonical(inventory, input.Inventory) || !sameCanonical(corpus, input.Corpus) || !sameCanonical(oracle, input.Oracle) || !sameCanonical(policy, input.Policy) || !sameCanonical(exceptions, input.Exceptions) {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, fmt.Errorf("replayed contract artifacts for repetition %d do not match its input", repetition)
	}
	var report measurement.MeasurementReport
	if _, err := readCanonicalJSON(filepath.Join(stage, prefix, "report.json"), &report); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, fmt.Errorf("replay repetition %d report: %w", repetition, err)
	}
	if err := report.Validate(); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, err
	}
	return input, report, nil
}

func readCanonicalJSON(path string, destination any) ([]byte, error) {
	raw, err := readRegularFile(path)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > benchmark.MaxJSONBytes {
		return nil, errors.New("JSON document exceeds benchmark size bound")
	}
	if err := benchmark.StrictDecode(bytes.NewReader(raw), destination); err != nil {
		return nil, err
	}
	encoded, err := benchmark.CanonicalJSON(destination)
	if err != nil {
		return nil, err
	}
	var canonical bytes.Buffer
	if err := benchmark.WriteCanonicalJSON(&canonical, encoded); err != nil {
		return nil, err
	}
	if !bytes.Equal(raw, canonical.Bytes()) {
		return nil, errors.New("JSON document is not canonical")
	}
	return encoded, nil
}

func readRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("artifact must be a regular non-symlink file")
	}
	if info.Size() > benchmark.MaxJSONBytes {
		return nil, errors.New("artifact exceeds benchmark JSON size bound")
	}
	return os.ReadFile(path)
}

func verifyArtifactInventory(stage string, artifacts ArtifactManifest) error {
	actual, err := regularRelativeFiles(stage)
	if err != nil {
		return err
	}
	expected := make([]string, 0, len(artifacts.Files)+1)
	for _, item := range artifacts.Files {
		raw, err := readRegularFile(filepath.Join(stage, filepath.FromSlash(item.Path)))
		if err != nil {
			return fmt.Errorf("reopen %s: %w", item.Path, err)
		}
		if benchmark.SHA256Digest(raw) != item.Digest {
			return fmt.Errorf("artifact digest mismatch for %s", item.Path)
		}
		expected = append(expected, item.Path)
	}
	expected = append(expected, artifactManifestPath)
	sort.Strings(expected)
	if !equalStrings(actual, expected) {
		return errors.New("sanitized artifact inventory is not exact")
	}
	return nil
}

func regularRelativeFiles(root string) ([]string, error) {
	files := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("sanitized stage contains a symlink")
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("sanitized stage contains a non-regular file")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func verifyNoPrivateLeak(stage string, files []PublishedArtifact, facts runtimeFacts) error {
	forbidden := []string{facts.repositoryRoot, facts.checkoutBundleRoot, facts.temporaryRoot, facts.rawRoot, facts.outputRoot, facts.controllerRoot}
	for _, item := range files {
		raw, err := readRegularFile(filepath.Join(stage, filepath.FromSlash(item.Path)))
		if err != nil {
			return err
		}
		for _, value := range forbidden {
			if hasPrivatePathVariant(raw, value) {
				return fmt.Errorf("sanitized artifact %s leaks a private path", item.Path)
			}
		}
	}
	return nil
}

func (manifest ArtifactManifest) Validate() error {
	if manifest.SchemaVersion != ArtifactSchemaVersion || len(manifest.Files) == 0 || len(manifest.Files) > maxArtifactFiles {
		return errors.New("invalid reachability artifact manifest")
	}
	previous := ""
	for _, item := range manifest.Files {
		if item.Path == artifactManifestPath || !fs.ValidPath(item.Path) || !validDigest(item.Digest) || item.Path <= previous {
			return errors.New("artifact manifest must contain strictly sorted digest-bound relative files")
		}
		previous = item.Path
	}
	return nil
}

func (manifest LifecycleManifest) Validate() error {
	if manifest.SchemaVersion != LifecycleSchemaVersion || !bounded(manifest.RunKey) || manifest.Repetitions != fixedRepetitions {
		return errors.New("invalid reachability lifecycle manifest")
	}
	if err := benchcycle.ValidateRunKey(manifest.RunKey); err != nil {
		return err
	}
	if err := validateHarness(manifest.Harness); err != nil || validateRevision(manifest.Analyzer) != nil || manifest.Harness.ID == manifest.Analyzer.ID {
		return errors.New("invalid or conflated lifecycle source identities")
	}
	if err := manifest.Snapshot.Validate(); err != nil || validateArtifact(manifest.Bundle) != nil {
		return errors.New("invalid lifecycle manifest identities")
	}
	if manifest.Authoritative != manifest.Route.authoritative() {
		return errors.New("lifecycle manifest authority does not match its route")
	}
	switch manifest.Route {
	case RouteProtectedBaseline:
		if manifest.Purpose != measurement.BaselineMeasurement || manifest.FinalMode != FinalBaseline || manifest.Analyzer.ID != AnalyzerSubjectID || manifest.Analyzer.Commit != measurement.TrustedBaselineRevision || manifest.BaselineAllowlist == nil {
			return errors.New("invalid protected baseline lifecycle manifest")
		}
		if err := manifest.Authority.Validate(); err != nil || manifest.Authority.ReviewedHarnessID != manifest.Harness.ID || manifest.BaselineAllowlist.Harness != manifest.Harness || manifest.BaselineAllowlist.Analyzer != manifest.Analyzer {
			return errors.New("protected baseline lifecycle authority or allowlist does not bind identities")
		}
		if err := manifest.BaselineAllowlist.Validate(); err != nil {
			return err
		}
	case RouteCandidate:
		if manifest.Purpose != measurement.CandidateAcceptance || manifest.FinalMode != FinalAcceptance || manifest.BaselineAllowlist != nil {
			return errors.New("invalid candidate lifecycle manifest")
		}
		if err := manifest.Authority.Validate(); err != nil || manifest.Authority.ReviewedHarnessID != manifest.Harness.ID {
			return errors.New("candidate lifecycle authority does not bind the harness")
		}
	case RouteLocalDiagnostic:
		if manifest.Purpose != measurement.CandidateAcceptance || manifest.FinalMode != FinalDiagnostic || manifest.BaselineAllowlist != nil || manifest.Authority != (ProceduralAuthority{}) {
			return errors.New("invalid local diagnostic lifecycle manifest")
		}
	default:
		return errors.New("unknown lifecycle manifest route")
	}
	if len(manifest.Cells) == 0 || len(manifest.Cells) > maxCells || len(manifest.ReportIDs) != fixedRepetitions {
		return errors.New("lifecycle manifest has invalid cells or reports")
	}
	previous := ""
	for _, cell := range manifest.Cells {
		if !bounded(cell.CaseID) || !bounded(cell.BindingID) || !bounded(cell.AnalyzerID) || validateArtifact(cell.Configuration) != nil || cellKey(cell) <= previous {
			return errors.New("lifecycle manifest contains invalid or unsorted cells")
		}
		previous = cellKey(cell)
	}
	for _, id := range manifest.ReportIDs {
		if !validDigest(id) {
			return errors.New("lifecycle manifest contains invalid report ID")
		}
	}
	return nil
}

func (repeat SemanticRepeatResult) Validate() error {
	if repeat.SchemaVersion != RepeatSchemaVersion || repeat.Repetitions != fixedRepetitions || !repeat.SemanticallyEqual || len(repeat.ReportIDs) != fixedRepetitions || len(repeat.Cells) == 0 || len(repeat.Cells) > maxCells {
		return errors.New("invalid semantic repeat result")
	}
	previous := ""
	for _, item := range repeat.Cells {
		key := item.CaseID + "\x00" + item.BindingID
		if !bounded(item.CaseID) || !bounded(item.BindingID) || !validDigest(item.ProjectionDigest) || key <= previous {
			return errors.New("semantic repeat result contains invalid or unsorted cells")
		}
		previous = key
	}
	for _, id := range repeat.ReportIDs {
		if !validDigest(id) {
			return errors.New("semantic repeat result contains invalid report ID")
		}
	}
	return nil
}

func sameCanonical(left, right any) bool {
	leftEncoded, leftErr := benchmark.CanonicalJSON(left)
	rightEncoded, rightErr := benchmark.CanonicalJSON(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftEncoded, rightEncoded)
}

func equalStrings(left, right []string) bool {
	return len(left) == len(right) && func() bool {
		for index := range left {
			if left[index] != right[index] {
				return false
			}
		}
		return true
	}()
}
