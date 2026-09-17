package reachbench

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

const artifactManifestPath = "artifact-manifest.json"

func writeSanitizedBundle(ctx context.Context, publication *benchcycle.Publication, manifest LifecycleManifest, repeat SemanticRepeatResult, inputs []measurement.MeasurementInput, reports []measurement.MeasurementReport) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if len(inputs) != fixedRepetitions || len(reports) != fixedRepetitions {
		return errors.New("sanitary bundle requires exactly two inputs and reports")
	}
	files := make([]PublishedArtifact, 0, maxArtifactFiles)
	for index := range inputs {
		if err := contextError(ctx); err != nil {
			return err
		}
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
			entry, err := writeCanonicalArtifact(ctx, publication, prefix+"/"+artifact.name, artifact.value)
			if err != nil {
				return err
			}
			files = append(files, entry)
		}
		entry, err := writeReportArtifact(ctx, publication, prefix+"/report.json", reports[index])
		if err != nil {
			return err
		}
		files = append(files, entry)
	}
	if manifest.BaselineAllowlist != nil {
		entry, err := writeCanonicalArtifact(ctx, publication, baselineAllowlistResultPath(), *manifest.BaselineAllowlist)
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
		entry, err := writeCanonicalArtifact(ctx, publication, artifact.name, artifact.value)
		if err != nil {
			return err
		}
		files = append(files, entry)
	}
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	if len(files) >= maxArtifactFiles {
		return errors.New("sanitized artifact inventory exceeds lifecycle bound")
	}
	_, err := writeCanonicalArtifact(ctx, publication, artifactManifestPath, ArtifactManifest{SchemaVersion: ArtifactSchemaVersion, Files: files})
	return err
}

func writeCanonicalArtifact(ctx context.Context, publication *benchcycle.Publication, relative string, value any) (PublishedArtifact, error) {
	if err := contextError(ctx); err != nil {
		return PublishedArtifact{}, err
	}
	encoded, err := benchmark.CanonicalJSON(value)
	if err != nil {
		return PublishedArtifact{}, fmt.Errorf("encode %s: %w", relative, err)
	}
	var body bytes.Buffer
	if err := benchmark.WriteCanonicalJSON(&body, encoded); err != nil {
		return PublishedArtifact{}, fmt.Errorf("write %s: %w", relative, err)
	}
	identity, err := publication.WriteBytes(ctx, relative, body.Bytes())
	if err != nil {
		return PublishedArtifact{}, fmt.Errorf("write %s without overwrite: %w", relative, err)
	}
	return publishedArtifact(identity), nil
}

func writeReportArtifact(ctx context.Context, publication *benchcycle.Publication, relative string, report measurement.MeasurementReport) (PublishedArtifact, error) {
	if err := contextError(ctx); err != nil {
		return PublishedArtifact{}, err
	}
	var body bytes.Buffer
	if err := measurement.EncodeMeasurementReport(&body, report); err != nil {
		return PublishedArtifact{}, fmt.Errorf("encode %s: %w", relative, err)
	}
	identity, err := publication.WriteBytes(ctx, relative, body.Bytes())
	if err != nil {
		return PublishedArtifact{}, fmt.Errorf("write %s without overwrite: %w", relative, err)
	}
	return publishedArtifact(identity), nil
}

func publishedArtifact(identity benchcycle.FileIdentity) PublishedArtifact {
	return PublishedArtifact{Path: identity.Path, Digest: "sha256:" + identity.Digest}
}

func encodeReport(report measurement.MeasurementReport) ([]byte, error) {
	var body bytes.Buffer
	if err := measurement.EncodeMeasurementReport(&body, report); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

func replaySanitizedBundle(ctx context.Context, stage string, expectedManifest LifecycleManifest, expectedRepeat SemanticRepeatResult, facts runtimeFacts) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	manifestRaw, err := readRegularFileContext(ctx, filepath.Join(stage, artifactManifestPath))
	if err != nil {
		return fmt.Errorf("reopen artifact manifest: %w", err)
	}
	var artifacts ArtifactManifest
	if _, err := readCanonicalJSONContext(ctx, filepath.Join(stage, artifactManifestPath), &artifacts); err != nil {
		return fmt.Errorf("replay artifact manifest: %w", err)
	}
	if err := artifacts.Validate(); err != nil {
		return err
	}
	if err := verifyArtifactInventory(ctx, stage, artifacts); err != nil {
		return err
	}
	if err := verifyNoPrivateLeak(ctx, stage, append(artifacts.Files, PublishedArtifact{Path: artifactManifestPath, Digest: benchmark.SHA256Digest(manifestRaw)}), facts); err != nil {
		return err
	}

	var manifest LifecycleManifest
	if _, err := readCanonicalJSONContext(ctx, filepath.Join(stage, "lifecycle-manifest.json"), &manifest); err != nil {
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
		if _, err := readCanonicalJSONContext(ctx, filepath.Join(stage, baselineAllowlistResultPath()), &allowlist); err != nil {
			return fmt.Errorf("replay baseline allowlist result: %w", err)
		}
		if err := allowlist.Validate(); err != nil || !sameCanonical(allowlist, *manifest.BaselineAllowlist) {
			return errors.New("replayed baseline allowlist result does not bind the lifecycle manifest")
		}
	}
	var repeat SemanticRepeatResult
	if _, err := readCanonicalJSONContext(ctx, filepath.Join(stage, "semantic-repeat.json"), &repeat); err != nil {
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
		if err := contextError(ctx); err != nil {
			return err
		}
		input, report, err := replayRepetition(ctx, stage, repetition)
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

func replayRepetition(ctx context.Context, stage string, repetition int) (measurement.MeasurementInput, measurement.MeasurementReport, error) {
	if err := contextError(ctx); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, err
	}
	prefix := fmt.Sprintf("repetition-%d", repetition)
	var inventory measurement.ProductionInventory
	if _, err := readCanonicalJSONContext(ctx, filepath.Join(stage, prefix, "inventory.json"), &inventory); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, fmt.Errorf("replay repetition %d inventory: %w", repetition, err)
	}
	if err := inventory.Validate(); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, err
	}
	var corpus measurement.ContractCorpus
	if _, err := readCanonicalJSONContext(ctx, filepath.Join(stage, prefix, "corpus.json"), &corpus); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, fmt.Errorf("replay repetition %d corpus: %w", repetition, err)
	}
	if err := corpus.Validate(); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, err
	}
	var oracle measurement.ReachabilityOracle
	if _, err := readCanonicalJSONContext(ctx, filepath.Join(stage, prefix, "oracle.json"), &oracle); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, fmt.Errorf("replay repetition %d oracle: %w", repetition, err)
	}
	if err := oracle.ValidateAgainst(corpus); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, err
	}
	var policy measurement.MeasurementPolicy
	if _, err := readCanonicalJSONContext(ctx, filepath.Join(stage, prefix, "policy.json"), &policy); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, fmt.Errorf("replay repetition %d policy: %w", repetition, err)
	}
	if err := policy.Validate(); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, err
	}
	var exceptions measurement.ExceptionManifest
	if _, err := readCanonicalJSONContext(ctx, filepath.Join(stage, prefix, "exceptions.json"), &exceptions); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, fmt.Errorf("replay repetition %d exceptions: %w", repetition, err)
	}
	if err := exceptions.Validate(); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, err
	}
	var input measurement.MeasurementInput
	if _, err := readCanonicalJSONContext(ctx, filepath.Join(stage, prefix, "input.json"), &input); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, fmt.Errorf("replay repetition %d input: %w", repetition, err)
	}
	if err := input.Validate(); err != nil {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, err
	}
	if !sameCanonical(inventory, input.Inventory) || !sameCanonical(corpus, input.Corpus) || !sameCanonical(oracle, input.Oracle) || !sameCanonical(policy, input.Policy) || !sameCanonical(exceptions, input.Exceptions) {
		return measurement.MeasurementInput{}, measurement.MeasurementReport{}, fmt.Errorf("replayed contract artifacts for repetition %d do not match its input", repetition)
	}
	var report measurement.MeasurementReport
	if _, err := readCanonicalJSONContext(ctx, filepath.Join(stage, prefix, "report.json"), &report); err != nil {
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

func readCanonicalJSONContext(ctx context.Context, path string, destination any) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	raw, err := readRegularFileContext(ctx, path)
	if err != nil {
		return nil, err
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := benchmark.ValidateJSONDocument(bytes.NewReader(raw)); err != nil {
		return nil, err
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
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	return encoded, nil
}

func readRegularFileContext(ctx context.Context, path string) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
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
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		return nil, errors.New("artifact changed while opening")
	}
	body := make([]byte, 0, info.Size())
	buffer := make([]byte, 32<<10)
	for {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		read, readErr := file.Read(buffer)
		if read > 0 {
			body = append(body, buffer[:read]...)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
		if read == 0 {
			return nil, io.ErrNoProgress
		}
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || !os.SameFile(info, after) || after.Size() != int64(len(body)) {
		return nil, errors.New("artifact changed while reading")
	}
	return body, nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("reachability lifecycle context is required")
	}
	return ctx.Err()
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

func verifyArtifactInventory(ctx context.Context, stage string, artifacts ArtifactManifest) error {
	actual, err := regularRelativeFiles(ctx, stage)
	if err != nil {
		return err
	}
	expected := make([]string, 0, len(artifacts.Files)+1)
	for _, item := range artifacts.Files {
		if err := contextError(ctx); err != nil {
			return err
		}
		raw, err := readRegularFileContext(ctx, filepath.Join(stage, filepath.FromSlash(item.Path)))
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

func regularRelativeFiles(ctx context.Context, root string) ([]string, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	files := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if err := contextError(ctx); err != nil {
			return err
		}
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

func verifyNoPrivateLeak(ctx context.Context, stage string, files []PublishedArtifact, facts runtimeFacts) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	forbidden := []string{facts.repositoryRoot, facts.checkoutBundleRoot, facts.temporaryRoot, facts.rawRoot, facts.outputRoot, facts.controllerRoot}
	for _, item := range files {
		if err := contextError(ctx); err != nil {
			return err
		}
		raw, err := readRegularFileContext(ctx, filepath.Join(stage, filepath.FromSlash(item.Path)))
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
		if manifest.Purpose != measurement.CandidateAcceptance || manifest.FinalMode != FinalAcceptance || manifest.BaselineAllowlist != nil || manifest.Analyzer.ID != AnalyzerSubjectID || manifest.Analyzer.Commit != manifest.Harness.Commit || manifest.Analyzer.Tree != manifest.Harness.Tree {
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
