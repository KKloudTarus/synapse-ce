package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	capture "github.com/KKloudTarus/synapse-ce/internal/infrastructure/scabench"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

var publicationIndexKinds = map[string]struct{}{
	"source_snapshot":        {},
	"pin":                    {},
	"sbom":                   {},
	"normalized_observation": {},
	"native_comparison":      {},
	"process_identity":       {},
	"ratchet":                {},
}

func materializePublicationControl(option options) error {
	if err := requirePaths(
		struct{ name, value string }{"candidate root", option.candidateRoot},
		struct{ name, value string }{"implementation commit", option.implementationCommit},
		struct{ name, value string }{"cycle plan", option.planOutput},
		struct{ name, value string }{"publication control output", option.publicationControlOutput},
	); err != nil {
		return err
	}
	if !validCommitSHA(option.implementationCommit) {
		return fmt.Errorf("implementation commit must be a full lowercase SHA")
	}
	plan, err := decodePlan(option.planOutput)
	if err != nil {
		return err
	}
	var policy cyclePolicy
	if err := decodeJSONFile(filepath.Join(option.candidateRoot, "control", "cycle-policy.json"), &policy); err != nil {
		return err
	}
	if err := policy.validate(); err != nil {
		return err
	}
	if policy.Repetitions != plan.Repetitions {
		return fmt.Errorf("cycle policy and plan repetition counts differ")
	}
	catalog, err := decodeCatalog(filepath.Join(option.candidateRoot, "control", "catalog.json"))
	if err != nil {
		return err
	}
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		return err
	}
	groups := make(map[string][]bench.ContentReference)
	appendExact := func(kind string, locators ...string) error {
		for _, locator := range locators {
			path := filepath.Join(option.candidateRoot, filepath.FromSlash(locator))
			reference, referenceErr := contentReference(path, locator)
			if referenceErr != nil {
				return fmt.Errorf("reference %s artifact %q: %w", kind, locator, referenceErr)
			}
			groups[kind] = append(groups[kind], reference)
		}
		return nil
	}
	if err := appendExact("source_snapshot", "control/source-freeze.json", "control/source-evidence-plan.json"); err != nil {
		return err
	}
	freeze, err := decodeSourceFreeze(filepath.Join(option.candidateRoot, "control", "source-freeze.json"))
	if err != nil {
		return err
	}
	sourceReferences, err := fileList(option.candidateRoot, "control/source-assets", func(string) bool { return true })
	if err != nil {
		return err
	}
	if len(sourceReferences) != len(freeze.Assets) {
		return fmt.Errorf("source asset count %d does not match source freeze assets %d", len(sourceReferences), len(freeze.Assets))
	}
	expectedSources := make(map[string]bench.ContentReference, len(freeze.Assets))
	for _, asset := range freeze.Assets {
		locator := filepath.ToSlash(filepath.Join("control", "source-assets", filepath.FromSlash(asset.Locator)))
		expectedSources[locator] = asset
	}
	for _, reference := range sourceReferences {
		expected, exists := expectedSources[reference.Locator]
		if !exists || reference.Digest != expected.Digest || reference.Size != expected.Size {
			return fmt.Errorf("source asset %q does not match the source freeze", reference.Locator)
		}
		delete(expectedSources, reference.Locator)
		groups["source_snapshot"] = append(groups["source_snapshot"], reference)
	}
	if err := appendExact("pin", "control/catalog.json", "control/oracle.json", "control/cycle-policy.json", "control/falsifier-spec.json", "control/plan.json", "control/review-capture.json"); err != nil {
		return err
	}
	review, err := decodeReview(filepath.Join(option.candidateRoot, "control", "accountable-review.json"))
	if err != nil {
		return err
	}
	retainedReviewCapture := groups["pin"][len(groups["pin"])-1]
	if retainedReviewCapture.Digest != review.ReviewCapture.Digest || retainedReviewCapture.Size != review.ReviewCapture.Size {
		return fmt.Errorf("retained review capture does not match the accountable review")
	}
	manifestReferences, err := fileList(option.candidateRoot, "control/capture-manifests", func(locator string) bool { return strings.HasSuffix(locator, ".json") })
	if err != nil {
		return err
	}
	if len(manifestReferences) != len(plan.Cells) {
		return fmt.Errorf("capture manifest count %d does not match plan cells %d", len(manifestReferences), len(plan.Cells))
	}
	expectedCapabilities := make(map[string]string)
	manifests := make(map[string]capture.CaptureManifest, len(manifestReferences))
	for _, reference := range manifestReferences {
		manifest, decodeErr := decodeCaptureManifest(filepath.Join(option.candidateRoot, filepath.FromSlash(reference.Locator)))
		if decodeErr != nil {
			return decodeErr
		}
		cell, planned := plannedCell(plan, manifest.TargetID, manifest.Engine)
		if !planned {
			return fmt.Errorf("generated capture manifest %q is not in the plan", reference.Locator)
		}
		target, exists := targetByID(catalog, manifest.TargetID)
		if !exists || manifest.CatalogRevision != catalog.Revision || manifest.CatalogDigest != catalogDigest {
			return fmt.Errorf("generated capture manifest %q does not bind the candidate catalog", reference.Locator)
		}
		expectedSBOMPath := filepath.Join(option.candidateRoot, "control", "sboms", target.ID+".cdx.json")
		if filepath.Clean(manifest.SBOMPath) != filepath.Clean(expectedSBOMPath) {
			return fmt.Errorf("generated capture manifest %q does not select the retained canonical SBOM", reference.Locator)
		}
		if cell.ExpectedState == bench.ObservationUnsupported {
			if manifest.Capability == nil {
				return fmt.Errorf("unsupported capture manifest %q omits its capability statement", reference.Locator)
			}
			capabilityLocator := filepath.ToSlash(filepath.Join("control", "capability-statements", manifest.TargetID+"--"+string(manifest.Engine)+".json"))
			expectedCapabilityPath := filepath.Join(option.candidateRoot, filepath.FromSlash(capabilityLocator))
			if filepath.Clean(manifest.Capability.Statement.Path) != filepath.Clean(expectedCapabilityPath) {
				return fmt.Errorf("unsupported capture manifest %q does not select its retained capability statement", reference.Locator)
			}
			expectedCapabilities[capabilityLocator] = manifest.Capability.Statement.Digest
		} else if manifest.Capability != nil {
			return fmt.Errorf("dispatched capture manifest %q carries an unsupported capability statement", reference.Locator)
		}
		expectedLocator := filepath.ToSlash(filepath.Join("control", "capture-manifests", manifest.TargetID+"--"+string(manifest.Engine)+".json"))
		if reference.Locator != expectedLocator {
			return fmt.Errorf("generated capture manifest locator %q does not match identity %q", reference.Locator, expectedLocator)
		}
		manifests[cellKey(manifest.TargetID, manifest.Engine)] = manifest
		groups["pin"] = append(groups["pin"], reference)
	}
	capabilityReferences, err := fileList(option.candidateRoot, "control/capability-statements", func(locator string) bool { return strings.HasSuffix(locator, ".json") })
	if err != nil {
		return err
	}
	expectedCapabilityCount := 0
	for _, cell := range plan.Cells {
		if cell.ExpectedState == bench.ObservationUnsupported {
			expectedCapabilityCount++
		}
	}
	if len(expectedCapabilities) != expectedCapabilityCount || len(capabilityReferences) != expectedCapabilityCount {
		return fmt.Errorf("capability statement count does not match unsupported plan cells %d", expectedCapabilityCount)
	}
	for _, reference := range capabilityReferences {
		expectedDigest, exists := expectedCapabilities[reference.Locator]
		if !exists || reference.Digest != expectedDigest {
			return fmt.Errorf("capability statement %q does not match its generated capture manifest", reference.Locator)
		}
		delete(expectedCapabilities, reference.Locator)
	}
	groups["pin"] = append(groups["pin"], capabilityReferences...)
	sbomReferences, err := fileList(option.candidateRoot, "control/sboms", func(locator string) bool { return strings.HasSuffix(locator, ".cdx.json") })
	if err != nil {
		return err
	}
	targets := distinctPlanTargets(plan)
	if len(sbomReferences) != len(targets) {
		return fmt.Errorf("SBOM count %d does not match plan targets %d", len(sbomReferences), len(targets))
	}
	expectedSBOMs := make(map[string]bench.Target, len(targets))
	for _, targetID := range targets {
		target, exists := targetByID(catalog, targetID)
		if !exists {
			return fmt.Errorf("plan target %q is absent from the candidate catalog", targetID)
		}
		expectedSBOMs[filepath.ToSlash(filepath.Join("control", "sboms", targetID+".cdx.json"))] = target
	}
	for _, reference := range sbomReferences {
		target, exists := expectedSBOMs[reference.Locator]
		if !exists {
			return fmt.Errorf("SBOM locator %q does not match a planned target", reference.Locator)
		}
		if reference.Digest != target.SBOMDigest {
			return fmt.Errorf("SBOM %q does not match the candidate catalog digest", reference.Locator)
		}
		delete(expectedSBOMs, reference.Locator)
	}
	groups["sbom"] = append(groups["sbom"], sbomReferences...)
	observationReferences, err := fileList(option.candidateRoot, "control/observations", func(locator string) bool { return strings.HasSuffix(locator, ".json") })
	if err != nil {
		return err
	}
	expectedSlots := plan.Repetitions * len(plan.Cells)
	if len(observationReferences) != expectedSlots {
		return fmt.Errorf("normalized observation count %d does not match planned slots %d", len(observationReferences), expectedSlots)
	}
	expectedObservations := make(map[string]bench.CycleCell, expectedSlots)
	for repetition := 1; repetition <= plan.Repetitions; repetition++ {
		for _, cell := range plan.Cells {
			locator := filepath.ToSlash(filepath.Join("control", "observations", fmt.Sprintf("%d", repetition), cell.TargetID+"--"+string(cell.Engine)+".json"))
			expectedObservations[locator] = cell
		}
	}
	for _, reference := range observationReferences {
		expectedCell, exists := expectedObservations[reference.Locator]
		if !exists {
			return fmt.Errorf("normalized observation locator %q does not match a planned slot", reference.Locator)
		}
		delete(expectedObservations, reference.Locator)
		var observation bench.Observation
		if err := decodeJSONFile(filepath.Join(option.candidateRoot, filepath.FromSlash(reference.Locator)), &observation); err != nil {
			return err
		}
		set := bench.ObservationSet{SchemaVersion: bench.ObservationSchemaVersion, CatalogRevision: observation.CatalogRevision, CatalogDigest: observation.CatalogDigest, Observations: []bench.Observation{observation}}
		if err := set.Validate(); err != nil {
			return fmt.Errorf("validate normalized observation %q: %w", reference.Locator, err)
		}
		if observation.TargetID != expectedCell.TargetID || observation.Engine != expectedCell.Engine || observation.State != expectedCell.ExpectedState {
			return fmt.Errorf("normalized observation %q does not match its planned slot", reference.Locator)
		}
		target, exists := targetByID(catalog, observation.TargetID)
		manifest, manifestExists := manifests[cellKey(observation.TargetID, observation.Engine)]
		if !exists || !manifestExists {
			return fmt.Errorf("normalized observation %q has no generated catalog and manifest identity", reference.Locator)
		}
		if err := validateObservationManifestBindings(catalog, catalogDigest, target, manifest, observation); err != nil {
			return fmt.Errorf("validate normalized observation %q: %w", reference.Locator, err)
		}
		groups["normalized_observation"] = append(groups["normalized_observation"], reference)
	}
	if err := appendExact("native_comparison", "publication/native-evidence.json"); err != nil {
		return err
	}
	recordReferences, err := fileList(option.candidateRoot, "records", func(locator string) bool { return strings.HasSuffix(locator, ".json") })
	if err != nil {
		return err
	}
	if len(recordReferences) < expectedSlots {
		return fmt.Errorf("process identity records %d do not cover planned slots %d", len(recordReferences), expectedSlots)
	}
	type orderedCapture struct {
		attempt int
		record  capture.CycleCellCapture
	}
	orderedCaptures := make([]orderedCapture, 0, len(recordReferences))
	for _, reference := range recordReferences {
		var record capture.CycleCellCapture
		if err := decodeJSONFile(filepath.Join(option.candidateRoot, filepath.FromSlash(reference.Locator)), &record); err != nil {
			return err
		}
		prefix := filepath.ToSlash(filepath.Join("records", fmt.Sprintf("%d-%s--%s-attempt-", record.Repetition, record.TargetID, record.Engine)))
		if !strings.HasPrefix(reference.Locator, prefix) || !strings.HasSuffix(reference.Locator, ".json") {
			return fmt.Errorf("process identity record locator %q does not match its captured slot", reference.Locator)
		}
		attemptText := strings.TrimSuffix(strings.TrimPrefix(reference.Locator, prefix), ".json")
		attempt, parseErr := strconv.Atoi(attemptText)
		if parseErr != nil || attempt < 1 || attempt > policy.MaxAttempts {
			return fmt.Errorf("process identity record locator %q has an attempt outside policy", reference.Locator)
		}
		orderedCaptures = append(orderedCaptures, orderedCapture{attempt: attempt, record: record})
	}
	sort.Slice(orderedCaptures, func(left, right int) bool {
		if orderedCaptures[left].record.Repetition != orderedCaptures[right].record.Repetition {
			return orderedCaptures[left].record.Repetition < orderedCaptures[right].record.Repetition
		}
		if orderedCaptures[left].record.TargetID != orderedCaptures[right].record.TargetID {
			return orderedCaptures[left].record.TargetID < orderedCaptures[right].record.TargetID
		}
		if orderedCaptures[left].record.Engine != orderedCaptures[right].record.Engine {
			return orderedCaptures[left].record.Engine < orderedCaptures[right].record.Engine
		}
		return orderedCaptures[left].attempt < orderedCaptures[right].attempt
	})
	captures := make([]capture.CycleCellCapture, 0, len(orderedCaptures))
	for index, item := range orderedCaptures {
		expectedAttempt := 1
		if index > 0 {
			previous := orderedCaptures[index-1]
			if previous.record.Repetition == item.record.Repetition && previous.record.TargetID == item.record.TargetID && previous.record.Engine == item.record.Engine {
				expectedAttempt = previous.attempt + 1
			}
		}
		if item.attempt != expectedAttempt {
			return fmt.Errorf("process identity records do not retain a contiguous attempt sequence")
		}
		captures = append(captures, item.record)
	}
	derivedLedger, err := capture.BuildCycleLedger(plan, captures)
	if err != nil {
		return fmt.Errorf("validate process identity records: %w", err)
	}
	storedLedger, err := decodeLedger(filepath.Join(option.candidateRoot, "control", "cycle-ledger.json"))
	if err != nil {
		return err
	}
	derivedLedgerDigest, err := bench.DigestCycleLedger(derivedLedger)
	if err != nil {
		return err
	}
	storedLedgerDigest, err := bench.DigestCycleLedger(storedLedger)
	if err != nil {
		return err
	}
	if derivedLedgerDigest != storedLedgerDigest {
		return fmt.Errorf("process identity records do not reproduce the cycle ledger")
	}
	groups["process_identity"] = append(groups["process_identity"], recordReferences...)
	if err := appendExact("ratchet", "control/ratchet.json"); err != nil {
		return err
	}

	indexRoot := filepath.Join(filepath.Dir(option.publicationControlOutput), "publication-indexes")
	outputs := make(map[string][]byte, len(groups)+1)
	artifacts := make([]bench.PublicationArtifact, 0, len(groups))
	for kind, files := range groups {
		sort.Slice(files, func(left, right int) bool { return files[left].Locator < files[right].Locator })
		index := publicationArtifactIndex{SchemaVersion: publicationArtifactIndexSchemaVersion, Kind: kind, Files: files}
		if err := index.validate(); err != nil {
			return fmt.Errorf("validate %s publication index: %w", kind, err)
		}
		indexPath := filepath.Join(indexRoot, kind+".json")
		locator, relErr := filepath.Rel(option.candidateRoot, indexPath)
		if relErr != nil || locator == ".." || strings.HasPrefix(locator, ".."+string(filepath.Separator)) {
			return fmt.Errorf("publication index path escapes the candidate root")
		}
		body, encodeErr := jsonLine(index)
		if encodeErr != nil {
			return fmt.Errorf("encode %s publication index: %w", kind, encodeErr)
		}
		outputs[indexPath] = body
		artifacts = append(artifacts, bench.PublicationArtifact{Kind: kind, Reference: contentReferenceForBytes(body, filepath.ToSlash(locator))})
	}
	sort.Slice(artifacts, func(left, right int) bool { return artifacts[left].Kind < artifacts[right].Kind })
	control := bench.PublicationControl{SchemaVersion: bench.PublicationControlSchemaVersion, ImplementationCommit: option.implementationCommit, Artifacts: artifacts}
	if err := control.Validate(); err != nil {
		return err
	}
	controlBody, err := jsonLine(control)
	if err != nil {
		return fmt.Errorf("encode publication control: %w", err)
	}
	outputs[option.publicationControlOutput] = controlBody
	if err := writeMixedOutputs(outputs); err != nil {
		return err
	}
	indexedFiles := 0
	for _, files := range groups {
		indexedFiles += len(files)
	}
	fmt.Printf("publication_control indexes=%d files=%d commit=%s\n", len(control.Artifacts), indexedFiles, control.ImplementationCommit)
	return nil
}

func plannedCell(plan bench.CyclePlan, targetID string, engine bench.Engine) (bench.CycleCell, bool) {
	for _, cell := range plan.Cells {
		if cell.TargetID == targetID && cell.Engine == engine {
			return cell, true
		}
	}
	return bench.CycleCell{}, false
}

func validateObservationManifestBindings(catalog bench.Catalog, catalogDigest string, target bench.Target, manifest capture.CaptureManifest, observation bench.Observation) error {
	binaryDigest, err := catalogPin(catalog, manifest.Binary.Reference)
	if err != nil {
		return err
	}
	databaseDigest, err := catalogPin(catalog, manifest.Database.Reference)
	if err != nil {
		return err
	}
	environmentDigest, err := catalogPin(catalog, manifest.EnvironmentPinReference)
	if err != nil {
		return err
	}
	configDigest, err := catalogPin(catalog, manifest.ProfilePinReference)
	if err != nil {
		return err
	}
	if observation.CatalogRevision != catalog.Revision || observation.CatalogDigest != catalogDigest ||
		observation.TargetDigest != target.Digest || observation.SBOMDigest != target.SBOMDigest ||
		observation.EngineVersion != manifest.EngineVersion || observation.EngineBinaryDigest != binaryDigest ||
		observation.DatabaseBuild != manifest.Database.Build || observation.DatabaseDigest != databaseDigest ||
		observation.EnvironmentID != manifest.Environment.ID || observation.EnvironmentDigest != environmentDigest ||
		observation.ConfigDigest != configDigest {
		return fmt.Errorf("normalized observation does not bind its generated manifest and catalog")
	}
	if manifest.Capability == nil {
		if observation.CapabilityKind != "" || observation.CapabilityDigest != "" {
			return fmt.Errorf("normalized observation carries an unexpected capability identity")
		}
		return nil
	}
	if observation.CapabilityKind != bench.CapabilityKindOSVScannerSUSERPM || observation.CapabilityDigest != manifest.Capability.Statement.Digest {
		return fmt.Errorf("normalized observation does not bind its generated capability statement")
	}
	return nil
}

func distinctPlanTargets(plan bench.CyclePlan) []string {
	seen := make(map[string]struct{}, len(plan.Cells))
	for _, cell := range plan.Cells {
		seen[cell.TargetID] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for target := range seen {
		out = append(out, target)
	}
	sort.Strings(out)
	return out
}

func cleanupRunnerState(option options) error {
	if err := requirePaths(
		struct{ name, value string }{"raw retention root", option.rawRetentionRoot},
		struct{ name, value string }{"run id", option.runID},
		struct{ name, value string }{"run attempt", option.runAttempt},
		struct{ name, value string }{"cleanup output", option.cleanupOutput},
		struct{ name, value string }{"Docker binary", option.dockerBinary},
	); err != nil {
		return err
	}
	if !portableSegment(option.runID) || !portableSegment(option.runAttempt) {
		return fmt.Errorf("run id and attempt must be portable path segments")
	}
	root, err := filepath.Abs(option.rawRetentionRoot)
	if err != nil {
		return err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve protected retention root: %w", err)
	}
	rootInfo, err := os.Stat(root)
	if err != nil {
		return err
	}
	if !rootInfo.IsDir() {
		return fmt.Errorf("protected retention root is not a directory")
	}
	runRoot := filepath.Join(root, option.runID, option.runAttempt)
	relative, err := filepath.Rel(root, runRoot)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("raw run root escapes the protected retention root")
	}
	if err := os.RemoveAll(runRoot); err != nil {
		return fmt.Errorf("remove protected raw run root: %w", err)
	}
	if _, err := os.Stat(runRoot); !os.IsNotExist(err) {
		if err == nil {
			return fmt.Errorf("protected raw run root still exists")
		}
		return err
	}
	if err := cleanDocker(option.dockerBinary); err != nil {
		return err
	}
	containers, err := dockerItems(option.dockerBinary, "ps", "-aq")
	if err != nil {
		return err
	}
	images, err := dockerItems(option.dockerBinary, "image", "ls", "-aq")
	if err != nil {
		return err
	}
	volumes, err := dockerItems(option.dockerBinary, "volume", "ls", "-q")
	if err != nil {
		return err
	}
	receipt := cleanupReceipt{
		SchemaVersion: cleanupReceiptSchemaVersion, RawRunLocator: filepath.ToSlash(filepath.Join("runs", option.runID, option.runAttempt)),
		RawRunRootRemoved: true, DockerContainersRemaining: len(containers), DockerImagesRemaining: len(images), DockerVolumesRemaining: len(volumes), DockerBuildCachePruned: true,
	}
	if err := receipt.validate(); err != nil {
		return err
	}
	if err := writeJSONSet(map[string]any{option.cleanupOutput: receipt}); err != nil {
		return err
	}
	fmt.Printf("cleanup raw=%s containers=%d images=%d volumes=%d\n", receipt.RawRunLocator, len(containers), len(images), len(volumes))
	return nil
}

func cleanDocker(binary string) error {
	containers, err := dockerItems(binary, "ps", "-aq")
	if err != nil {
		return err
	}
	if len(containers) != 0 {
		arguments := append([]string{"rm", "-f"}, containers...)
		if _, err := runDocker(binary, arguments...); err != nil {
			return err
		}
	}
	volumes, err := dockerItems(binary, "volume", "ls", "-q")
	if err != nil {
		return err
	}
	if len(volumes) != 0 {
		arguments := append([]string{"volume", "rm", "-f"}, volumes...)
		if _, err := runDocker(binary, arguments...); err != nil {
			return err
		}
	}
	images, err := dockerItems(binary, "image", "ls", "-aq")
	if err != nil {
		return err
	}
	if len(images) != 0 {
		arguments := append([]string{"image", "rm", "-f"}, images...)
		if _, err := runDocker(binary, arguments...); err != nil {
			return err
		}
	}
	if _, err := runDocker(binary, "image", "prune", "-af"); err != nil {
		return err
	}
	if _, err := runDocker(binary, "builder", "prune", "-af"); err != nil {
		return err
	}
	return nil
}

func dockerItems(binary string, arguments ...string) ([]string, error) {
	output, err := runDocker(binary, arguments...)
	if err != nil {
		return nil, err
	}
	lines := strings.Fields(string(output))
	for _, line := range lines {
		if !portableDockerIdentifier(line) {
			return nil, fmt.Errorf("Docker returned an unsafe resource identifier")
		}
	}
	return lines, nil
}

func runDocker(binary string, arguments ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, binary, arguments...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("Docker %q timed out: %w", strings.Join(arguments, " "), ctx.Err())
		}
		return nil, fmt.Errorf("Docker %q failed: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func portableSegment(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

func portableDockerIdentifier(value string) bool {
	if value == "" || strings.ContainsAny(value, "\x00\r\n/\\") {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("_.:-", character)) {
			return false
		}
	}
	return true
}

func verifyPublicationIndex(candidateRoot, kind, path string) (publicationArtifactIndex, error) {
	var index publicationArtifactIndex
	if err := decodeJSONFile(path, &index); err != nil {
		return publicationArtifactIndex{}, err
	}
	if err := index.validate(); err != nil {
		return publicationArtifactIndex{}, err
	}
	if index.Kind != kind {
		return publicationArtifactIndex{}, fmt.Errorf("publication index kind %q does not match artifact kind %q", index.Kind, kind)
	}
	for _, expected := range index.Files {
		actual, err := contentReference(filepath.Join(candidateRoot, filepath.FromSlash(expected.Locator)), expected.Locator)
		if err != nil {
			return publicationArtifactIndex{}, fmt.Errorf("verify indexed publication artifact %q: %w", expected.Locator, err)
		}
		if actual != expected {
			return publicationArtifactIndex{}, fmt.Errorf("indexed publication artifact %q digest or size changed", expected.Locator)
		}
	}
	return index, nil
}

func materializeCandidateReceipt(option options) error {
	if err := requirePaths(
		struct{ name, value string }{"candidate root", option.candidateRoot},
		struct{ name, value string }{"implementation commit", option.implementationCommit},
		struct{ name, value string }{"cycle plan", option.planOutput},
		struct{ name, value string }{"cycle policy", option.cyclePolicy},
		struct{ name, value string }{"catalog", option.catalog},
		struct{ name, value string }{"oracle", option.oracle},
		struct{ name, value string }{"ratchet", option.ratchet},
		struct{ name, value string }{"ledger", option.ledger},
		struct{ name, value string }{"result", option.result},
		struct{ name, value string }{"publication manifest", option.publicationManifest},
		struct{ name, value string }{"cleanup receipt", option.cleanupReceipt},
		struct{ name, value string }{"receipt output", option.receiptOutput},
		struct{ name, value string }{"inventory output", option.inventoryOutput},
		struct{ name, value string }{"markdown output", option.markdownOutput},
		struct{ name, value string }{"artifact name", option.artifactName},
	); err != nil {
		return err
	}
	plan, err := decodePlan(option.planOutput)
	if err != nil {
		return err
	}
	var policy cyclePolicy
	if err := decodeJSONFile(option.cyclePolicy, &policy); err != nil {
		return err
	}
	if err := policy.validate(); err != nil {
		return err
	}
	if policy.Repetitions != plan.Repetitions {
		return fmt.Errorf("cycle policy and plan repetition counts differ")
	}
	catalog, err := decodeCatalog(option.catalog)
	if err != nil {
		return err
	}
	oracle, err := decodeOracle(option.oracle)
	if err != nil {
		return err
	}
	ratchet, err := decodeRatchet(option.ratchet)
	if err != nil {
		return err
	}
	ledger, err := decodeLedger(option.ledger)
	if err != nil {
		return err
	}
	if err := ledger.ValidateAgainstPlan(plan); err != nil {
		return err
	}
	result, err := decodeResult(option.result)
	if err != nil {
		return err
	}
	if result.Gate == nil || !result.Gate.Passed {
		return fmt.Errorf("candidate receipt requires a passing benchmark gate")
	}
	manifest, err := decodePublicationManifest(option.publicationManifest)
	if err != nil {
		return err
	}
	if err := manifest.ValidateAgainstPlan(plan); err != nil {
		return err
	}
	var cleanup cleanupReceipt
	if err := decodeJSONFile(option.cleanupReceipt, &cleanup); err != nil {
		return err
	}
	if err := cleanup.validate(); err != nil {
		return err
	}
	if manifest.ImplementationCommit != option.implementationCommit {
		return fmt.Errorf("publication manifest does not bind the supplied implementation commit")
	}
	if manifest.AccountableReview.ReviewedCommit != option.implementationCommit {
		return fmt.Errorf("accountable review does not bind the supplied implementation commit")
	}
	allowedFiles := make(map[string]struct{}, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		path := filepath.Join(option.candidateRoot, filepath.FromSlash(artifact.Reference.Locator))
		reference, referenceErr := contentReference(path, artifact.Reference.Locator)
		if referenceErr != nil {
			return fmt.Errorf("verify publication artifact %q: %w", artifact.Reference.Locator, referenceErr)
		}
		if reference != artifact.Reference {
			return fmt.Errorf("publication artifact %q digest or size changed", artifact.Reference.Locator)
		}
		allowedFiles[artifact.Reference.Locator] = struct{}{}
		if _, indexed := publicationIndexKinds[artifact.Kind]; indexed {
			expectedLocator := filepath.ToSlash(filepath.Join("control", "publication-indexes", artifact.Kind+".json"))
			if artifact.Reference.Locator != expectedLocator {
				return fmt.Errorf("publication artifact %q must use generated index locator %q", artifact.Reference.Locator, expectedLocator)
			}
			index, indexErr := verifyPublicationIndex(option.candidateRoot, artifact.Kind, path)
			if indexErr != nil {
				return indexErr
			}
			for _, indexedFile := range index.Files {
				allowedFiles[indexedFile.Locator] = struct{}{}
			}
		} else if strings.HasPrefix(artifact.Reference.Locator, "control/publication-indexes/") {
			return fmt.Errorf("publication artifact kind %q cannot use a control index locator", artifact.Kind)
		}
	}
	requiredSupplemental := []string{
		option.publicationManifest,
		option.cleanupReceipt,
		filepath.Join(option.candidateRoot, "candidate-evidence-summary.json"),
	}
	for _, path := range requiredSupplemental {
		relative, relErr := filepath.Rel(option.candidateRoot, path)
		if relErr != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("candidate supplemental path escapes the candidate root")
		}
		locator := filepath.ToSlash(relative)
		if _, referenceErr := contentReference(path, locator); referenceErr != nil {
			return fmt.Errorf("reference required candidate file %q: %w", locator, referenceErr)
		}
		allowedFiles[locator] = struct{}{}
	}
	excluded := map[string]struct{}{}
	for _, path := range []string{option.receiptOutput, option.inventoryOutput, option.markdownOutput} {
		relative, relErr := filepath.Rel(option.candidateRoot, path)
		if relErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("receipt outputs must be inside the candidate root")
		}
		excluded[filepath.ToSlash(relative)] = struct{}{}
	}
	files, err := fileList(option.candidateRoot, ".", func(locator string) bool {
		_, skip := excluded[locator]
		return !skip
	})
	if err != nil {
		return err
	}
	if err := validateCandidateInventory(files, allowedFiles); err != nil {
		return err
	}
	inventory := candidateFileInventory{SchemaVersion: candidateFileInventorySchemaVersion, Files: files}
	inventoryDigest, err := bench.DigestContentReferences(files)
	if err != nil {
		return err
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
	planDigest, err := bench.DigestCyclePlan(plan)
	if err != nil {
		return err
	}
	ledgerDigest, err := bench.DigestCycleLedger(ledger)
	if err != nil {
		return err
	}
	resultDigest, err := bench.DigestResult(result)
	if err != nil {
		return err
	}
	manifestDigest, err := bench.DigestPublicationManifest(manifest)
	if err != nil {
		return err
	}
	if result.CatalogDigest != catalogDigest || result.OracleDigest != oracleDigest || result.Gate.RatchetDigest != ratchetDigest || manifest.CyclePlanDigest != planDigest || manifest.CycleLedgerDigest != ledgerDigest {
		return fmt.Errorf("candidate result and publication identities do not form one bound cycle")
	}
	receipt := candidateReceipt{
		SchemaVersion: candidateReceiptSchemaVersion, CycleID: plan.CycleID, ImplementationCommit: option.implementationCommit,
		ArtifactName: option.artifactName, ArtifactRetention: policy.AcceptedArtifactRetentionDays, Counts: countsForPlan(plan),
		Digests:    candidateDigests{Catalog: catalogDigest, Oracle: oracleDigest, Ratchet: ratchetDigest, Plan: planDigest, Ledger: ledgerDigest, Result: resultDigest, PublicationManifest: manifestDigest},
		GatePassed: true, Cleanup: cleanup, InventoryDigest: inventoryDigest,
	}
	if err := receipt.validate(); err != nil {
		return err
	}
	markdown := renderReceiptMarkdown(receipt)
	inventoryBody, err := jsonLine(inventory)
	if err != nil {
		return fmt.Errorf("encode candidate inventory: %w", err)
	}
	receiptBody, err := jsonLine(receipt)
	if err != nil {
		return fmt.Errorf("encode candidate receipt: %w", err)
	}
	if err := writeMixedOutputs(map[string][]byte{
		option.inventoryOutput: inventoryBody, option.receiptOutput: receiptBody, option.markdownOutput: []byte(markdown),
	}); err != nil {
		return err
	}
	fmt.Printf("receipt inventory=%s files=%d artifact=%s\n", inventoryDigest, len(files), receipt.ArtifactName)
	return nil
}

func validateCandidateInventory(files []bench.ContentReference, allowed map[string]struct{}) error {
	for _, file := range files {
		if _, exists := allowed[file.Locator]; !exists {
			return fmt.Errorf("candidate inventory contains unexpected file %q", file.Locator)
		}
	}
	return rejectRawCandidatePaths(files)
}

func rejectRawCandidatePaths(files []bench.ContentReference) error {
	for _, file := range files {
		lower := strings.ToLower(file.Locator)
		segments := strings.Split(lower, "/")
		for _, segment := range segments {
			if segment == "raw" || segment == "stdout" || segment == "stderr" || strings.HasPrefix(segment, "raw-") || strings.HasPrefix(segment, "raw_") {
				return fmt.Errorf("candidate inventory contains raw scanner material path %q", file.Locator)
			}
		}
	}
	return nil
}

func jsonLine(value any) ([]byte, error) {
	body, err := bench.CanonicalJSON(value)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func writeMixedOutputs(values map[string][]byte) error {
	paths := make([]string, 0, len(values))
	for path := range values {
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("output path is required")
		}
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("output %s already exists", path)
		} else if !os.IsNotExist(err) {
			return err
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	temporary := make(map[string]string, len(paths))
	cleanup := func() {
		for _, path := range temporary {
			_ = os.Remove(path)
		}
	}
	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			cleanup()
			return err
		}
		file, err := os.CreateTemp(filepath.Dir(path), ".sca-delivery-*.tmp")
		if err != nil {
			cleanup()
			return err
		}
		temporary[path] = file.Name()
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			cleanup()
			return err
		}
		if _, err := file.Write(values[path]); err != nil {
			_ = file.Close()
			cleanup()
			return err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			cleanup()
			return err
		}
		if err := file.Close(); err != nil {
			cleanup()
			return err
		}
	}
	committed := make([]string, 0, len(paths))
	for _, path := range paths {
		if err := os.Rename(temporary[path], path); err != nil {
			for _, committedPath := range committed {
				_ = os.Remove(committedPath)
			}
			cleanup()
			return err
		}
		delete(temporary, path)
		committed = append(committed, path)
	}
	return nil
}

func renderReceiptMarkdown(receipt candidateReceipt) string {
	var builder strings.Builder
	builder.WriteString("## Trusted SCA accuracy cycle\n\n")
	fmt.Fprintf(&builder, "- Exact implementation commit: `%s`\n", receipt.ImplementationCommit)
	fmt.Fprintf(&builder, "- Cycle: `%s`\n", receipt.CycleID)
	fmt.Fprintf(&builder, "- Accepted artifact: `%s` (%d-day retention)\n", receipt.ArtifactName, receipt.ArtifactRetention)
	fmt.Fprintf(&builder, "- Matrix: %d repetitions, %d cells each, %d accepted slots, %d scanner dispatches, %d explicit unsupported records.\n", receipt.Counts.Repetitions, receipt.Counts.Cells, receipt.Counts.PlannedSlots, receipt.Counts.ScannerDispatches, receipt.Counts.Unsupported)
	builder.WriteString("- Ratchet gate: passed. Unknown, unsupported, and incomplete states remain separate from scored covered relations.\n")
	builder.WriteString("- Cleanup: protected raw run data removed; Docker containers, images, volumes, and build cache cleared on the ephemeral runner.\n")
	fmt.Fprintf(&builder, "- Catalog: `%s`\n", receipt.Digests.Catalog)
	fmt.Fprintf(&builder, "- Oracle: `%s`\n", receipt.Digests.Oracle)
	fmt.Fprintf(&builder, "- Ratchet: `%s`\n", receipt.Digests.Ratchet)
	fmt.Fprintf(&builder, "- Result: `%s`\n", receipt.Digests.Result)
	fmt.Fprintf(&builder, "- Publication manifest: `%s`\n", receipt.Digests.PublicationManifest)
	fmt.Fprintf(&builder, "- Sanitized file inventory: `%s`\n", receipt.InventoryDigest)
	return builder.String()
}
