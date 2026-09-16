package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	capture "github.com/KKloudTarus/synapse-ce/internal/infrastructure/scabench"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func materializeSourceFreeze(option options) error {
	if err := requirePaths(
		struct{ name, value string }{"repository root", option.repositoryRoot},
		struct{ name, value string }{"source freeze template", option.sourceFreezeTemplate},
		struct{ name, value string }{"source plan template", option.sourcePlanTemplate},
		struct{ name, value string }{"source freeze output", option.sourceFreezeOutput},
		struct{ name, value string }{"source plan output", option.sourcePlanOutput},
	); err != nil {
		return err
	}
	var freezeTemplate sourceFreezeTemplate
	if err := decodeJSONFile(option.sourceFreezeTemplate, &freezeTemplate); err != nil {
		return err
	}
	if err := freezeTemplate.validate(); err != nil {
		return err
	}
	var planTemplate sourcePlanTemplate
	if err := decodeJSONFile(option.sourcePlanTemplate, &planTemplate); err != nil {
		return err
	}
	if err := planTemplate.validate(); err != nil {
		return err
	}
	if planTemplate.CycleID != freezeTemplate.CycleID {
		return fmt.Errorf("source templates belong to different cycles")
	}
	assets := make([]bench.ContentReference, 0, len(freezeTemplate.Assets))
	assetLocators := make(map[string]struct{}, len(freezeTemplate.Assets))
	for _, asset := range freezeTemplate.Assets {
		path, err := resolveRepositoryAsset(option.repositoryRoot, asset.Locator)
		if err != nil {
			return err
		}
		reference, err := contentReference(path, asset.Locator)
		if err != nil {
			return fmt.Errorf("hash source asset %q: %w", asset.Locator, err)
		}
		assets = append(assets, reference)
		assetLocators[asset.Locator] = struct{}{}
	}
	sort.Slice(assets, func(left, right int) bool { return assets[left].Locator < assets[right].Locator })
	for _, target := range planTemplate.Targets {
		if _, exists := assetLocators[target.SourceAssetLocator]; !exists {
			return fmt.Errorf("source plan target %q selects an asset absent from the freeze template", target.TargetID)
		}
	}
	contentDigest, err := bench.DigestContentReferences(assets)
	if err != nil {
		return err
	}
	freeze := bench.SourceFreeze{SchemaVersion: bench.SourceFreezeSchemaVersion, CycleID: freezeTemplate.CycleID, Assets: assets, ContentDigest: contentDigest}
	freezeDigest, err := bench.DigestSourceFreeze(freeze)
	if err != nil {
		return err
	}
	plan := bench.SourceEvidencePlan{SchemaVersion: bench.SourceEvidencePlanSchemaVersion, CycleID: planTemplate.CycleID, SourceFreezeDigest: freezeDigest, Targets: planTemplate.Targets}
	if err := plan.Validate(); err != nil {
		return err
	}
	if _, err := bench.DigestSourceEvidencePlan(plan); err != nil {
		return err
	}
	if err := writeJSONSet(map[string]any{option.sourceFreezeOutput: freeze, option.sourcePlanOutput: plan}); err != nil {
		return err
	}
	fmt.Printf("source_freeze=%s assets=%d targets=%d\n", freezeDigest, len(freeze.Assets), len(plan.Targets))
	return nil
}

func materializeBinaryPin(option options) error {
	if err := requirePaths(
		struct{ name, value string }{"catalog", option.catalog},
		struct{ name, value string }{"ratchet", option.ratchet},
		struct{ name, value string }{"binary reference", option.binaryReference},
		struct{ name, value string }{"binary path", option.binaryPath},
		struct{ name, value string }{"engine", option.engine},
		struct{ name, value string }{"catalog output", option.catalogOutput},
		struct{ name, value string }{"ratchet output", option.ratchetOutput},
	); err != nil {
		return err
	}
	if filepath.Clean(option.catalogOutput) == filepath.Clean(option.ratchetOutput) {
		return fmt.Errorf("catalog and ratchet outputs must be distinct")
	}

	engine := bench.Engine(strings.TrimSpace(option.engine))
	validEngine := false
	for _, candidate := range bench.Engines() {
		if candidate == engine {
			validEngine = true
			break
		}
	}
	if !validEngine {
		return fmt.Errorf("unsupported engine %q", option.engine)
	}

	catalog, err := decodeCatalog(option.catalog)
	if err != nil {
		return err
	}
	ratchet, err := decodeRatchet(option.ratchet)
	if err != nil {
		return err
	}
	oldCatalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		return err
	}
	if ratchet.CatalogRevision != catalog.Revision || ratchet.CatalogDigest != oldCatalogDigest {
		return fmt.Errorf("ratchet does not bind the supplied catalog")
	}

	capabilityFloors := 0
	for _, floor := range ratchet.Floors {
		if floor.Expected.CapabilityDigest != "" {
			capabilityFloors++
		}
	}
	var freeze bench.SourceFreeze
	var oldCapabilityDigests map[string]string
	if capabilityFloors > 0 {
		if err := requirePaths(
			struct{ name, value string }{"repository root", option.repositoryRoot},
			struct{ name, value string }{"source freeze", option.sourceFreezeOutput},
			struct{ name, value string }{"manifest template directory", option.manifestTemplateDir},
		); err != nil {
			return err
		}
		freeze, err = decodeSourceFreeze(option.sourceFreezeOutput)
		if err != nil {
			return err
		}
		oldCapabilityDigests, err = capabilityDigestsForCatalog(option.repositoryRoot, option.manifestTemplateDir, freeze, catalog, oldCatalogDigest)
		if err != nil {
			return err
		}
		if len(oldCapabilityDigests) != capabilityFloors {
			return fmt.Errorf("capability template count %d does not match ratchet floor count %d", len(oldCapabilityDigests), capabilityFloors)
		}
	}

	reference := strings.TrimSpace(option.binaryReference)
	pinIndex := -1
	for index := range catalog.Pins {
		if catalog.Pins[index].Reference != reference {
			continue
		}
		if pinIndex >= 0 {
			return fmt.Errorf("catalog contains duplicate binary reference %q", reference)
		}
		pinIndex = index
	}
	if pinIndex < 0 {
		return fmt.Errorf("catalog omits binary reference %q", reference)
	}
	oldBinaryDigest := catalog.Pins[pinIndex].Digest
	binary, err := contentReference(option.binaryPath, "benchmark-binary")
	if err != nil {
		return fmt.Errorf("hash benchmark binary: %w", err)
	}
	catalog.Pins[pinIndex].Digest = binary.Digest
	if err := catalog.Validate(); err != nil {
		return err
	}
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		return err
	}

	var newCapabilityDigests map[string]string
	if capabilityFloors > 0 {
		newCapabilityDigests, err = capabilityDigestsForCatalog(option.repositoryRoot, option.manifestTemplateDir, freeze, catalog, catalogDigest)
		if err != nil {
			return err
		}
		if len(newCapabilityDigests) != capabilityFloors {
			return fmt.Errorf("generated capability count %d does not match ratchet floor count %d", len(newCapabilityDigests), capabilityFloors)
		}
	}

	updatedFloors := 0
	for index := range ratchet.Floors {
		floor := &ratchet.Floors[index]
		if floor.Expected.Engine != engine {
			continue
		}
		if floor.Expected.EngineBinaryDigest != oldBinaryDigest {
			return fmt.Errorf("ratchet floor for %s and %s does not bind catalog binary %q", floor.Expected.TargetID, engine, reference)
		}
		floor.Expected.EngineBinaryDigest = binary.Digest
		updatedFloors++
	}
	if updatedFloors == 0 {
		return fmt.Errorf("ratchet has no floors for engine %q", engine)
	}

	updatedCapabilities := 0
	for index := range ratchet.Floors {
		floor := &ratchet.Floors[index]
		if floor.Expected.CapabilityDigest == "" {
			continue
		}
		key := cellKey(floor.Expected.TargetID, floor.Expected.Engine)
		oldDigest, oldExists := oldCapabilityDigests[key]
		newDigest, newExists := newCapabilityDigests[key]
		if !oldExists || !newExists {
			return fmt.Errorf("ratchet capability floor %s has no matching capability template", key)
		}
		if floor.Expected.CapabilityKind != bench.CapabilityKindOSVScannerSUSERPM || floor.Expected.CapabilityDigest != oldDigest {
			return fmt.Errorf("ratchet floor %s does not bind the generated capability statement", key)
		}
		floor.Expected.CapabilityDigest = newDigest
		updatedCapabilities++
	}
	if updatedCapabilities != capabilityFloors {
		return fmt.Errorf("updated %d capability floors, want %d", updatedCapabilities, capabilityFloors)
	}

	ratchet.CatalogDigest = catalogDigest
	if err := ratchet.Validate(); err != nil {
		return err
	}
	ratchetDigest, err := bench.DigestRatchet(ratchet)
	if err != nil {
		return err
	}
	if err := writeJSONSet(map[string]any{option.catalogOutput: catalog, option.ratchetOutput: ratchet}); err != nil {
		return err
	}
	fmt.Printf("binary=%s catalog=%s ratchet=%s floors=%d capabilities=%d reference=%s engine=%s\n", binary.Digest, catalogDigest, ratchetDigest, updatedFloors, updatedCapabilities, reference, engine)
	return nil
}

func capabilityDigestsForCatalog(repositoryRoot, manifestTemplateDir string, freeze bench.SourceFreeze, catalog bench.Catalog, catalogDigest string) (map[string]string, error) {
	entries, err := os.ReadDir(manifestTemplateDir)
	if err != nil {
		return nil, err
	}
	digests := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		var template captureManifestTemplate
		path := filepath.Join(manifestTemplateDir, entry.Name())
		if err := decodeJSONFile(path, &template); err != nil {
			return nil, err
		}
		if err := template.validate(); err != nil {
			return nil, fmt.Errorf("validate %s: %w", entry.Name(), err)
		}
		if template.Capability == nil {
			continue
		}
		target, exists := targetByID(catalog, template.TargetID)
		if !exists {
			return nil, fmt.Errorf("capability template references unknown target %q", template.TargetID)
		}
		sources, err := capabilityArtifactsFromFreeze(repositoryRoot, freeze, template.Capability.Sources)
		if err != nil {
			return nil, err
		}
		_, digest, err := buildCapabilityStatement(catalog, catalogDigest, target, template, sources)
		if err != nil {
			return nil, err
		}
		key := cellKey(template.TargetID, template.Engine)
		if _, exists := digests[key]; exists {
			return nil, fmt.Errorf("duplicate capability template for %s", key)
		}
		digests[key] = digest
	}
	return digests, nil
}

func materializeManifestSet(option options) error {
	if err := requirePaths(
		struct{ name, value string }{"repository root", option.repositoryRoot},
		struct{ name, value string }{"source freeze", option.sourceFreezeOutput},
		struct{ name, value string }{"catalog", option.catalog},
		struct{ name, value string }{"oracle", option.oracle},
		struct{ name, value string }{"manifest template directory", option.manifestTemplateDir},
		struct{ name, value string }{"manifest output directory", option.manifestOutputDir},
		struct{ name, value string }{"capability output directory", option.capabilityOutputDir},
		struct{ name, value string }{"SBOM root", option.sbomRoot},
	); err != nil {
		return err
	}
	catalog, err := decodeCatalog(option.catalog)
	if err != nil {
		return err
	}
	oracle, err := decodeOracle(option.oracle)
	if err != nil {
		return err
	}
	freeze, err := decodeSourceFreeze(option.sourceFreezeOutput)
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
	if oracle.CatalogRevision != catalog.Revision {
		return fmt.Errorf("oracle and catalog revisions differ")
	}
	states, err := expectedCellStates(catalog, oracle)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(option.manifestTemplateDir)
	if err != nil {
		return err
	}
	templates := make(map[string]captureManifestTemplate, len(states))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(option.manifestTemplateDir, entry.Name())
		var template captureManifestTemplate
		if err := decodeJSONFile(path, &template); err != nil {
			return err
		}
		if err := template.validate(); err != nil {
			return fmt.Errorf("validate %s: %w", entry.Name(), err)
		}
		key := cellKey(template.TargetID, template.Engine)
		if _, exists := templates[key]; exists {
			return fmt.Errorf("duplicate capture manifest template for %s", key)
		}
		templates[key] = template
	}
	if len(templates) != len(states) {
		return fmt.Errorf("capture manifest template count %d does not match derived matrix count %d", len(templates), len(states))
	}

	values := make(map[string]any, len(states)+1)
	capabilityPaths := make(map[string]struct{})
	manifests := make(map[string]capture.CaptureManifest, len(states))
	for key, state := range states {
		template, exists := templates[key]
		if !exists {
			return fmt.Errorf("missing capture manifest template for %s", key)
		}
		target, exists := targetByID(catalog, template.TargetID)
		if !exists {
			return fmt.Errorf("capture manifest template references unknown target %q", template.TargetID)
		}
		manifest := capture.CaptureManifest{
			SchemaVersion:           capture.CaptureManifestSchemaVersion,
			CatalogRevision:         catalog.Revision,
			CatalogDigest:           catalogDigest,
			TargetID:                template.TargetID,
			SBOMPath:                filepath.Join(option.sbomRoot, template.TargetID+".cdx.json"),
			Engine:                  template.Engine,
			EngineVersion:           template.EngineVersion,
			Binary:                  template.Binary,
			Database:                template.Database,
			Environment:             template.Environment,
			EnvironmentAttestation:  template.EnvironmentAttestation,
			EnvironmentPinReference: template.EnvironmentPinReference,
			ProfilePinReference:     template.ProfilePinReference,
			Limits:                  template.Limits,
		}
		if state == bench.ObservationUnsupported {
			if template.Capability == nil {
				return fmt.Errorf("unsupported cell %s requires a capability template", key)
			}
			sources, sourceErr := capabilityArtifactsFromFreeze(option.repositoryRoot, freeze, template.Capability.Sources)
			if sourceErr != nil {
				return sourceErr
			}
			statement, statementDigest, buildErr := buildCapabilityStatement(catalog, catalogDigest, target, template, sources)
			if buildErr != nil {
				return buildErr
			}
			statementPath := filepath.Join(option.capabilityOutputDir, template.TargetID+"--"+string(template.Engine)+".json")
			manifest.Capability = &capture.CapabilityManifest{
				Statement: capture.CapabilityArtifact{Reference: template.Capability.StatementReference, Path: statementPath, Digest: statementDigest},
				Sources:   sources,
			}
			values[statementPath] = statement
			capabilityPaths[statementPath] = struct{}{}
		} else if template.Capability != nil {
			return fmt.Errorf("dispatched cell %s must not carry a zero-dispatch capability template", key)
		}
		if err := manifest.Validate(); err != nil {
			return fmt.Errorf("validate generated manifest %s: %w", key, err)
		}
		outputPath := filepath.Join(option.manifestOutputDir, template.TargetID+"--"+string(template.Engine)+".json")
		values[outputPath] = manifest
		manifests[key] = manifest
	}
	if option.ratchet != "" {
		ratchet, decodeErr := decodeRatchet(option.ratchet)
		if decodeErr != nil {
			return decodeErr
		}
		if err := validateRatchetAgainstMaterializedInputs(catalog, catalogDigest, oracleDigest, states, manifests, ratchet); err != nil {
			return err
		}
	}
	outputs := make(map[string][]byte, len(values))
	for path, value := range values {
		encoded, encodeErr := bench.CanonicalJSON(value)
		if encodeErr != nil {
			return encodeErr
		}
		if _, capability := capabilityPaths[path]; !capability {
			encoded = append(encoded, '\n')
		}
		outputs[path] = encoded
	}
	if err := writeMixedOutputs(outputs); err != nil {
		return err
	}
	fmt.Printf("catalog=%s oracle=%s manifests=%d capabilities=%d\n", catalogDigest, oracleDigest, len(manifests), len(values)-len(manifests))
	return nil
}

func capabilityArtifactsFromFreeze(repositoryRoot string, freeze bench.SourceFreeze, templates []capabilitySourceTemplate) ([]capture.CapabilityArtifact, error) {
	root, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return nil, err
	}
	frozen := make(map[string]bench.ContentReference, len(freeze.Assets))
	for _, asset := range freeze.Assets {
		frozen[asset.Locator] = asset
	}
	artifacts := make([]capture.CapabilityArtifact, 0, len(templates))
	seen := make(map[string]struct{}, len(templates))
	for _, template := range templates {
		if _, exists := seen[template.Locator]; exists {
			return nil, fmt.Errorf("capability source locator %q is duplicated", template.Locator)
		}
		seen[template.Locator] = struct{}{}
		reference, exists := frozen[template.Locator]
		if !exists || reference.Digest != template.Digest {
			return nil, fmt.Errorf("capability source %q does not match the source freeze", template.Locator)
		}
		path := filepath.Join(root, filepath.FromSlash(template.Locator))
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("capability source locator %q escapes the repository root", template.Locator)
		}
		artifacts = append(artifacts, capture.CapabilityArtifact{Reference: template.Reference, Path: path, Digest: template.Digest})
	}
	return artifacts, nil
}

func buildCapabilityStatement(catalog bench.Catalog, catalogDigest string, target bench.Target, template captureManifestTemplate, artifacts []capture.CapabilityArtifact) (capture.CapabilityStatement, string, error) {
	binaryDigest, err := catalogPin(catalog, template.Binary.Reference)
	if err != nil {
		return capture.CapabilityStatement{}, "", err
	}
	databaseDigest, err := catalogPin(catalog, template.Database.Reference)
	if err != nil {
		return capture.CapabilityStatement{}, "", err
	}
	environmentDigest, err := catalogPin(catalog, template.EnvironmentPinReference)
	if err != nil {
		return capture.CapabilityStatement{}, "", err
	}
	configDigest, err := catalogPin(catalog, template.ProfilePinReference)
	if err != nil {
		return capture.CapabilityStatement{}, "", err
	}
	if template.Capability == nil {
		return capture.CapabilityStatement{}, "", fmt.Errorf("capability template is required")
	}
	components := append([]bench.Component(nil), target.Components...)
	componentKeys := make(map[string]string, len(components))
	for _, component := range components {
		key, keyErr := bench.BenchmarkKey(component, "placeholder")
		if keyErr != nil {
			return capture.CapabilityStatement{}, "", keyErr
		}
		componentKeys[component.PURL+"\x00"+component.Version] = key.Ecosystem + "\x00" + key.Package + "\x00" + key.Version
	}
	sort.Slice(components, func(left, right int) bool {
		return componentKeys[components[left].PURL+"\x00"+components[left].Version] < componentKeys[components[right].PURL+"\x00"+components[right].Version]
	})
	sources := make([]capture.CapabilityStatementSource, 0, len(artifacts))
	for _, source := range artifacts {
		sources = append(sources, capture.CapabilityStatementSource{Reference: source.Reference, Digest: source.Digest})
	}
	statement := capture.CapabilityStatement{
		SchemaVersion:        capture.CapabilityStatementSchemaVersion,
		Kind:                 bench.CapabilityKindOSVScannerSUSERPM,
		DecisionRuleRevision: capture.CapabilityDecisionRuleRevision,
		Scope:                capture.CapabilityScopeSameSBOMOSPackageMatching,
		CatalogRevision:      catalog.Revision,
		CatalogDigest:        catalogDigest,
		TargetID:             target.ID,
		TargetDigest:         target.Digest,
		SBOMDigest:           target.SBOMDigest,
		Engine:               template.Engine,
		EngineVersion:        template.EngineVersion,
		EngineBinaryDigest:   binaryDigest,
		DatabaseBuild:        template.Database.Build,
		DatabaseDigest:       databaseDigest,
		EnvironmentID:        template.Environment.ID,
		EnvironmentDigest:    environmentDigest,
		ConfigDigest:         configDigest,
		Components:           components,
		Sources:              sources,
	}
	if err := statement.Validate(); err != nil {
		return capture.CapabilityStatement{}, "", err
	}
	encoded, err := bench.CanonicalJSON(statement)
	if err != nil {
		return capture.CapabilityStatement{}, "", err
	}
	return statement, bench.SHA256Digest(encoded), nil
}

func expectedCellStates(catalog bench.Catalog, oracle bench.Oracle) (map[string]bench.ObservationState, error) {
	knownTargets := make(map[string]bench.Target, len(catalog.Targets))
	for _, target := range catalog.Targets {
		knownTargets[target.ID] = target
	}
	cases := make(map[string][]bench.OracleCase, len(catalog.Targets))
	for _, item := range oracle.Cases {
		target, exists := knownTargets[item.TargetID]
		if !exists {
			return nil, fmt.Errorf("oracle case %q references unknown target %q", item.ID, item.TargetID)
		}
		componentFound := false
		for _, component := range target.Components {
			if component.PURL == item.Component.PURL && component.Version == item.Component.Version {
				componentFound = true
				break
			}
		}
		if !componentFound {
			return nil, fmt.Errorf("oracle case %q references a component absent from its target", item.ID)
		}
		cases[item.TargetID] = append(cases[item.TargetID], item)
	}
	states := make(map[string]bench.ObservationState, len(catalog.Targets)*len(bench.Engines()))
	for _, target := range catalog.Targets {
		targetCases := cases[target.ID]
		if len(targetCases) == 0 {
			return nil, fmt.Errorf("target %q has no oracle cases", target.ID)
		}
		for _, engine := range bench.Engines() {
			allUnsupported := true
			for _, item := range targetCases {
				coverage, exists := item.ExpectedCoverage[engine]
				if !exists {
					return nil, fmt.Errorf("oracle case %q omits expected coverage for %q", item.ID, engine)
				}
				if coverage != bench.CoverageUnsupported {
					allUnsupported = false
				}
			}
			state := bench.ObservationComplete
			if allUnsupported {
				state = bench.ObservationUnsupported
			}
			states[cellKey(target.ID, engine)] = state
		}
	}
	return states, nil
}

func materializeRatchet(option options) error {
	if err := requirePaths(
		struct{ name, value string }{"baseline ratchet", option.baselineRatchet},
		struct{ name, value string }{"baseline result", option.baselineResult},
		struct{ name, value string }{"ratchet output", option.ratchetOutput},
	); err != nil {
		return err
	}
	baseline, err := decodeRatchet(option.baselineRatchet)
	if err != nil {
		return err
	}
	result, err := decodeResult(option.baselineResult)
	if err != nil {
		return err
	}
	if result.Gate == nil || !result.Gate.Passed {
		return fmt.Errorf("baseline result must carry a passing gate")
	}
	baselineDigest, err := bench.DigestRatchet(baseline)
	if err != nil {
		return err
	}
	if result.Gate.RatchetDigest != baselineDigest || result.CatalogRevision != baseline.CatalogRevision || result.CatalogDigest != baseline.CatalogDigest || result.OracleDigest != baseline.OracleDigest {
		return fmt.Errorf("baseline result does not bind the supplied baseline ratchet and corpus")
	}
	if len(result.RunMetrics) != len(baseline.Floors) {
		return fmt.Errorf("baseline result and ratchet do not cover the same logical runs")
	}
	metrics := make(map[string]bench.RunMetric, len(result.RunMetrics))
	for _, metric := range result.RunMetrics {
		key := cellKey(metric.Run.TargetID, metric.Run.Engine)
		if _, exists := metrics[key]; exists {
			return fmt.Errorf("baseline result contains duplicate logical run %s", key)
		}
		metrics[key] = metric
	}
	strict := bench.Ratchet{SchemaVersion: baseline.SchemaVersion, CatalogRevision: baseline.CatalogRevision, CatalogDigest: baseline.CatalogDigest, OracleDigest: baseline.OracleDigest, Floors: make([]bench.RatchetFloor, 0, len(baseline.Floors))}
	for _, floor := range baseline.Floors {
		metric, exists := metrics[cellKey(floor.Expected.TargetID, floor.Expected.Engine)]
		if !exists {
			return fmt.Errorf("baseline result omits a ratcheted logical run")
		}
		strictFloor, floorErr := nonRegressionFloor(floor, metric)
		if floorErr != nil {
			return floorErr
		}
		strict.Floors = append(strict.Floors, strictFloor)
	}
	if err := strict.Validate(); err != nil {
		return err
	}
	gated, err := bench.ApplyRatchet(result, strict)
	if err != nil {
		return err
	}
	if gated.Gate == nil || !gated.Gate.Passed {
		return fmt.Errorf("strict ratchet does not accept its source baseline result")
	}
	if err := writeJSONSet(map[string]any{option.ratchetOutput: strict}); err != nil {
		return err
	}
	digest, err := bench.DigestRatchet(strict)
	if err != nil {
		return err
	}
	fmt.Printf("ratchet=%s floors=%d source_result=%s\n", digest, len(strict.Floors), result.ID)
	return nil
}

func nonRegressionFloor(baseline bench.RatchetFloor, metric bench.RunMetric) (bench.RatchetFloor, error) {
	zero := 0
	zeroMetric := 0.0
	if baseline.Mode == bench.FloorGateModeUnsupportedOnly {
		unsupported := metric.Metrics.Unsupported
		if metric.Metrics.Covered != 0 || metric.Metrics.Unknown != 0 || metric.Metrics.Incomplete != 0 || metric.Metrics.FalsePositives != 0 || metric.Metrics.FalseNegatives != 0 || unsupported == 0 {
			return bench.RatchetFloor{}, fmt.Errorf("unsupported-only baseline run has incompatible metrics")
		}
		return bench.RatchetFloor{Expected: baseline.Expected, Mode: bench.FloorGateModeUnsupportedOnly, MinimumCovered: &zero, MinimumAffectedRelations: &zero, MinimumNegativeRelations: &zero, MinimumPrecision: &zeroMetric, MinimumRecall: &zeroMetric, MaximumFalsePositives: &zero, MaximumFalseNegatives: &zero, MaximumUnknown: &zero, MaximumIncomplete: &zero, MaximumUnsupported: &unsupported}, nil
	}
	if metric.Metrics.Precision == nil && metric.Metrics.TruePositives+metric.Metrics.FalsePositives != 0 {
		return bench.RatchetFloor{}, fmt.Errorf("accuracy baseline has inconsistent undefined precision")
	}
	if metric.Metrics.Recall == nil {
		return bench.RatchetFloor{}, fmt.Errorf("accuracy baseline has undefined recall")
	}
	precision := 0.0
	allowUndefinedPrecision := metric.Metrics.Precision == nil
	if metric.Metrics.Precision != nil {
		precision = *metric.Metrics.Precision
	}
	recall := *metric.Metrics.Recall
	covered := metric.Metrics.Covered
	affected := metric.Metrics.AffectedRelations
	negative := metric.Metrics.NegativeRelations
	falsePositives := metric.Metrics.FalsePositives
	falseNegatives := metric.Metrics.FalseNegatives
	unknown := metric.Metrics.Unknown
	incomplete := metric.Metrics.Incomplete
	unsupported := metric.Metrics.Unsupported
	return bench.RatchetFloor{Expected: baseline.Expected, Mode: bench.FloorGateModeAccuracy, AllowUndefinedPrecision: allowUndefinedPrecision, MinimumCovered: &covered, MinimumAffectedRelations: &affected, MinimumNegativeRelations: &negative, MinimumPrecision: &precision, MinimumRecall: &recall, MaximumFalsePositives: &falsePositives, MaximumFalseNegatives: &falseNegatives, MaximumUnknown: &unknown, MaximumIncomplete: &incomplete, MaximumUnsupported: &unsupported}, nil
}

func materializeAccountableReview(option options) error {
	if err := requirePaths(
		struct{ name, value string }{"repository root", option.repositoryRoot},
		struct{ name, value string }{"review capture locator", option.reviewCaptureLocator},
		struct{ name, value string }{"review capture output", option.reviewCaptureOutput},
		struct{ name, value string }{"decision capture locator", option.decisionCaptureLocator},
		struct{ name, value string }{"decision capture output", option.decisionCaptureOutput},
		struct{ name, value string }{"implementation commit", option.implementationCommit},
		struct{ name, value string }{"adjudication", option.adjudication},
		struct{ name, value string }{"oracle", option.oracle},
		struct{ name, value string }{"review output", option.reviewOutput},
	); err != nil {
		return err
	}
	if !validCommitSHA(option.implementationCommit) {
		return fmt.Errorf("implementation commit must be a full commit SHA")
	}
	adjudication, err := decodeAdjudication(option.adjudication)
	if err != nil {
		return err
	}
	oracle, err := decodeOracle(option.oracle)
	if err != nil {
		return err
	}
	reviewCapturePath, err := resolveRepositoryAsset(option.repositoryRoot, option.reviewCaptureLocator)
	if err != nil {
		return err
	}
	reviewFile, err := os.Open(reviewCapturePath)
	if err != nil {
		return err
	}
	reviewCapture, err := bench.DecodeGitHubReviewCapture(reviewFile)
	_ = reviewFile.Close()
	if err != nil {
		return err
	}
	decisionCapturePath, err := resolveRepositoryAsset(option.repositoryRoot, option.decisionCaptureLocator)
	if err != nil {
		return err
	}
	decisionFile, err := os.Open(decisionCapturePath)
	if err != nil {
		return err
	}
	decisionCapture, err := bench.DecodeGitHubReviewDispositionCapture(decisionFile)
	_ = decisionFile.Close()
	if err != nil {
		return err
	}
	reviewCaptureReference, err := contentReference(reviewCapturePath, option.reviewCaptureLocator)
	if err != nil {
		return err
	}
	reviewCaptureBody, err := os.ReadFile(reviewCapturePath)
	if err != nil {
		return err
	}
	copiedReviewReference := contentReferenceForBytes(reviewCaptureBody, option.reviewCaptureLocator)
	if copiedReviewReference.Digest != reviewCaptureReference.Digest || copiedReviewReference.Size != reviewCaptureReference.Size {
		return fmt.Errorf("github review capture changed during materialization")
	}
	decisionCaptureReference, err := contentReference(decisionCapturePath, option.decisionCaptureLocator)
	if err != nil {
		return err
	}
	decisionCaptureBody, err := os.ReadFile(decisionCapturePath)
	if err != nil {
		return err
	}
	copiedDecisionReference := contentReferenceForBytes(decisionCaptureBody, option.decisionCaptureLocator)
	if copiedDecisionReference.Digest != decisionCaptureReference.Digest || copiedDecisionReference.Size != decisionCaptureReference.Size {
		return fmt.Errorf("github review disposition capture changed during materialization")
	}
	adjudicationDigest, err := bench.DigestAdjudicationRecord(adjudication)
	if err != nil {
		return err
	}
	oracleDigest, err := bench.DigestOracle(oracle)
	if err != nil {
		return err
	}
	review := bench.AccountableReview{
		SchemaVersion:             bench.AccountableReviewSchemaVersion,
		CycleID:                   adjudication.CycleID,
		AdjudicationDigest:        adjudicationDigest,
		FinalOracleDigest:         oracleDigest,
		ReviewerIdentity:          "github:" + reviewCapture.Login,
		SubmittedAt:               reviewCapture.SubmittedAt,
		ReviewedCommit:            reviewCapture.CommitID,
		GitHubReviewID:            reviewCapture.ID,
		GitHubReviewURL:           reviewCapture.URL,
		ReviewCapture:             reviewCaptureReference,
		DecisionAuthorityIdentity: "github:" + decisionCapture.Login,
		DecisionSubmittedAt:       decisionCapture.CreatedAt,
		ImplementationCommit:      option.implementationCommit,
		GitHubDispositionID:       decisionCapture.ID,
		GitHubDispositionURL:      decisionCapture.URL,
		DecisionCapture:           decisionCaptureReference,
		Decision:                  decisionCapture.Decision,
		DecisionDigest:            decisionCaptureReference.Digest,
	}
	if err := review.Validate(); err != nil {
		return err
	}
	if err := reviewCapture.ValidateAgainstAccountableReview(review); err != nil {
		return err
	}
	if err := decisionCapture.ValidateAgainstAccountableReview(review); err != nil {
		return err
	}
	reviewBody, err := bench.CanonicalJSON(review)
	if err != nil {
		return err
	}
	if err := writeMixedOutputs(map[string][]byte{
		option.reviewOutput:          append(reviewBody, '\n'),
		option.reviewCaptureOutput:   reviewCaptureBody,
		option.decisionCaptureOutput: decisionCaptureBody,
	}); err != nil {
		return err
	}
	digest, err := bench.DigestAccountableReview(review)
	if err != nil {
		return err
	}
	fmt.Printf("accountable_review=%s reviewer=%s reviewed_commit=%s decision_authority=%s implementation_commit=%s decision=%s\n", digest, review.ReviewerIdentity, review.ReviewedCommit, review.DecisionAuthorityIdentity, review.ImplementationCommit, review.Decision)
	return nil
}

func materializePlan(option options) error {
	if err := requirePaths(
		struct{ name, value string }{"source freeze", option.sourceFreezeOutput},
		struct{ name, value string }{"oracle candidate", option.oracleCandidate},
		struct{ name, value string }{"cross-check", option.crossCheck},
		struct{ name, value string }{"adjudication", option.adjudication},
		struct{ name, value string }{"accountable review", option.accountableReview},
		struct{ name, value string }{"final oracle freeze", option.finalOracleFreeze},
		struct{ name, value string }{"catalog", option.catalog},
		struct{ name, value string }{"oracle", option.oracle},
		struct{ name, value string }{"ratchet", option.ratchet},
		struct{ name, value string }{"baseline ratchet", option.baselineRatchet},
		struct{ name, value string }{"cycle policy", option.cyclePolicy},
		struct{ name, value string }{"plan output", option.planOutput},
	); err != nil {
		return err
	}
	freeze, err := decodeSourceFreeze(option.sourceFreezeOutput)
	if err != nil {
		return err
	}
	candidate, err := decodeCandidate(option.oracleCandidate)
	if err != nil {
		return err
	}
	crossCheck, err := decodeCrossCheck(option.crossCheck)
	if err != nil {
		return err
	}
	adjudication, err := decodeAdjudication(option.adjudication)
	if err != nil {
		return err
	}
	review, err := decodeReview(option.accountableReview)
	if err != nil {
		return err
	}
	finalOracle, err := decodeFinalOracleFreeze(option.finalOracleFreeze)
	if err != nil {
		return err
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
	baselineRatchet, err := decodeRatchet(option.baselineRatchet)
	if err != nil {
		return err
	}
	if err := bench.ValidateRatchetTightening(baselineRatchet, ratchet); err != nil {
		return fmt.Errorf("validate ratchet monotonicity: %w", err)
	}
	var policy cyclePolicy
	if err := decodeJSONFile(option.cyclePolicy, &policy); err != nil {
		return err
	}
	if err := policy.validate(); err != nil {
		return err
	}
	states, err := expectedCellStates(catalog, oracle)
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
	if err := validateRatchetPlanBindings(catalog, catalogDigest, oracleDigest, states, ratchet); err != nil {
		return err
	}
	freezeDigest, err := bench.DigestSourceFreeze(freeze)
	if err != nil {
		return err
	}
	candidateDigest, err := bench.DigestOracleCandidate(candidate)
	if err != nil {
		return err
	}
	crossCheckDigest, err := bench.DigestAutomatedCrossCheck(crossCheck)
	if err != nil {
		return err
	}
	adjudicationDigest, err := bench.DigestAdjudicationRecord(adjudication)
	if err != nil {
		return err
	}
	reviewDigest, err := bench.DigestAccountableReview(review)
	if err != nil {
		return err
	}
	cells := make([]bench.CycleCell, 0, len(states))
	for key, state := range states {
		targetID, engine, splitErr := splitCellKey(key)
		if splitErr != nil {
			return splitErr
		}
		dispatches := 1
		if state == bench.ObservationUnsupported {
			dispatches = 0
		}
		cells = append(cells, bench.CycleCell{TargetID: targetID, Engine: engine, ExpectedState: state, ScannerDispatches: dispatches})
	}
	plan := bench.CyclePlan{
		SchemaVersion: bench.CyclePlanSchemaVersion, CycleID: freeze.CycleID,
		SourceFreezeDigest: freezeDigest, OracleCandidateDigest: candidateDigest,
		CrossCheckDigest: crossCheckDigest, AdjudicationDigest: adjudicationDigest,
		AccountableReviewDigest: reviewDigest, FinalOracleDigest: finalOracle.OracleDigest,
		Repetitions: policy.Repetitions, Cells: canonicalCells(cells),
	}
	if finalOracle.OracleDigest != oracleDigest {
		return fmt.Errorf("final oracle freeze does not bind the supplied oracle")
	}
	if err := bench.ValidateCycleInputs(plan, freeze, candidate, crossCheck, adjudication, review, finalOracle); err != nil {
		return err
	}
	if err := writeJSONSet(map[string]any{option.planOutput: plan}); err != nil {
		return err
	}
	digest, err := bench.DigestCyclePlan(plan)
	if err != nil {
		return err
	}
	counts := countsForPlan(plan)
	fmt.Printf("plan=%s repetitions=%d cells=%d slots=%d dispatches=%d unsupported=%d\n", digest, counts.Repetitions, counts.Cells, counts.PlannedSlots, counts.ScannerDispatches, counts.Unsupported)
	return nil
}

func validateRatchetPlanBindings(catalog bench.Catalog, catalogDigest, oracleDigest string, states map[string]bench.ObservationState, ratchet bench.Ratchet) error {
	if ratchet.CatalogRevision != catalog.Revision || ratchet.CatalogDigest != catalogDigest || ratchet.OracleDigest != oracleDigest {
		return fmt.Errorf("ratchet does not bind the supplied catalog and oracle")
	}
	if len(ratchet.Floors) != len(states) {
		return fmt.Errorf("ratchet floor count does not match the derived matrix")
	}
	seen := make(map[string]struct{}, len(ratchet.Floors))
	for _, floor := range ratchet.Floors {
		key := cellKey(floor.Expected.TargetID, floor.Expected.Engine)
		state, exists := states[key]
		if !exists {
			return fmt.Errorf("ratchet contains unplanned floor %s", key)
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("ratchet duplicates floor %s", key)
		}
		seen[key] = struct{}{}
		if state == bench.ObservationUnsupported && floor.Mode != bench.FloorGateModeUnsupportedOnly {
			return fmt.Errorf("unsupported cell %s lacks unsupported-only ratchet mode", key)
		}
		if state == bench.ObservationComplete && floor.Mode == bench.FloorGateModeUnsupportedOnly {
			return fmt.Errorf("dispatched cell %s uses unsupported-only ratchet mode", key)
		}
		target, exists := targetByID(catalog, floor.Expected.TargetID)
		if !exists || floor.Expected.TargetDigest != target.Digest || floor.Expected.SBOMDigest != target.SBOMDigest {
			return fmt.Errorf("ratchet floor %s does not bind its catalog target", key)
		}
	}
	return nil
}

func validateRatchetAgainstMaterializedInputs(catalog bench.Catalog, catalogDigest, oracleDigest string, states map[string]bench.ObservationState, manifests map[string]capture.CaptureManifest, ratchet bench.Ratchet) error {
	if err := validateRatchetPlanBindings(catalog, catalogDigest, oracleDigest, states, ratchet); err != nil {
		return err
	}
	floors := make(map[string]bench.RatchetFloor, len(ratchet.Floors))
	for _, floor := range ratchet.Floors {
		floors[cellKey(floor.Expected.TargetID, floor.Expected.Engine)] = floor
	}
	for key, manifest := range manifests {
		floor := floors[key]
		target, _ := targetByID(catalog, manifest.TargetID)
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
		expected := floor.Expected
		if expected.TargetDigest != target.Digest || expected.SBOMDigest != target.SBOMDigest || expected.EngineVersion != manifest.EngineVersion || expected.EngineBinaryDigest != binaryDigest || expected.DatabaseBuild != manifest.Database.Build || expected.DatabaseDigest != databaseDigest || expected.EnvironmentID != manifest.Environment.ID || expected.EnvironmentDigest != environmentDigest || expected.ConfigDigest != configDigest {
			return fmt.Errorf("ratchet floor %s does not match generated capture identities", key)
		}
		if manifest.Capability == nil {
			if expected.CapabilityKind != "" || expected.CapabilityDigest != "" {
				return fmt.Errorf("ratchet floor %s carries an unexpected capability identity", key)
			}
		} else if expected.CapabilityKind != bench.CapabilityKindOSVScannerSUSERPM || expected.CapabilityDigest != manifest.Capability.Statement.Digest {
			return fmt.Errorf("ratchet floor %s does not bind the generated capability statement", key)
		}
	}
	return nil
}

func countsForPlan(plan bench.CyclePlan) matrixCounts {
	perRepetitionDispatches := 0
	perRepetitionUnsupported := 0
	for _, cell := range plan.Cells {
		perRepetitionDispatches += cell.ScannerDispatches
		if cell.ExpectedState == bench.ObservationUnsupported && cell.ScannerDispatches == 0 {
			perRepetitionUnsupported++
		}
	}
	return matrixCounts{Repetitions: plan.Repetitions, Cells: len(plan.Cells), PlannedSlots: plan.Repetitions * len(plan.Cells), ScannerDispatches: plan.Repetitions * perRepetitionDispatches, Unsupported: plan.Repetitions * perRepetitionUnsupported}
}

func cellKey(targetID string, engine bench.Engine) string {
	return targetID + "\x00" + string(engine)
}

func splitCellKey(key string) (string, bench.Engine, error) {
	parts := strings.Split(key, "\x00")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid cell key")
	}
	return parts[0], bench.Engine(parts[1]), nil
}
