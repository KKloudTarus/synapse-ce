package scabench

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

const (
	maxOVALCompressedBytes   = 96 << 20
	maxOVALDecompressedBytes = 1536 << 20
)

// NativeComparatorFactory creates a comparator bound to the exact selected
// target. Production supplies an OCI boundary; tests supply a deterministic
// fake without substituting a host package comparator.
type NativeComparatorFactory func(bench.Target) (ports.NativeVersionComparator, error)

// BuildSourceNativeEvidence reads SHA- and size-verified frozen vendor OVAL
// bytes, evaluates every safely supported definition matching the declared
// package allowlist, and executes every required version predicate through the
// target-native comparator. Unsupported or incomplete matching definitions
// abort the build instead of becoming negative evidence.
func BuildSourceNativeEvidence(ctx context.Context, repositoryRoot string, freeze bench.SourceFreeze, catalog bench.Catalog, plan bench.SourceEvidencePlan, newComparator NativeComparatorFactory) (bench.SourceCaseEvidenceSet, bench.NativeEvidenceSet, error) {
	if err := freeze.Validate(); err != nil {
		return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, err
	}
	if err := catalog.Validate(); err != nil {
		return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, err
	}
	if err := plan.Validate(); err != nil {
		return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, err
	}
	if newComparator == nil {
		return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, fmt.Errorf("target-native comparator factory is required")
	}
	freezeDigest, err := bench.DigestSourceFreeze(freeze)
	if err != nil {
		return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, err
	}
	if plan.CycleID != freeze.CycleID || plan.SourceFreezeDigest != freezeDigest {
		return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, fmt.Errorf("source evidence plan does not bind the frozen source")
	}
	assets := make(map[string]bench.ContentReference, len(freeze.Assets))
	for _, asset := range freeze.Assets {
		assets[asset.Locator] = asset
	}
	targets := make(map[string]bench.Target, len(catalog.Targets))
	for _, target := range catalog.Targets {
		targets[target.ID] = target
	}

	targetEvidence := make([]bench.NativeTargetEvidence, 0, len(plan.Targets))
	groups := make(map[sourceCaseKey]*sourceCaseGroup)
	diagnostics := make([]bench.SourceEvidenceDiagnostic, 0)
	for _, selection := range plan.Targets {
		target, exists := targets[selection.TargetID]
		if !exists {
			return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, fmt.Errorf("source evidence target %q is not in the catalog", selection.TargetID)
		}
		asset, exists := assets[selection.SourceAssetLocator]
		if !exists {
			return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, fmt.Errorf("source evidence target %q selects an asset outside the source freeze", selection.TargetID)
		}
		body, err := ReadVerifiedRepositoryAsset(repositoryRoot, asset)
		if err != nil {
			return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, fmt.Errorf("read frozen vendor source for target %q: %w", selection.TargetID, err)
		}
		document, err := parseVendorOVAL(body)
		if err != nil {
			return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, fmt.Errorf("parse frozen vendor OVAL for target %q: %w", selection.TargetID, err)
		}
		comparator, err := newComparator(target)
		if err != nil {
			return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, fmt.Errorf("create target-native comparator for target %q: %w", selection.TargetID, err)
		}
		if comparator == nil {
			return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, fmt.Errorf("target-native comparator for target %q is required", selection.TargetID)
		}
		records := make(map[string]bench.NativeComparisonRecord)
		for _, pkg := range selection.Packages {
			if !catalogHasComponent(target, pkg.Component) {
				return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, fmt.Errorf("source evidence package %q does not match catalog target %q", pkg.Name, target.ID)
			}
			definitions := document.definitionsForPackage(pkg)
			if len(definitions) == 0 {
				return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, fmt.Errorf("frozen vendor source is silent for allowlisted package %q on target %q", pkg.Name, target.ID)
			}
			for _, definition := range definitions {
				if len(definition.advisories) == 0 {
					diagnostics = append(diagnostics, sourceOVALDiagnostic(target.ID, pkg.Component, definition.id, "definition", definition.id, "definition has no CVE reference"))
					continue
				}
				evaluator := ovalEvaluator{ctx: ctx, document: document, target: target, selection: selection, pkg: pkg, comparator: comparator, definitionStack: map[string]struct{}{definition.id: {}}}
				if definition.unsupported != "" {
					diagnostics = append(diagnostics, sourceOVALDiagnostic(target.ID, pkg.Component, definition.id, "definition", definition.id, definition.unsupported))
					continue
				}
				result, err := evaluator.evaluate(definition.criteria)
				if err != nil {
					return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, fmt.Errorf("evaluate vendor definition %q for package %q: %w", definition.id, pkg.Name, err)
				}
				for _, record := range result.records {
					if previous, exists := records[record.ID]; exists && previous != record {
						return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, fmt.Errorf("vendor definition %q produced conflicting native comparison %q", definition.id, record.ID)
					}
					records[record.ID] = record
				}
				for _, unsupported := range result.unsupported {
					diagnostics = append(diagnostics, sourceOVALDiagnostic(target.ID, pkg.Component, definition.id, unsupported.kind, unsupported.id, unsupported.reason))
				}
				if !result.applicable || len(result.unsupported) != 0 {
					continue
				}
				truth, err := ovalResultTruth(result)
				if err != nil {
					diagnostics = append(diagnostics, sourceOVALDiagnostic(target.ID, pkg.Component, definition.id, "definition", definition.id, err.Error()))
					continue
				}
				for _, advisory := range definition.advisories {
					key := sourceCaseKey{targetID: target.ID, component: pkg.Component, advisoryID: advisory}
					group := groups[key]
					if group == nil {
						group = &sourceCaseGroup{key: key, citation: asset, truth: truth}
						groups[key] = group
					}
					if group.truth != truth {
						return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, fmt.Errorf("vendor definitions for target %q component %q advisory %q disagree", target.ID, pkg.Name, advisory)
					}
					group.definitions = append(group.definitions, definition.id)
					for _, record := range result.records {
						group.comparisonIDs = appendUnique(group.comparisonIDs, record.ID)
					}
				}
			}
		}
		comparisons := make([]bench.NativeComparisonRecord, 0, len(records))
		for _, record := range records {
			comparisons = append(comparisons, record)
		}
		sort.Slice(comparisons, func(left, right int) bool { return comparisons[left].ID < comparisons[right].ID })
		targetEvidence = append(targetEvidence, bench.NativeTargetEvidence{TargetID: target.ID, TargetDigest: target.Digest, PackageFamily: selection.PackageFamily, Comparisons: comparisons})
	}

	native := bench.NativeEvidenceSet{SchemaVersion: bench.NativeEvidenceSetSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, Targets: targetEvidence}
	nativeDigest, err := bench.DigestNativeEvidenceSet(native)
	if err != nil {
		return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, err
	}
	cases := make([]bench.SourceCaseEvidence, 0, len(groups))
	for _, group := range groups {
		sort.Strings(group.definitions)
		sort.Strings(group.comparisonIDs)
		caseID := group.key.targetID + "::" + group.key.component.PURL + "::" + group.key.advisoryID
		cases = append(cases, bench.SourceCaseEvidence{
			ID: caseID, TargetID: group.key.targetID, Component: group.key.component, AdvisoryID: group.key.advisoryID,
			DerivedTruth: group.truth, NativeComparisonIDs: group.comparisonIDs,
			Rationale: "derived from complete supported vendor OVAL definitions " + strings.Join(group.definitions, ", "),
			Citations: []bench.ContentReference{group.citation},
		})
	}
	sort.Slice(cases, func(left, right int) bool { return cases[left].ID < cases[right].ID })
	sort.Slice(diagnostics, func(left, right int) bool {
		leftKey := diagnostics[left].TargetID + "\x00" + diagnostics[left].Component.PURL + "\x00" + diagnostics[left].DefinitionID + "\x00" + diagnostics[left].ElementKind + "\x00" + diagnostics[left].ElementID
		rightKey := diagnostics[right].TargetID + "\x00" + diagnostics[right].Component.PURL + "\x00" + diagnostics[right].DefinitionID + "\x00" + diagnostics[right].ElementKind + "\x00" + diagnostics[right].ElementID
		return leftKey < rightKey
	})
	if len(cases) == 0 && len(diagnostics) == 0 {
		return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, fmt.Errorf("source evidence plan did not produce cases or diagnostics")
	}
	source := bench.SourceCaseEvidenceSet{SchemaVersion: bench.SourceCaseEvidenceSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, NativeEvidenceDigest: nativeDigest, Cases: cases, Unsupported: diagnostics}
	if err := source.Validate(); err != nil {
		return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, err
	}
	return source, native, nil
}

type sourceCaseKey struct {
	targetID   string
	component  bench.Component
	advisoryID string
}

type sourceCaseGroup struct {
	key           sourceCaseKey
	citation      bench.ContentReference
	truth         bench.Truth
	definitions   []string
	comparisonIDs []string
}

func catalogHasComponent(target bench.Target, component bench.Component) bool {
	for _, candidate := range target.Components {
		if candidate == component {
			return true
		}
	}
	return false
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func sourceOVALDiagnostic(targetID string, component bench.Component, definitionID, elementKind, elementID, reason string) bench.SourceEvidenceDiagnostic {
	return bench.SourceEvidenceDiagnostic{TargetID: targetID, Component: component, DefinitionID: definitionID, ElementKind: elementKind, ElementID: elementID, Reason: reason}
}

type ovalNode struct {
	name     string
	attrs    map[string]string
	text     string
	children []*ovalNode
}

type ovalDocument struct {
	definitions map[string]ovalDefinition
	tests       map[string]ovalTest
	objects     map[string]ovalObject
	states      map[string]ovalState
}

type ovalDefinition struct {
	id          string
	advisories  []string
	criteria    *ovalNode
	unsupported string
}

type ovalTest struct {
	id          string
	kind        string
	check       string
	existence   string
	objectID    string
	objectIDs   []string
	stateID     string
	stateIDs    []string
	unsupported string
}

type ovalObject struct {
	id          string
	name        string
	names       []string
	guards      map[string]string
	unknown     []string
	unsupported string
}

type ovalState struct {
	id          string
	operator    string
	negate      bool
	fixedEVR    string
	guards      map[string]string
	unknown     []string
	unsupported string
}

func parseVendorOVAL(body []byte) (ovalDocument, error) {
	decoded, err := boundedOVALBytes(body)
	if err != nil {
		return ovalDocument{}, err
	}
	decoder := xml.NewDecoder(bytes.NewReader(decoded))
	decoder.Strict = true
	var root *ovalNode
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ovalDocument{}, fmt.Errorf("decode XML: %w", err)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		root, err = decodeOVALNode(decoder, start, 0)
		if err != nil {
			return ovalDocument{}, err
		}
		break
	}
	if root == nil {
		return ovalDocument{}, fmt.Errorf("vendor OVAL source is empty")
	}
	document := ovalDocument{definitions: map[string]ovalDefinition{}, tests: map[string]ovalTest{}, objects: map[string]ovalObject{}, states: map[string]ovalState{}}
	for _, node := range descendOVAL(root) {
		id := node.attrs["id"]
		switch {
		case node.name == "definition":
			if id == "" {
				return ovalDocument{}, fmt.Errorf("vendor OVAL definition has no id")
			}
			definition := ovalDefinition{id: id, criteria: firstOVALDescendant(node, "criteria")}
			if definition.criteria == nil {
				definition.unsupported = "definition has no criteria"
			}
			for _, reference := range descendOVAL(node) {
				if reference.name == "reference" && strings.EqualFold(reference.attrs["source"], "CVE") && strings.TrimSpace(reference.attrs["ref_id"]) != "" {
					definition.advisories = appendUnique(definition.advisories, reference.attrs["ref_id"])
				}
			}
			if _, exists := document.definitions[id]; exists {
				return ovalDocument{}, fmt.Errorf("vendor OVAL has duplicate definition %q", id)
			}
			document.definitions[id] = definition
		case strings.HasSuffix(node.name, "_test"):
			test, err := parseOVALTest(node)
			if err != nil {
				test, err = unsupportedOVALTest(node, err)
				if err != nil {
					return ovalDocument{}, err
				}
			}
			if _, exists := document.tests[test.id]; exists {
				return ovalDocument{}, fmt.Errorf("vendor OVAL has duplicate test %q", test.id)
			}
			document.tests[test.id] = test
		case strings.HasSuffix(node.name, "_object"):
			object, err := parseOVALObject(node)
			if err != nil {
				object, err = unsupportedOVALObject(node, err)
				if err != nil {
					return ovalDocument{}, err
				}
			}
			if _, exists := document.objects[object.id]; exists {
				return ovalDocument{}, fmt.Errorf("vendor OVAL has duplicate object %q", object.id)
			}
			document.objects[object.id] = object
		case strings.HasSuffix(node.name, "_state"):
			state, err := parseOVALState(node)
			if err != nil {
				state, err = unsupportedOVALState(node, err)
				if err != nil {
					return ovalDocument{}, err
				}
			}
			if _, exists := document.states[state.id]; exists {
				return ovalDocument{}, fmt.Errorf("vendor OVAL has duplicate state %q", state.id)
			}
			document.states[state.id] = state
		}
	}
	if len(document.definitions) == 0 || len(document.tests) == 0 || len(document.objects) == 0 {
		return ovalDocument{}, fmt.Errorf("vendor OVAL source lacks definitions, tests, or objects")
	}
	return document, nil
}

func boundedOVALBytes(body []byte) ([]byte, error) {
	return boundedOVALBytesWithLimits(body, maxOVALCompressedBytes, maxOVALDecompressedBytes)
}

func boundedOVALBytesWithLimits(body []byte, compressedLimit, decompressedLimit int) ([]byte, error) {
	if len(body) == 0 || len(body) > compressedLimit {
		return nil, fmt.Errorf("vendor OVAL input size is invalid")
	}
	reader := io.Reader(bytes.NewReader(body))
	switch {
	case len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b:
		gzipReader, err := gzip.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("open vendor OVAL gzip: %w", err)
		}
		defer func() { _ = gzipReader.Close() }()
		reader = gzipReader
	case len(body) >= 3 && body[0] == 'B' && body[1] == 'Z' && body[2] == 'h':
		reader = bzip2.NewReader(reader)
	}
	limited := io.LimitReader(reader, int64(decompressedLimit)+1)
	decoded, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read vendor OVAL: %w", err)
	}
	if len(decoded) == 0 || len(decoded) > decompressedLimit {
		return nil, fmt.Errorf("vendor OVAL expands beyond its limit")
	}
	return decoded, nil
}

func decodeOVALNode(decoder *xml.Decoder, start xml.StartElement, depth int) (*ovalNode, error) {
	if depth > 128 {
		return nil, fmt.Errorf("vendor OVAL nesting exceeds limit")
	}
	node := &ovalNode{name: start.Name.Local, attrs: make(map[string]string, len(start.Attr))}
	for _, attr := range start.Attr {
		node.attrs[attr.Name.Local] = strings.TrimSpace(attr.Value)
	}
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch value := token.(type) {
		case xml.StartElement:
			child, err := decodeOVALNode(decoder, value, depth+1)
			if err != nil {
				return nil, err
			}
			node.children = append(node.children, child)
		case xml.CharData:
			node.text += string(value)
		case xml.EndElement:
			if value.Name == start.Name {
				node.text = strings.TrimSpace(node.text)
				return node, nil
			}
		}
	}
}

func descendOVAL(root *ovalNode) []*ovalNode {
	if root == nil {
		return nil
	}
	result := []*ovalNode{root}
	for _, child := range root.children {
		result = append(result, descendOVAL(child)...)
	}
	return result
}

func firstOVALDescendant(root *ovalNode, name string) *ovalNode {
	for _, node := range descendOVAL(root) {
		if node.name == name {
			return node
		}
	}
	return nil
}

func parseOVALTest(node *ovalNode) (ovalTest, error) {
	id := node.attrs["id"]
	if id == "" {
		return ovalTest{}, fmt.Errorf("vendor OVAL test has no id")
	}
	objectRefs := make([]string, 0, 1)
	stateRefs := make([]string, 0, 1)
	for _, child := range node.children {
		switch child.name {
		case "object":
			objectRefs = append(objectRefs, child.attrs["object_ref"])
		case "state":
			stateRefs = append(stateRefs, child.attrs["state_ref"])
		}
	}
	check := node.attrs["check"]
	if check == "" {
		check = "all"
	}
	existence := node.attrs["check_existence"]
	if existence == "" {
		existence = "at_least_one_exists"
	}
	if strings.ToLower(check) != "all" || (existence != "at_least_one_exists" && existence != "all_exist") || node.attrs["negate"] == "true" || len(objectRefs) != 1 || len(stateRefs) != 1 || objectRefs[0] == "" || stateRefs[0] == "" {
		return ovalTest{}, fmt.Errorf("vendor OVAL test %q has unsupported check, existence, negation, or references", id)
	}
	return ovalTest{id: id, kind: node.name, check: check, existence: existence, objectID: objectRefs[0], objectIDs: objectRefs, stateID: stateRefs[0], stateIDs: stateRefs}, nil
}

func parseOVALObject(node *ovalNode) (ovalObject, error) {
	if node.attrs["id"] == "" {
		return ovalObject{}, fmt.Errorf("vendor OVAL object has no id")
	}
	object := ovalObject{id: node.attrs["id"], guards: map[string]string{}}
	for _, child := range node.children {
		value := strings.TrimSpace(child.text)
		switch child.name {
		case "name":
			if object.name != "" || value == "" {
				return ovalObject{}, fmt.Errorf("vendor OVAL object %q has an ambiguous package name", object.id)
			}
			object.name = value
			object.names = append(object.names, value)
		case "arch", "product", "release":
			if value == "" || object.guards[child.name] != "" {
				return ovalObject{}, fmt.Errorf("vendor OVAL object %q has an ambiguous %s guard", object.id, child.name)
			}
			object.guards[child.name] = value
		default:
			object.unknown = append(object.unknown, child.name)
		}
	}
	if object.name == "" {
		return ovalObject{}, fmt.Errorf("vendor OVAL object %q has no package name", object.id)
	}
	return object, nil
}

func parseOVALState(node *ovalNode) (ovalState, error) {
	if node.attrs["id"] == "" {
		return ovalState{}, fmt.Errorf("vendor OVAL state has no id")
	}
	state := ovalState{id: node.attrs["id"], operator: node.attrs["operator"], negate: node.attrs["negate"] == "true", guards: map[string]string{}}
	if state.operator == "" {
		state.operator = "AND"
	}
	if state.operator != "AND" || state.negate {
		return ovalState{}, fmt.Errorf("vendor OVAL state %q does not use positive AND", state.id)
	}
	for _, child := range node.children {
		value := strings.TrimSpace(child.text)
		switch child.name {
		case "evr":
			if state.fixedEVR != "" || value == "" || child.attrs["operation"] != "less than" {
				return ovalState{}, fmt.Errorf("vendor OVAL state %q has an unsupported version range", state.id)
			}
			state.fixedEVR = value
		case "arch", "product", "release":
			operation := child.attrs["operation"]
			if operation != "" && operation != "equals" || value == "" || state.guards[child.name] != "" {
				return ovalState{}, fmt.Errorf("vendor OVAL state %q has an unsupported %s guard", state.id, child.name)
			}
			state.guards[child.name] = value
		default:
			state.unknown = append(state.unknown, child.name)
		}
	}
	if state.fixedEVR == "" {
		return ovalState{}, fmt.Errorf("vendor OVAL state %q has no supported EVR predicate", state.id)
	}
	return state, nil
}

func unsupportedOVALTest(node *ovalNode, parseErr error) (ovalTest, error) {
	id := node.attrs["id"]
	if id == "" {
		return ovalTest{}, parseErr
	}
	var objectIDs, stateIDs []string
	for _, child := range node.children {
		switch child.name {
		case "object":
			if reference := child.attrs["object_ref"]; reference != "" {
				objectIDs = append(objectIDs, reference)
			}
		case "state":
			if reference := child.attrs["state_ref"]; reference != "" {
				stateIDs = append(stateIDs, reference)
			}
		}
	}
	var objectID, stateID string
	if len(objectIDs) != 0 {
		objectID = objectIDs[0]
	}
	if len(stateIDs) != 0 {
		stateID = stateIDs[0]
	}
	return ovalTest{id: id, kind: node.name, objectID: objectID, objectIDs: objectIDs, stateID: stateID, stateIDs: stateIDs, unsupported: parseErr.Error()}, nil
}

func unsupportedOVALObject(node *ovalNode, parseErr error) (ovalObject, error) {
	id := node.attrs["id"]
	if id == "" {
		return ovalObject{}, parseErr
	}
	object := ovalObject{id: id, guards: map[string]string{}, unsupported: parseErr.Error()}
	for _, child := range node.children {
		if child.name != "name" {
			continue
		}
		if name := strings.TrimSpace(child.text); name != "" {
			object.names = append(object.names, name)
			if object.name == "" {
				object.name = name
			}
		}
	}
	return object, nil
}

func unsupportedOVALState(node *ovalNode, parseErr error) (ovalState, error) {
	id := node.attrs["id"]
	if id == "" {
		return ovalState{}, parseErr
	}
	return ovalState{id: id, guards: map[string]string{}, unsupported: parseErr.Error()}, nil
}

func (test ovalTest) objectReferences() []string {
	if len(test.objectIDs) != 0 {
		return test.objectIDs
	}
	if test.objectID == "" {
		return nil
	}
	return []string{test.objectID}
}

func (object ovalObject) matchesPackage(pkg bench.SourceEvidencePackage) bool {
	names := object.names
	if len(names) == 0 && object.name != "" {
		names = []string{object.name}
	}
	for _, name := range names {
		if name == pkg.Name || name == pkg.SourcePackage {
			return true
		}
	}
	return false
}

func (evaluator ovalEvaluator) selectedObject(test ovalTest) (ovalObject, bool) {
	for _, objectID := range test.objectReferences() {
		object, exists := evaluator.document.objects[objectID]
		if !exists || !object.matchesPackage(evaluator.pkg) {
			continue
		}
		applicable := true
		for name, want := range map[string]string{"arch": evaluator.selection.Architecture, "product": evaluator.selection.Product, "release": evaluator.selection.Release} {
			if value := object.guards[name]; value != "" && value != want {
				applicable = false
				break
			}
		}
		if applicable {
			return object, true
		}
	}
	return ovalObject{}, false
}

func (document ovalDocument) definitionsForPackage(pkg bench.SourceEvidencePackage) []ovalDefinition {
	definitions := make([]ovalDefinition, 0)
	for _, definition := range document.definitions {
		if document.nodeMatchesPackage(definition.criteria, pkg, map[string]struct{}{definition.id: {}}) {
			definitions = append(definitions, definition)
		}
	}
	sort.Slice(definitions, func(left, right int) bool { return definitions[left].id < definitions[right].id })
	return definitions
}

func (document ovalDocument) nodeMatchesPackage(node *ovalNode, pkg bench.SourceEvidencePackage, seenDefinitions map[string]struct{}) bool {
	if node == nil {
		return false
	}
	switch node.name {
	case "criterion":
		test, exists := document.tests[node.attrs["test_ref"]]
		if !exists {
			return false
		}
		for _, objectID := range test.objectReferences() {
			object, exists := document.objects[objectID]
			if exists && object.matchesPackage(pkg) {
				return true
			}
		}
		return false
	case "extend_definition":
		definitionID := node.attrs["definition_ref"]
		if definitionID == "" {
			return false
		}
		if _, seen := seenDefinitions[definitionID]; seen {
			return false
		}
		definition, exists := document.definitions[definitionID]
		if !exists {
			return false
		}
		seenDefinitions[definitionID] = struct{}{}
		matched := document.nodeMatchesPackage(definition.criteria, pkg, seenDefinitions)
		delete(seenDefinitions, definitionID)
		return matched
	default:
		for _, child := range node.children {
			if document.nodeMatchesPackage(child, pkg, seenDefinitions) {
				return true
			}
		}
		return false
	}
}

func criterionTestRefs(node *ovalNode) []string {
	if node == nil {
		return nil
	}
	refs := make([]string, 0)
	if node.name == "criterion" && node.attrs["test_ref"] != "" {
		refs = append(refs, node.attrs["test_ref"])
	}
	for _, child := range node.children {
		refs = append(refs, criterionTestRefs(child)...)
	}
	return refs
}

type ovalEvaluator struct {
	ctx             context.Context
	document        ovalDocument
	target          bench.Target
	selection       bench.SourceEvidenceTarget
	pkg             bench.SourceEvidencePackage
	comparator      ports.NativeVersionComparator
	definitionStack map[string]struct{}
}

type ovalResult struct {
	applicable  bool
	truth       bool
	records     []bench.NativeComparisonRecord
	unsupported []*ovalUnsupportedError
}

type ovalUnsupportedError struct {
	kind   string
	id     string
	reason string
}

func (err *ovalUnsupportedError) Error() string {
	return "vendor OVAL " + err.kind + " " + fmt.Sprintf("%q", err.id) + " is unsupported: " + err.reason
}

func (evaluator ovalEvaluator) evaluate(node *ovalNode) (ovalResult, error) {
	if node == nil {
		return unsupportedOVALResult("criteria", "missing", "criterion is missing"), nil
	}
	if negate, exists := node.attrs["negate"]; exists {
		switch strings.ToLower(strings.TrimSpace(negate)) {
		case "false":
		case "true":
			return unsupportedOVALResult("criteria", node.name, "negated criteria are unsupported"), nil
		default:
			return unsupportedOVALResult("criteria", node.name, "criteria negate must be true or false"), nil
		}
	}
	switch node.name {
	case "criterion":
		testID := node.attrs["test_ref"]
		if testID == "" {
			return unsupportedOVALResult("criterion", "missing-test-ref", "criterion has no explicit test reference"), nil
		}
		return evaluator.evaluateTest(testID)
	case "extend_definition":
		definitionID := node.attrs["definition_ref"]
		if definitionID == "" {
			return unsupportedOVALResult("extend_definition", "missing-definition-ref", "extension has no definition reference"), nil
		}
		if _, seen := evaluator.definitionStack[definitionID]; seen {
			return unsupportedOVALResult("definition", definitionID, "definition extension is cyclic"), nil
		}
		definition, exists := evaluator.document.definitions[definitionID]
		if !exists {
			return unsupportedOVALResult("definition", definitionID, "extended definition is missing"), nil
		}
		if definition.unsupported != "" {
			return unsupportedOVALResult("definition", definitionID, definition.unsupported), nil
		}
		if evaluator.definitionStack == nil {
			evaluator.definitionStack = make(map[string]struct{})
		}
		evaluator.definitionStack[definitionID] = struct{}{}
		result, err := evaluator.evaluate(definition.criteria)
		delete(evaluator.definitionStack, definitionID)
		return result, err
	case "criteria":
		operator := node.attrs["operator"]
		if operator == "" {
			operator = "AND"
		}
		if (operator != "AND" && operator != "OR") || len(node.children) == 0 {
			return unsupportedOVALResult("criteria", node.name, "criteria has an unsupported operator or no children"), nil
		}
		if operator == "AND" {
			result := ovalResult{applicable: true, truth: true}
			for _, child := range node.children {
				childResult, err := evaluator.evaluate(child)
				if err != nil {
					return ovalResult{}, err
				}
				result.unsupported = append(result.unsupported, childResult.unsupported...)
				if !childResult.applicable {
					result.applicable = false
				}
				result.truth = result.truth && childResult.truth
				result.records = append(result.records, childResult.records...)
			}
			return result, nil
		}

		// An OR is affected when one complete supported branch is true. Keep the
		// first such branch in source order; later alternatives cannot undermine
		// that witness and must not create unrelated diagnostics or split records.
		result := ovalResult{}
		for _, child := range node.children {
			childResult, err := evaluator.evaluate(child)
			if err != nil {
				return ovalResult{}, err
			}
			if !childResult.applicable {
				continue
			}
			if childResult.truth && len(childResult.unsupported) == 0 {
				return childResult, nil
			}
			result.applicable = true
			result.unsupported = append(result.unsupported, childResult.unsupported...)
			result.records = append(result.records, childResult.records...)
		}
		// Without a complete true witness, only supported false branches can
		// establish fixed status. Any retained unsupported branch blocks it.
		return result, nil
	default:
		return unsupportedOVALResult("criteria", node.name, "criteria has an unsupported child"), nil
	}
}

func unsupportedOVALResult(kind, id, reason string) ovalResult {
	return ovalResult{applicable: true, unsupported: []*ovalUnsupportedError{{kind: kind, id: id, reason: reason}}}
}

func (evaluator ovalEvaluator) evaluateTest(testID string) (ovalResult, error) {
	test, exists := evaluator.document.tests[testID]
	if !exists {
		return unsupportedOVALResult("test", testID, "test is missing"), nil
	}

	// Resolve package identity and object-level guards before considering test or
	// state semantics. An unsupported branch for another package or platform is
	// non-applicable evidence, not a reason to block this selected package.
	missingObject := ""
	for _, objectID := range test.objectReferences() {
		if _, exists := evaluator.document.objects[objectID]; !exists {
			missingObject = objectID
			break
		}
	}
	object, applicable := evaluator.selectedObject(test)
	if !applicable {
		if missingObject != "" {
			return unsupportedOVALResult("object", missingObject, "object is missing"), nil
		}
		return ovalResult{}, nil
	}
	if object.unsupported != "" {
		return unsupportedOVALResult("object", object.id, object.unsupported), nil
	}
	if len(object.unknown) != 0 {
		return unsupportedOVALResult("object", object.id, "object has unresolved semantics"), nil
	}
	if test.unsupported != "" {
		return unsupportedOVALResult("test", testID, test.unsupported), nil
	}
	if evaluator.selection.PackageFamily == "deb" && !strings.Contains(test.kind, "dpkg") || evaluator.selection.PackageFamily == "rpm" && !strings.Contains(test.kind, "rpm") {
		return unsupportedOVALResult("test", testID, "test does not match the selected package family"), nil
	}

	state, exists := evaluator.document.states[test.stateID]
	if !exists {
		return unsupportedOVALResult("state", test.stateID, "state is missing"), nil
	}
	if state.unsupported != "" {
		return unsupportedOVALResult("state", state.id, state.unsupported), nil
	}
	if len(state.unknown) != 0 {
		return unsupportedOVALResult("state", state.id, "state has unresolved semantics"), nil
	}
	for name, want := range map[string]string{"arch": evaluator.selection.Architecture, "product": evaluator.selection.Product, "release": evaluator.selection.Release} {
		if value := state.guards[name]; value != "" && value != want {
			return ovalResult{}, nil
		}
	}

	candidateEVR := ""
	packageIdentity := ""
	switch {
	case object.name == evaluator.pkg.SourcePackage:
		// Prefer an explicit source mapping even where a source and binary name
		// happen to be the same: vendor OVAL objects are source-package scoped.
		candidateEVR = evaluator.pkg.SourceEVR
		packageIdentity = "source:" + evaluator.pkg.SourcePackage
	case object.name == evaluator.pkg.Name:
		candidateEVR = evaluator.pkg.Component.Version
		packageIdentity = "binary:" + evaluator.pkg.Name
	default:
		return ovalResult{}, nil
	}
	family := ports.NativePackageDeb
	method := "target-native-dpkg"
	if evaluator.selection.PackageFamily == "rpm" {
		family = ports.NativePackageRPM
		method = "target-native-rpm"
	}
	comparison, err := evaluator.comparator.CompareNativeVersion(evaluator.ctx, ports.NativeVersionComparisonRequest{TargetDigest: evaluator.target.Digest, Family: family, LeftEVR: candidateEVR, RightEVR: state.fixedEVR})
	if err != nil {
		return ovalResult{}, fmt.Errorf("target-native comparison for test %q: %w", testID, err)
	}
	relation := ""
	switch comparison.Relation {
	case -1:
		relation = "before"
	case 0:
		relation = "equal"
	case 1:
		relation = "after"
	default:
		return ovalResult{}, fmt.Errorf("target-native comparison for test %q returned an invalid relation", testID)
	}
	record := bench.NativeComparisonRecord{SchemaVersion: bench.NativeComparisonSchemaVersion, ID: evaluator.target.ID + "::" + testID, TargetID: evaluator.target.ID, TargetDigest: evaluator.target.Digest, PackageFamily: evaluator.selection.PackageFamily, PackageIdentity: packageIdentity, CandidateEVR: candidateEVR, FixedEVR: state.fixedEVR, Relation: relation, Method: method, ExecutionDigest: comparison.ExecutionDigest}
	if err := record.Validate(); err != nil {
		return ovalResult{}, err
	}
	return ovalResult{applicable: true, truth: relation == "before", records: []bench.NativeComparisonRecord{record}}, nil
}

func ovalResultTruth(result ovalResult) (bench.Truth, error) {
	if !result.applicable {
		return "", fmt.Errorf("vendor OVAL branch is not applicable")
	}
	if len(result.unsupported) != 0 {
		return "", fmt.Errorf("vendor OVAL branch retains unsupported semantics")
	}
	if len(result.records) == 0 {
		return "", fmt.Errorf("vendor OVAL branch has no version predicates")
	}
	if result.truth {
		for _, record := range result.records {
			if record.Relation == "before" {
				return bench.TruthAffected, nil
			}
		}
		return "", fmt.Errorf("vendor OVAL affected branch lacks affected evidence")
	}
	for _, record := range result.records {
		if record.Relation == "before" {
			return "", fmt.Errorf("vendor OVAL fixed branch has an affected applicable predicate")
		}
	}
	return bench.TruthFixed, nil
}
