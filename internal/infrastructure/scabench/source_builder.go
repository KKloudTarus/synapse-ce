package scabench

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
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
	diagnostics, err = normalizeSourceEvidenceDiagnostics(diagnostics)
	if err != nil {
		return bench.SourceCaseEvidenceSet{}, bench.NativeEvidenceSet{}, fmt.Errorf("normalize source evidence diagnostics: %w", err)
	}
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

func normalizeSourceEvidenceDiagnostics(diagnostics []bench.SourceEvidenceDiagnostic) ([]bench.SourceEvidenceDiagnostic, error) {
	sorted := append([]bench.SourceEvidenceDiagnostic(nil), diagnostics...)
	sort.Slice(sorted, func(left, right int) bool {
		leftIdentity := sourceEvidenceDiagnosticIdentity(sorted[left])
		rightIdentity := sourceEvidenceDiagnosticIdentity(sorted[right])
		if leftIdentity != rightIdentity {
			return leftIdentity < rightIdentity
		}
		return sourceEvidenceDiagnosticPayload(sorted[left]) < sourceEvidenceDiagnosticPayload(sorted[right])
	})

	normalized := make([]bench.SourceEvidenceDiagnostic, 0, len(sorted))
	for _, diagnostic := range sorted {
		if len(normalized) == 0 {
			normalized = append(normalized, diagnostic)
			continue
		}
		previous := normalized[len(normalized)-1]
		if sourceEvidenceDiagnosticIdentity(previous) != sourceEvidenceDiagnosticIdentity(diagnostic) {
			normalized = append(normalized, diagnostic)
			continue
		}
		if previous != diagnostic {
			return nil, fmt.Errorf("conflicting source evidence diagnostics for identity %q", sourceEvidenceDiagnosticIdentity(diagnostic))
		}
	}
	return normalized, nil
}

func sourceEvidenceDiagnosticIdentity(diagnostic bench.SourceEvidenceDiagnostic) string {
	return diagnostic.TargetID + "\x00" +
		diagnostic.Component.PURL + "\x00" +
		diagnostic.DefinitionID + "\x00" +
		diagnostic.ElementKind + "\x00" +
		diagnostic.ElementID
}

func sourceEvidenceDiagnosticPayload(diagnostic bench.SourceEvidenceDiagnostic) string {
	return sourceEvidenceDiagnosticIdentity(diagnostic) + "\x00" +
		diagnostic.Component.Version + "\x00" +
		diagnostic.Reason
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
	comment     string
	objectID    string
	objectIDs   []string
	stateID     string
	stateIDs    []string
	unsupported string
}

type ovalObject struct {
	id                 string
	kind               string
	name               string
	names              []string
	guards             map[string]string
	debianReleaseGuard bool
	debianUnameGuard   bool
	unknown            []string
	unsupported        string
}

type ovalState struct {
	id                 string
	kind               string
	operator           string
	predicateKind      string
	predicateValue     string
	debianReleaseGuard bool
	guards             map[string]string
	architectures      map[string]struct{}
	unknown            []string
	unsupported        string
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
				if reference.name != "reference" || !strings.EqualFold(reference.attrs["source"], "CVE") {
					continue
				}
				if advisory, valid := canonicalOVALCVE(reference.attrs["ref_id"]); valid {
					definition.advisories = appendUnique(definition.advisories, advisory)
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

// canonicalOVALCVE accepts only one complete direct or Mitre-prefixed CVE
// identity. Vendor ref_id values are untrusted metadata, so substrings and
// ambiguous lists never become benchmark advisory identities.
func canonicalOVALCVE(refID string) (string, bool) {
	value := strings.TrimSpace(refID)
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "mitre ") {
		value = value[len("mitre "):]
		if value == "" || strings.TrimSpace(value) != value {
			return "", false
		}
	}
	value = strings.ToUpper(value)
	parts := strings.Split(value, "-")
	if len(parts) != 3 || parts[0] != "CVE" || len(parts[1]) != 4 || len(parts[2]) < 4 || !decimalOVAL(parts[1]) || !decimalOVAL(parts[2]) {
		return "", false
	}
	return value, true
}

func decimalOVAL(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return value != ""
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

func isOVALNamespaceDeclaration(attr xml.Attr) bool {
	return attr.Name.Space == "xmlns" || (attr.Name.Space == "" && attr.Name.Local == "xmlns")
}

func isOVALSchemaLocation(element string, attr xml.Attr) bool {
	return element == "oval_definitions" &&
		attr.Name.Space == "http://www.w3.org/2001/XMLSchema-instance" &&
		attr.Name.Local == "schemaLocation"
}

func decodeOVALNode(decoder *xml.Decoder, start xml.StartElement, depth int) (*ovalNode, error) {
	if depth > 128 {
		return nil, fmt.Errorf("vendor OVAL nesting exceeds limit")
	}
	node := &ovalNode{name: start.Name.Local, attrs: make(map[string]string, len(start.Attr))}
	for _, attr := range start.Attr {
		if isOVALNamespaceDeclaration(attr) || isOVALSchemaLocation(start.Name.Local, attr) {
			continue
		}
		if _, exists := node.attrs[attr.Name.Local]; exists {
			return nil, fmt.Errorf("vendor OVAL element %q has duplicate attribute %q", start.Name.Local, attr.Name.Local)
		}
		if attr.Name.Space != "" {
			return nil, fmt.Errorf("vendor OVAL element %q has qualified attribute %q", start.Name.Local, attr.Name.Local)
		}
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
	if (node.name == "textfilecontent54_test" || node.name == "uname_test") && (!onlyOVALAttributes(node.attrs, "id", "version", "check", "check_existence", "comment") || node.attrs["negate"] != "") {
		return ovalTest{}, fmt.Errorf("vendor OVAL test %q has unsupported applicability-guard attributes", id)
	}
	objectRefs := make([]string, 0, 1)
	stateRefs := make([]string, 0, 1)
	for _, child := range node.children {
		switch child.name {
		case "object":
			if len(child.children) != 0 || child.text != "" || len(child.attrs) != 1 || child.attrs["object_ref"] == "" {
				return ovalTest{}, fmt.Errorf("vendor OVAL test %q has an invalid object reference", id)
			}
			objectRefs = append(objectRefs, child.attrs["object_ref"])
		case "state":
			if len(child.children) != 0 || child.text != "" || len(child.attrs) != 1 || child.attrs["state_ref"] == "" {
				return ovalTest{}, fmt.Errorf("vendor OVAL test %q has an invalid state reference", id)
			}
			stateRefs = append(stateRefs, child.attrs["state_ref"])
		default:
			return ovalTest{}, fmt.Errorf("vendor OVAL test %q has an unsupported child", id)
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
	negate := strings.ToLower(strings.TrimSpace(node.attrs["negate"]))
	if negate != "" && negate != "false" {
		return ovalTest{}, fmt.Errorf("vendor OVAL test %q has unsupported check, existence, negation, or references", id)
	}
	if (existence != "at_least_one_exists" && existence != "all_exist") || len(objectRefs) != 1 || objectRefs[0] == "" {
		return ovalTest{}, fmt.Errorf("vendor OVAL test %q has unsupported check, existence, negation, or references", id)
	}
	if node.name == "uname_test" {
		if strings.ToLower(check) != "all" || len(stateRefs) != 0 {
			return ovalTest{}, fmt.Errorf("vendor OVAL test %q has unsupported check, existence, negation, or references", id)
		}
		return ovalTest{id: id, kind: node.name, check: check, existence: existence, comment: node.attrs["comment"], objectID: objectRefs[0], objectIDs: objectRefs}, nil
	}
	if len(stateRefs) != 1 || stateRefs[0] == "" {
		return ovalTest{}, fmt.Errorf("vendor OVAL test %q has unsupported check, existence, negation, or references", id)
	}
	if strings.ToLower(check) != "all" && !(node.name == "rpminfo_test" && check == "at least one") {
		return ovalTest{}, fmt.Errorf("vendor OVAL test %q has unsupported check, existence, negation, or references", id)
	}
	return ovalTest{id: id, kind: node.name, check: check, existence: existence, comment: node.attrs["comment"], objectID: objectRefs[0], objectIDs: objectRefs, stateID: stateRefs[0], stateIDs: stateRefs}, nil
}

func onlyOVALAttributes(attrs map[string]string, allowed ...string) bool {
	known := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		known[name] = struct{}{}
	}
	for name := range attrs {
		if _, exists := known[name]; !exists {
			return false
		}
	}
	return true
}

func parseOVALObject(node *ovalNode) (ovalObject, error) {
	if node.attrs["id"] == "" {
		return ovalObject{}, fmt.Errorf("vendor OVAL object has no id")
	}
	switch node.name {
	case "textfilecontent54_object":
		return parseDebianReleaseObject(node)
	case "uname_object":
		if !onlyOVALAttributes(node.attrs, "id", "version") || len(node.children) != 0 {
			return ovalObject{}, fmt.Errorf("vendor OVAL uname object %q is not empty", node.attrs["id"])
		}
		return ovalObject{id: node.attrs["id"], kind: node.name, guards: map[string]string{}, debianUnameGuard: true}, nil
	}
	object := ovalObject{id: node.attrs["id"], kind: node.name, guards: map[string]string{}}
	for _, child := range node.children {
		value := strings.TrimSpace(child.text)
		if len(child.children) != 0 {
			return ovalObject{}, fmt.Errorf("vendor OVAL object %q has nested child semantics", object.id)
		}
		switch child.name {
		case "name":
			if object.name != "" || value == "" || len(child.attrs) > 1 || (child.attrs["operation"] != "" && child.attrs["operation"] != "equals") {
				return ovalObject{}, fmt.Errorf("vendor OVAL object %q has an ambiguous package name", object.id)
			}
			object.name = value
			object.names = append(object.names, value)
		case "arch", "product", "release":
			if value == "" || object.guards[child.name] != "" || len(child.attrs) > 1 || (child.attrs["operation"] != "" && child.attrs["operation"] != "equals") {
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

func parseDebianReleaseObject(node *ovalNode) (ovalObject, error) {
	object := ovalObject{id: node.attrs["id"], kind: node.name, guards: map[string]string{}}
	if !onlyOVALAttributes(node.attrs, "id", "version") {
		return ovalObject{}, fmt.Errorf("vendor OVAL Debian release object %q has unsupported attributes", object.id)
	}
	fields := make(map[string]*ovalNode, len(node.children))
	for _, child := range node.children {
		if len(child.children) != 0 {
			return ovalObject{}, fmt.Errorf("vendor OVAL Debian release object %q has nested fields", object.id)
		}
		if _, exists := fields[child.name]; exists {
			return ovalObject{}, fmt.Errorf("vendor OVAL Debian release object %q duplicates %s", object.id, child.name)
		}
		fields[child.name] = child
	}
	if len(fields) != 4 || fields["path"] == nil || fields["filename"] == nil || fields["pattern"] == nil || fields["instance"] == nil {
		return ovalObject{}, fmt.Errorf("vendor OVAL Debian release object %q has unsupported fields", object.id)
	}
	if fields["path"].text != "/etc" || len(fields["path"].attrs) != 0 || fields["filename"].text != "debian_version" || len(fields["filename"].attrs) != 0 || fields["pattern"].text != `(\d+)\.\d` || fields["pattern"].attrs["operation"] != "pattern match" || len(fields["pattern"].attrs) != 1 || fields["instance"].text != "1" || fields["instance"].attrs["datatype"] != "int" || len(fields["instance"].attrs) != 1 {
		return ovalObject{}, fmt.Errorf("vendor OVAL Debian release object %q has unsupported release-file semantics", object.id)
	}
	object.debianReleaseGuard = true
	return object, nil
}

func parseOVALState(node *ovalNode) (ovalState, error) {
	if node.attrs["id"] == "" {
		return ovalState{}, fmt.Errorf("vendor OVAL state has no id")
	}
	if node.name == "textfilecontent54_state" {
		return parseDebianReleaseState(node)
	}
	negate := strings.TrimSpace(node.attrs["negate"])
	if negate != "" && !strings.EqualFold(negate, "false") {
		return ovalState{}, fmt.Errorf("vendor OVAL state %q has unsupported negation", node.attrs["id"])
	}
	state := ovalState{id: node.attrs["id"], kind: node.name, operator: node.attrs["operator"], guards: map[string]string{}}
	if state.operator == "" {
		state.operator = "AND"
	}
	if state.operator != "AND" {
		return ovalState{}, fmt.Errorf("vendor OVAL state %q does not use positive AND", state.id)
	}
	for _, child := range node.children {
		value := strings.TrimSpace(child.text)
		if len(child.children) != 0 {
			return ovalState{}, fmt.Errorf("vendor OVAL state %q has nested child semantics", state.id)
		}
		switch child.name {
		case "evr":
			if state.predicateKind != "" || value == "" || !onlyOVALAttributes(child.attrs, "operation", "datatype") {
				return ovalState{}, fmt.Errorf("vendor OVAL state %q has an unsupported version range", state.id)
			}
			operation := child.attrs["operation"]
			if operation != "less than" && operation != "greater than" {
				return ovalState{}, fmt.Errorf("vendor OVAL state %q has an unsupported version range", state.id)
			}
			expectedDatatype := ""
			switch node.name {
			case "dpkginfo_state":
				expectedDatatype = "debian_evr_string"
			case "rpminfo_state":
				expectedDatatype = "evr_string"
			default:
				return ovalState{}, fmt.Errorf("vendor OVAL state %q has an unsupported EVR family", state.id)
			}
			if datatype, present := child.attrs["datatype"]; present && datatype != expectedDatatype {
				return ovalState{}, fmt.Errorf("vendor OVAL state %q has an unsupported EVR datatype", state.id)
			}
			state.predicateKind = bench.NativePredicateEVRLessThan
			if operation == "greater than" {
				if node.name != "rpminfo_state" {
					return ovalState{}, fmt.Errorf("vendor OVAL state %q has an unsupported version range", state.id)
				}
				state.predicateKind = bench.NativePredicateEVRGreaterThan
			}
			state.predicateValue = value
		case "version":
			if state.predicateKind != "" || value == "" || child.attrs["operation"] != "equals" || len(child.attrs) != 1 {
				return ovalState{}, fmt.Errorf("vendor OVAL state %q has an unsupported version equality", state.id)
			}
			state.predicateKind = "version_equals"
			state.predicateValue = value
		case "arch":
			if child.attrs["operation"] == "pattern match" {
				if node.name != "rpminfo_state" || !onlyOVALAttributes(child.attrs, "operation", "datatype") || child.attrs["datatype"] != "string" || value == "" || state.guards["arch"] != "" || len(state.architectures) != 0 {
					return ovalState{}, fmt.Errorf("vendor OVAL state %q has an unsupported architecture guard", state.id)
				}
				architectures, valid := parseSLESArchitectureAlternation(value)
				if !valid {
					return ovalState{}, fmt.Errorf("vendor OVAL state %q has an unsupported architecture guard", state.id)
				}
				state.architectures = architectures
				continue
			}
			fallthrough
		case "product", "release":
			operation := child.attrs["operation"]
			if len(child.attrs) > 1 || (operation != "" && operation != "equals") || value == "" || state.guards[child.name] != "" {
				return ovalState{}, fmt.Errorf("vendor OVAL state %q has an unsupported %s guard", state.id, child.name)
			}
			state.guards[child.name] = value
		default:
			state.unknown = append(state.unknown, child.name)
		}
	}
	if state.predicateKind == "" {
		return ovalState{}, fmt.Errorf("vendor OVAL state %q has no supported predicate", state.id)
	}
	return state, nil
}

func parseSLESArchitectureAlternation(value string) (map[string]struct{}, bool) {
	if len(value) < 5 || !strings.HasPrefix(value, "(") || !strings.HasSuffix(value, ")") {
		return nil, false
	}
	values := strings.Split(value[1:len(value)-1], "|")
	if len(values) < 2 || len(values) > 5 {
		return nil, false
	}
	architectures := make(map[string]struct{}, len(values))
	for _, architecture := range values {
		switch architecture {
		case "aarch64", "i586", "ppc64le", "s390x", "x86_64":
		default:
			return nil, false
		}
		if _, exists := architectures[architecture]; exists {
			return nil, false
		}
		architectures[architecture] = struct{}{}
	}
	return architectures, true
}

func parseDebianReleaseState(node *ovalNode) (ovalState, error) {
	state := ovalState{id: node.attrs["id"], kind: node.name, guards: map[string]string{}}
	if !onlyOVALAttributes(node.attrs, "id", "version") || len(node.children) != 1 {
		return ovalState{}, fmt.Errorf("vendor OVAL Debian release state %q has unsupported semantics", state.id)
	}
	child := node.children[0]
	if child.name != "subexpression" || len(child.children) != 0 || child.attrs["operation"] != "equals" || len(child.attrs) != 1 || strings.TrimSpace(child.text) == "" {
		return ovalState{}, fmt.Errorf("vendor OVAL Debian release state %q has unsupported semantics", state.id)
	}
	state.debianReleaseGuard = true
	state.predicateValue = child.text
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
	truths      []bench.Truth
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
		return evaluator.evaluateTest(testID, node.attrs["comment"])
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
			result := ovalResult{applicable: true}
			for _, child := range node.children {
				childResult, err := evaluator.evaluate(child)
				if err != nil {
					return ovalResult{}, err
				}
				result.unsupported = append(result.unsupported, childResult.unsupported...)
				if !childResult.applicable {
					result.applicable = false
				}
				result.truths = appendOVALTruths(result.truths, childResult.truths...)
				result.records = append(result.records, childResult.records...)
			}
			return result, nil
		}

		// A complete affected witness wins an OR in source order. If a supported
		// applicability guard is true, the OR is already true; it remains available
		// for an enclosing AND while evaluation continues for an affected package
		// predicate. Without either witness, every applicable branch must remain
		// supported and agree on fixed versus explicitly not-affected.
		result := ovalResult{}
		var guardWitness *ovalResult
		for _, child := range node.children {
			childResult, err := evaluator.evaluate(child)
			if err != nil {
				return ovalResult{}, err
			}
			if !childResult.applicable {
				continue
			}
			if truth, complete := completeOVALTruth(childResult); complete && truth == bench.TruthAffected && len(childResult.unsupported) == 0 {
				return childResult, nil
			}
			if len(childResult.records) == 0 && len(childResult.truths) == 0 && len(childResult.unsupported) == 0 {
				if guardWitness == nil {
					witness := childResult
					guardWitness = &witness
				}
				continue
			}
			if guardWitness != nil {
				continue
			}
			result.applicable = true
			result.unsupported = append(result.unsupported, childResult.unsupported...)
			result.truths = appendOVALTruths(result.truths, childResult.truths...)
			result.records = append(result.records, childResult.records...)
			if len(childResult.records) == 0 && len(childResult.unsupported) == 0 {
				result.unsupported = append(result.unsupported, &ovalUnsupportedError{kind: "criteria", id: node.name, reason: "OR branch has no package version predicate"})
			}
		}
		if guardWitness != nil {
			return *guardWitness, nil
		}
		if len(result.unsupported) == 0 && len(result.truths) > 1 {
			result.unsupported = append(result.unsupported, &ovalUnsupportedError{kind: "criteria", id: node.name, reason: "OR branches disagree on negative disposition"})
		}
		return result, nil
	default:
		return unsupportedOVALResult("criteria", node.name, "criteria has an unsupported child"), nil
	}
}

func appendOVALTruths(existing []bench.Truth, values ...bench.Truth) []bench.Truth {
	for _, value := range values {
		if value == "" {
			continue
		}
		seen := false
		for _, present := range existing {
			if present == value {
				seen = true
				break
			}
		}
		if !seen {
			existing = append(existing, value)
		}
	}
	return existing
}

func completeOVALTruth(result ovalResult) (bench.Truth, bool) {
	if len(result.truths) != 1 || len(result.records) == 0 {
		return "", false
	}
	return result.truths[0], true
}

func unsupportedOVALResult(kind, id, reason string) ovalResult {
	return ovalResult{applicable: true, unsupported: []*ovalUnsupportedError{{kind: kind, id: id, reason: reason}}}
}

func (evaluator ovalEvaluator) evaluateTest(testID, criterionComment string) (ovalResult, error) {
	test, exists := evaluator.document.tests[testID]
	if !exists {
		return unsupportedOVALResult("test", testID, "test is missing"), nil
	}
	switch test.kind {
	case "textfilecontent54_test":
		return evaluator.evaluateDebianReleaseGuard(test)
	case "uname_test":
		return evaluator.evaluateDebianUnameGuard(test)
	case "rpminfo_test":
		if object, exists := evaluator.document.objects[test.objectID]; exists && strings.HasSuffix(object.name, "-release") {
			return evaluator.evaluateSLESReleaseGuard(test, object)
		}
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
	if test.kind == "rpminfo_test" && test.check == "at least one" && evaluator.selection.Product != "sles" {
		return unsupportedOVALResult("test", testID, "SLES-only check semantics do not apply to this target"), nil
	}
	if (evaluator.selection.PackageFamily == "deb" && test.kind != "dpkginfo_test") || (evaluator.selection.PackageFamily == "rpm" && test.kind != "rpminfo_test") {
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
	if len(state.architectures) != 0 {
		if _, matches := state.architectures[evaluator.selection.Architecture]; !matches {
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

	predicateKind := state.predicateKind
	rightEVR := state.predicateValue
	if predicateKind == "version_equals" {
		if evaluator.selection.PackageFamily != "rpm" || rightEVR != "0" || !slesZeroSentinelCorroborated(test.comment, criterionComment, object.name) {
			return unsupportedOVALResult("state", state.id, "version equality is not the explicit corroborated SLES not-affected sentinel"), nil
		}
		version, err := rpmVersionFromEVR(candidateEVR)
		if err != nil {
			return unsupportedOVALResult("state", state.id, "not-affected sentinel has an invalid RPM package version"), nil
		}
		candidateEVR = version
		predicateKind = bench.NativePredicateVersionEqualsZero
		rightEVR = "0"
	}
	if predicateKind != bench.NativePredicateEVRLessThan && predicateKind != bench.NativePredicateEVRGreaterThan && predicateKind != bench.NativePredicateVersionEqualsZero {
		return unsupportedOVALResult("state", state.id, "state predicate is unsupported"), nil
	}
	if evaluator.selection.PackageFamily == "deb" && predicateKind == bench.NativePredicateEVRLessThan && rightEVR == "0:0" {
		return unsupportedOVALResult("state", state.id, "Debian zero boundary does not establish an affected or remediated version range"), nil
	}

	family := ports.NativePackageDeb
	method := "target-native-dpkg"
	if evaluator.selection.PackageFamily == "rpm" {
		family = ports.NativePackageRPM
		method = "target-native-rpm"
		if predicateKind != bench.NativePredicateVersionEqualsZero {
			canonicalCandidate, err := canonicalRPMEVR(candidateEVR)
			if err != nil {
				return unsupportedOVALResult("state", state.id, "candidate RPM EVR cannot be canonicalized"), nil
			}
			canonicalBoundary, err := canonicalRPMEVR(rightEVR)
			if err != nil {
				return unsupportedOVALResult("state", state.id, "boundary RPM EVR cannot be canonicalized"), nil
			}
			candidateEVR = canonicalCandidate
			rightEVR = canonicalBoundary
		}
	}
	comparison, err := evaluator.comparator.CompareNativeVersion(evaluator.ctx, ports.NativeVersionComparisonRequest{TargetDigest: evaluator.target.Digest, Family: family, LeftEVR: candidateEVR, RightEVR: rightEVR})
	if err != nil {
		return ovalResult{}, fmt.Errorf("target-native comparison for test %q: %w", testID, err)
	}
	relation, err := nativeRelation(comparison.Relation)
	if err != nil {
		return ovalResult{}, fmt.Errorf("target-native comparison for test %q: %w", testID, err)
	}
	record := bench.NativeComparisonRecord{SchemaVersion: bench.NativeComparisonSchemaVersion, ID: evaluator.target.ID + "::" + testID, TargetID: evaluator.target.ID, TargetDigest: evaluator.target.Digest, PackageFamily: evaluator.selection.PackageFamily, PackageIdentity: packageIdentity, CandidateEVR: candidateEVR, FixedEVR: rightEVR, PredicateKind: predicateKind, Relation: relation, Method: method, ExecutionDigest: comparison.ExecutionDigest}
	if err := record.Validate(); err != nil {
		return ovalResult{}, err
	}
	if predicateKind == bench.NativePredicateVersionEqualsZero {
		if relation == "equal" {
			return unsupportedOVALResult("state", state.id, "not-affected sentinel collides with the exact target package version"), nil
		}
		return ovalResult{applicable: true, truths: []bench.Truth{bench.TruthNotAffected}, records: []bench.NativeComparisonRecord{record}}, nil
	}
	truth := bench.TruthFixed
	if (predicateKind == bench.NativePredicateEVRLessThan && relation == "before") || (predicateKind == bench.NativePredicateEVRGreaterThan && relation == "after") {
		truth = bench.TruthAffected
	}
	return ovalResult{applicable: true, truths: []bench.Truth{truth}, records: []bench.NativeComparisonRecord{record}}, nil
}

func (evaluator ovalEvaluator) evaluateDebianReleaseGuard(test ovalTest) (ovalResult, error) {
	if test.unsupported != "" {
		return unsupportedOVALResult("test", test.id, test.unsupported), nil
	}
	object, exists := evaluator.document.objects[test.objectID]
	if !exists {
		return unsupportedOVALResult("object", test.objectID, "object is missing"), nil
	}
	state, exists := evaluator.document.states[test.stateID]
	if !exists {
		return unsupportedOVALResult("state", test.stateID, "state is missing"), nil
	}
	if object.unsupported != "" || !object.debianReleaseGuard || state.unsupported != "" || !state.debianReleaseGuard {
		return unsupportedOVALResult("test", test.id, "test is not the supported Debian release-file guard"), nil
	}
	if evaluator.selection.PackageFamily != "deb" || evaluator.selection.Product != "debian" || state.predicateValue != evaluator.selection.Release {
		return ovalResult{}, nil
	}
	return ovalResult{applicable: true}, nil
}

func (evaluator ovalEvaluator) evaluateDebianUnameGuard(test ovalTest) (ovalResult, error) {
	if test.unsupported != "" {
		return unsupportedOVALResult("test", test.id, test.unsupported), nil
	}
	object, exists := evaluator.document.objects[test.objectID]
	if !exists {
		return unsupportedOVALResult("object", test.objectID, "object is missing"), nil
	}
	if object.unsupported != "" || !object.debianUnameGuard {
		return unsupportedOVALResult("test", test.id, "test is not the supported architecture-independent Debian uname guard"), nil
	}
	if evaluator.selection.PackageFamily != "deb" || evaluator.selection.Product != "debian" {
		return ovalResult{}, nil
	}
	return ovalResult{applicable: true}, nil
}

func (evaluator ovalEvaluator) evaluateSLESReleaseGuard(test ovalTest, object ovalObject) (ovalResult, error) {
	if test.unsupported != "" || object.unsupported != "" || object.kind != "rpminfo_object" || len(object.unknown) != 0 || len(object.guards) != 0 {
		return unsupportedOVALResult("test", test.id, "test is not the supported SLES release-package guard"), nil
	}
	state, exists := evaluator.document.states[test.stateID]
	if !exists {
		return unsupportedOVALResult("state", test.stateID, "state is missing"), nil
	}
	if state.unsupported != "" || len(state.unknown) != 0 || len(state.guards) != 0 || len(state.architectures) != 0 || state.predicateKind != "version_equals" {
		return unsupportedOVALResult("state", test.stateID, "state is not the supported SLES release-package guard"), nil
	}
	if evaluator.selection.PackageFamily != "rpm" || evaluator.selection.Product != "sles" || state.predicateValue != evaluator.selection.Release {
		return ovalResult{}, nil
	}
	version, present, err := slesCatalogReleaseVersion(evaluator.target, object.name)
	if err != nil {
		return unsupportedOVALResult("object", object.id, err.Error()), nil
	}
	if !present {
		if object.name == "sles-release" {
			return unsupportedOVALResult("object", object.id, "SLES primary release package is missing from the exact catalog target"), nil
		}
		return ovalResult{}, nil
	}
	if version != evaluator.selection.Release || version != state.predicateValue {
		return ovalResult{}, nil
	}
	return ovalResult{applicable: true}, nil
}

func slesZeroSentinelCorroborated(testComment, criterionComment, packageName string) bool {
	return strings.EqualFold(strings.TrimSpace(testComment), packageName+" is ==0") && strings.EqualFold(strings.TrimSpace(criterionComment), packageName+" is not affected")
}

func nativeRelation(relation int) (string, error) {
	switch relation {
	case -1:
		return "before", nil
	case 0:
		return "equal", nil
	case 1:
		return "after", nil
	default:
		return "", fmt.Errorf("returned an invalid relation")
	}
}

func slesCatalogReleaseVersion(target bench.Target, releasePackage string) (string, bool, error) {
	matches := make([]bench.Component, 0, 1)
	for _, component := range target.Components {
		family, name, err := catalogPackageIdentity(component.PURL)
		if err != nil || name != releasePackage {
			continue
		}
		if family != "rpm" {
			return "", false, fmt.Errorf("SLES release package %q has a non-RPM catalog identity", releasePackage)
		}
		matches = append(matches, component)
	}
	if len(matches) == 0 {
		return "", false, nil
	}
	if len(matches) != 1 {
		return "", true, fmt.Errorf("SLES release package %q is duplicate or conflicting in the exact catalog target", releasePackage)
	}
	version, err := rpmVersionFromEVR(matches[0].Version)
	if err != nil {
		return "", true, fmt.Errorf("SLES release package %q has an invalid catalog EVR: %w", releasePackage, err)
	}
	return version, true, nil
}

func catalogPackageIdentity(purl string) (string, string, error) {
	value := strings.TrimSpace(purl)
	if !strings.HasPrefix(value, "pkg:") {
		return "", "", fmt.Errorf("catalog component has an invalid purl")
	}
	value = value[len("pkg:"):]
	if delimiter := strings.IndexAny(value, "?#"); delimiter >= 0 {
		value = value[:delimiter]
	}
	separator := strings.IndexByte(value, '/')
	if separator <= 0 || separator == len(value)-1 {
		return "", "", fmt.Errorf("catalog component has an invalid purl")
	}
	family, err := url.PathUnescape(value[:separator])
	if err != nil {
		return "", "", fmt.Errorf("catalog component has an invalid package family")
	}
	packagePath := value[separator+1:]
	if at := strings.LastIndexByte(packagePath, '@'); at >= 0 {
		packagePath = packagePath[:at]
	}
	packageName, err := url.PathUnescape(packagePath)
	if err != nil || packageName == "" {
		return "", "", fmt.Errorf("catalog component has an invalid package name")
	}
	if slash := strings.LastIndexByte(packageName, '/'); slash >= 0 {
		packageName = packageName[slash+1:]
	}
	if packageName == "" {
		return "", "", fmt.Errorf("catalog component has an invalid package name")
	}
	return family, packageName, nil
}

func rpmVersionFromEVR(evr string) (string, error) {
	if strings.TrimSpace(evr) != evr || evr == "" || strings.ContainsAny(evr, "\t\n\r ") {
		return "", fmt.Errorf("EVR is empty or contains whitespace")
	}
	version := evr
	if epochEnd := strings.IndexByte(version, ':'); epochEnd >= 0 {
		epoch := version[:epochEnd]
		if epoch == "" || !decimalOVAL(epoch) || strings.Count(version, ":") != 1 {
			return "", fmt.Errorf("EVR has an invalid epoch")
		}
		version = version[epochEnd+1:]
	}
	if releaseStart := strings.IndexByte(version, '-'); releaseStart >= 0 {
		if releaseStart == 0 || releaseStart == len(version)-1 || strings.Count(version, "-") != 1 {
			return "", fmt.Errorf("EVR has an invalid release")
		}
		version = version[:releaseStart]
	}
	if version == "" || strings.ContainsAny(version, ":-") {
		return "", fmt.Errorf("EVR has an invalid version")
	}
	return version, nil
}

func ovalResultTruth(result ovalResult) (bench.Truth, error) {
	if !result.applicable {
		return "", fmt.Errorf("vendor OVAL branch is not applicable")
	}
	if len(result.unsupported) != 0 {
		return "", fmt.Errorf("vendor OVAL branch retains unsupported semantics")
	}
	truth, complete := completeOVALTruth(result)
	if !complete {
		return "", fmt.Errorf("vendor OVAL branch has split or missing package version predicates")
	}
	for _, record := range result.records {
		if err := record.Validate(); err != nil {
			return "", err
		}
		switch truth {
		case bench.TruthAffected:
			if (record.PredicateKind != "" && record.PredicateKind != bench.NativePredicateEVRLessThan && record.PredicateKind != bench.NativePredicateEVRGreaterThan) || (record.PredicateKind != bench.NativePredicateEVRGreaterThan && record.Relation != "before") || (record.PredicateKind == bench.NativePredicateEVRGreaterThan && record.Relation != "after") {
				return "", fmt.Errorf("vendor OVAL affected branch has non-affected native evidence")
			}
		case bench.TruthFixed:
			if (record.PredicateKind != "" && record.PredicateKind != bench.NativePredicateEVRLessThan && record.PredicateKind != bench.NativePredicateEVRGreaterThan) || (record.PredicateKind != bench.NativePredicateEVRGreaterThan && record.Relation == "before") || (record.PredicateKind == bench.NativePredicateEVRGreaterThan && record.Relation == "after") {
				return "", fmt.Errorf("vendor OVAL fixed branch has incompatible native evidence")
			}
		case bench.TruthNotAffected:
			if record.PredicateKind != bench.NativePredicateVersionEqualsZero || record.Relation == "equal" {
				return "", fmt.Errorf("vendor OVAL not-affected branch has a zero-sentinel collision")
			}
		default:
			return "", fmt.Errorf("vendor OVAL branch has an invalid disposition")
		}
	}
	return truth, nil
}
