package scabench

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"
)

const (
	// SourceEvidencePlanSchemaVersion describes scanner-free, reviewable source
	// selection. It intentionally contains no truth labels, CVE selection, OVAL
	// definition selection, or version relations.
	SourceEvidencePlanSchemaVersion = "synapse-sca-benchmark-source-evidence-plan-v4"
	SourceCaseEvidenceSchemaVersion = "synapse-sca-benchmark-source-case-evidence-v3"
	NativeEvidenceSetSchemaVersion  = "synapse-sca-benchmark-native-evidence-v2"
)

// SourceEvidencePlan selects frozen vendor OVAL assets and a target package
// allowlist. The builder emits every safely evaluable vendor definition that
// applies to each selected package; it never accepts CVE or definition
// cherry-picking from the plan.
type SourceEvidencePlan struct {
	SchemaVersion      string                 `json:"schema_version"`
	CycleID            string                 `json:"cycle_id"`
	SourceFreezeDigest string                 `json:"source_freeze_digest"`
	Targets            []SourceEvidenceTarget `json:"targets"`
}

type SourceEvidenceTarget struct {
	TargetID           string                  `json:"target_id"`
	SourceAssetLocator string                  `json:"source_asset_locator"`
	PackageFamily      string                  `json:"package_family"`
	Release            string                  `json:"release"`
	Product            string                  `json:"product"`
	Architecture       string                  `json:"architecture"`
	Packages           []SourceEvidencePackage `json:"packages"`
}

type SourceEvidencePackage struct {
	Name          string    `json:"name"`
	Component     Component `json:"component"`
	Architecture  string    `json:"architecture"`
	Distro        string    `json:"distro"`
	Release       string    `json:"release"`
	SourcePackage string    `json:"source_package"`
	SourceEVR     string    `json:"source_evr"`
}

func (plan SourceEvidencePlan) Validate() error {
	if plan.SchemaVersion != SourceEvidencePlanSchemaVersion {
		return fmt.Errorf("unsupported source evidence plan schema %q", plan.SchemaVersion)
	}
	if err := validateCycleID(plan.CycleID); err != nil {
		return err
	}
	if !validSHA256Digest(plan.SourceFreezeDigest) || len(plan.Targets) == 0 {
		return fmt.Errorf("source evidence plan requires a frozen source digest and targets")
	}
	seenTargets := make(map[string]struct{}, len(plan.Targets))
	for _, target := range plan.Targets {
		if strings.TrimSpace(target.TargetID) == "" || containsControlCharacter(target.TargetID) || strings.TrimSpace(target.SourceAssetLocator) == "" || strings.TrimSpace(target.Release) == "" || strings.TrimSpace(target.Product) == "" || strings.TrimSpace(target.Architecture) == "" {
			return fmt.Errorf("source evidence target is incomplete")
		}
		if target.PackageFamily != "deb" && target.PackageFamily != "rpm" {
			return fmt.Errorf("source evidence target %q has an invalid package family", target.TargetID)
		}
		if _, exists := seenTargets[target.TargetID]; exists {
			return fmt.Errorf("source evidence plan has duplicate target %q", target.TargetID)
		}
		seenTargets[target.TargetID] = struct{}{}
		if len(target.Packages) == 0 {
			return fmt.Errorf("source evidence target %q requires packages", target.TargetID)
		}
		seenPackages := make(map[string]struct{}, len(target.Packages))
		for _, item := range target.Packages {
			if strings.TrimSpace(item.Name) == "" || containsControlCharacter(item.Name) {
				return fmt.Errorf("source evidence target %q has an invalid package name", target.TargetID)
			}
			if _, exists := seenPackages[item.Name]; exists {
				return fmt.Errorf("source evidence target %q has duplicate package %q", target.TargetID, item.Name)
			}
			seenPackages[item.Name] = struct{}{}
			if err := validateSourcePackageBinding(target, item); err != nil {
				return fmt.Errorf("source evidence target %q package %q: %w", target.TargetID, item.Name, err)
			}
		}
	}
	return nil
}

func validateSourcePackageBinding(target SourceEvidenceTarget, item SourceEvidencePackage) error {
	identity, err := componentIdentityKey(item.Component)
	if err != nil {
		return fmt.Errorf("component: %w", err)
	}
	if identity.Ecosystem != target.PackageFamily {
		return fmt.Errorf("component purl type %q does not match package family %q", identity.Ecosystem, target.PackageFamily)
	}
	packageName := identity.Package
	if separator := strings.LastIndexByte(packageName, '/'); separator >= 0 {
		packageName = packageName[separator+1:]
	}
	if item.Name != packageName {
		return fmt.Errorf("package name does not match the component purl basename")
	}
	if item.Component.Version != identity.Version {
		return fmt.Errorf("component version does not match the component purl")
	}
	if !validSourceBindingValue(item.SourcePackage) || !validSourceBindingValue(item.SourceEVR) {
		return fmt.Errorf("upstream source name and EVR are required")
	}
	mapping, err := sourceMappingFromPURL(item.Component.PURL)
	if err != nil {
		return err
	}
	if item.Architecture != target.Architecture || item.Architecture != mapping.architecture {
		return fmt.Errorf("package architecture must bind the selected target and component purl")
	}
	if item.Distro != mapping.distro || item.Release != target.Release {
		return fmt.Errorf("package distro and release must bind the component purl and selected target")
	}
	if mapping.distro != target.Product+"-"+target.Release {
		return fmt.Errorf("component purl distro must bind the selected target product and release")
	}
	expectedUpstream := item.SourcePackage + "@" + item.SourceEVR
	if target.PackageFamily == "rpm" {
		expectedUpstream = item.SourcePackage + "-" + item.SourceEVR + ".src.rpm"
	}
	if mapping.upstream != expectedUpstream {
		return fmt.Errorf("component purl upstream does not exactly bind the source package and EVR")
	}
	return nil
}

type sourcePURLMapping struct {
	architecture string
	distro       string
	upstream     string
}

func sourceMappingFromPURL(purl string) (sourcePURLMapping, error) {
	queryOffset := strings.IndexByte(purl, '?')
	if queryOffset < 0 || queryOffset == len(purl)-1 {
		return sourcePURLMapping{}, fmt.Errorf("component purl requires arch, distro, and upstream qualifiers")
	}
	queryEnd := len(purl)
	if fragmentOffset := strings.IndexByte(purl[queryOffset+1:], '#'); fragmentOffset >= 0 {
		queryEnd = queryOffset + 1 + fragmentOffset
	}
	query, err := url.ParseQuery(purl[queryOffset+1 : queryEnd])
	if err != nil {
		return sourcePURLMapping{}, fmt.Errorf("component purl source mapping: %w", err)
	}
	architectures := query["arch"]
	distros := query["distro"]
	upstreams := query["upstream"]
	if len(architectures) != 1 || len(distros) != 1 || len(upstreams) != 1 || !validSourceBindingValue(architectures[0]) || !validSourceBindingValue(distros[0]) || !validSourceBindingValue(upstreams[0]) {
		return sourcePURLMapping{}, fmt.Errorf("component purl requires one nonempty arch, distro, and upstream qualifier")
	}
	return sourcePURLMapping{architecture: architectures[0], distro: distros[0], upstream: upstreams[0]}, nil
}

func validSourceBindingValue(value string) bool {
	return strings.TrimSpace(value) != "" && !containsControlCharacter(value) && !strings.ContainsFunc(value, unicode.IsSpace)
}

// SourceCaseEvidenceSet is generated from the frozen vendor source by the
// benchmark-only evaluator. It records derived source truth and references the
// independently executed target-native evidence set used to derive it.
type SourceCaseEvidenceSet struct {
	SchemaVersion        string                     `json:"schema_version"`
	CycleID              string                     `json:"cycle_id"`
	SourceFreezeDigest   string                     `json:"source_freeze_digest"`
	NativeEvidenceDigest string                     `json:"native_evidence_digest"`
	Cases                []SourceCaseEvidence       `json:"cases"`
	Unsupported          []SourceEvidenceDiagnostic `json:"unsupported,omitempty"`
}

// SourceEvidenceDiagnostic retains a matching vendor branch that cannot safely
// contribute source truth. Diagnostics are evidence of blocked evaluation, not
// an inferred fixed result.
type SourceEvidenceDiagnostic struct {
	TargetID     string    `json:"target_id"`
	Component    Component `json:"component"`
	DefinitionID string    `json:"definition_id"`
	ElementKind  string    `json:"element_kind"`
	ElementID    string    `json:"element_id"`
	Reason       string    `json:"reason"`
}

type SourceCaseEvidence struct {
	ID                  string             `json:"id"`
	TargetID            string             `json:"target_id"`
	Component           Component          `json:"component"`
	AdvisoryID          string             `json:"advisory_id"`
	DerivedTruth        Truth              `json:"derived_truth"`
	NativeComparisonIDs []string           `json:"native_comparison_ids"`
	Rationale           string             `json:"rationale"`
	Citations           []ContentReference `json:"citations"`
}

func (set SourceCaseEvidenceSet) Validate() error {
	if set.SchemaVersion != SourceCaseEvidenceSchemaVersion {
		return fmt.Errorf("unsupported source case evidence schema %q", set.SchemaVersion)
	}
	if err := validateCycleID(set.CycleID); err != nil {
		return err
	}
	if !validSHA256Digest(set.SourceFreezeDigest) || !validSHA256Digest(set.NativeEvidenceDigest) || (len(set.Cases) == 0 && len(set.Unsupported) == 0) {
		return fmt.Errorf("source case evidence requires frozen source, native evidence, and cases or unsupported diagnostics")
	}
	seen := make(map[string]struct{}, len(set.Cases))
	for _, item := range set.Cases {
		if strings.TrimSpace(item.ID) == "" || strings.TrimSpace(item.TargetID) == "" || containsControlCharacter(item.ID) || containsControlCharacter(item.TargetID) {
			return fmt.Errorf("source case evidence requires a non-control id and target id")
		}
		if _, exists := seen[item.ID]; exists {
			return fmt.Errorf("source case evidence has duplicate case %q", item.ID)
		}
		seen[item.ID] = struct{}{}
		if _, err := componentIdentityKey(item.Component); err != nil || strings.TrimSpace(item.AdvisoryID) == "" || strings.TrimSpace(item.Rationale) == "" {
			return fmt.Errorf("source case evidence %q is incomplete", item.ID)
		}
		if item.DerivedTruth != TruthAffected && item.DerivedTruth != TruthFixed && item.DerivedTruth != TruthNotAffected {
			return fmt.Errorf("source case evidence %q must derive affected, fixed, or not-affected truth", item.ID)
		}
		if len(item.NativeComparisonIDs) == 0 {
			return fmt.Errorf("source case evidence %q requires native comparisons", item.ID)
		}
		comparisons := make(map[string]struct{}, len(item.NativeComparisonIDs))
		for _, comparisonID := range item.NativeComparisonIDs {
			if strings.TrimSpace(comparisonID) == "" || containsControlCharacter(comparisonID) {
				return fmt.Errorf("source case evidence %q has an invalid native comparison id", item.ID)
			}
			if _, exists := comparisons[comparisonID]; exists {
				return fmt.Errorf("source case evidence %q has duplicate native comparison %q", item.ID, comparisonID)
			}
			comparisons[comparisonID] = struct{}{}
		}
		if len(item.Citations) == 0 {
			return fmt.Errorf("source case evidence %q requires citations", item.ID)
		}
		citations := make(map[string]struct{}, len(item.Citations))
		for _, citation := range item.Citations {
			if err := citation.Validate(); err != nil {
				return fmt.Errorf("source case evidence %q citation: %w", item.ID, err)
			}
			if _, exists := citations[citation.Locator]; exists {
				return fmt.Errorf("source case evidence %q duplicates citation %q", item.ID, citation.Locator)
			}
			citations[citation.Locator] = struct{}{}
		}
	}
	return validateSourceDiagnostics(set.Unsupported)
}

func validateSourceDiagnostics(diagnostics []SourceEvidenceDiagnostic) error {
	seen := make(map[string]struct{}, len(diagnostics))
	for _, diagnostic := range diagnostics {
		if strings.TrimSpace(diagnostic.TargetID) == "" || strings.TrimSpace(diagnostic.DefinitionID) == "" || strings.TrimSpace(diagnostic.ElementKind) == "" || strings.TrimSpace(diagnostic.ElementID) == "" || strings.TrimSpace(diagnostic.Reason) == "" || containsControlCharacter(diagnostic.TargetID) || containsControlCharacter(diagnostic.DefinitionID) || containsControlCharacter(diagnostic.ElementKind) || containsControlCharacter(diagnostic.ElementID) || containsControlCharacter(diagnostic.Reason) {
			return fmt.Errorf("source evidence diagnostic is incomplete")
		}
		if _, err := componentIdentityKey(diagnostic.Component); err != nil {
			return fmt.Errorf("source evidence diagnostic component: %w", err)
		}
		key := diagnostic.TargetID + "\x00" + diagnostic.Component.PURL + "\x00" + diagnostic.DefinitionID + "\x00" + diagnostic.ElementKind + "\x00" + diagnostic.ElementID
		if _, exists := seen[key]; exists {
			return fmt.Errorf("source evidence diagnostic is duplicated")
		}
		seen[key] = struct{}{}
	}
	return nil
}

// NativeEvidenceSet binds every target-native comparison used by generated
// source evidence. Its target entries are reused by every capture engine.
type NativeEvidenceSet struct {
	SchemaVersion      string                 `json:"schema_version"`
	CycleID            string                 `json:"cycle_id"`
	SourceFreezeDigest string                 `json:"source_freeze_digest"`
	Targets            []NativeTargetEvidence `json:"targets"`
}

type NativeTargetEvidence struct {
	TargetID      string                   `json:"target_id"`
	TargetDigest  string                   `json:"target_digest"`
	PackageFamily string                   `json:"package_family"`
	Comparisons   []NativeComparisonRecord `json:"comparisons"`
}

func (set NativeEvidenceSet) Validate() error {
	if set.SchemaVersion != NativeEvidenceSetSchemaVersion {
		return fmt.Errorf("unsupported native evidence schema %q", set.SchemaVersion)
	}
	if err := validateCycleID(set.CycleID); err != nil {
		return err
	}
	if !validSHA256Digest(set.SourceFreezeDigest) || len(set.Targets) == 0 {
		return fmt.Errorf("native evidence requires frozen source and targets")
	}
	seenTargets := make(map[string]struct{}, len(set.Targets))
	seenComparisons := make(map[string]struct{})
	for _, target := range set.Targets {
		if err := target.Validate(); err != nil {
			return err
		}
		if _, exists := seenTargets[target.TargetID]; exists {
			return fmt.Errorf("native evidence has duplicate target %q", target.TargetID)
		}
		seenTargets[target.TargetID] = struct{}{}
		for _, comparison := range target.Comparisons {
			if _, exists := seenComparisons[comparison.ID]; exists {
				return fmt.Errorf("native evidence has duplicate comparison %q", comparison.ID)
			}
			seenComparisons[comparison.ID] = struct{}{}
		}
	}
	return nil
}

func (target NativeTargetEvidence) Validate() error {
	if strings.TrimSpace(target.TargetID) == "" || !validSHA256Digest(target.TargetDigest) || (target.PackageFamily != "deb" && target.PackageFamily != "rpm") {
		return fmt.Errorf("native target evidence is incomplete")
	}
	seen := make(map[string]struct{}, len(target.Comparisons))
	for _, comparison := range target.Comparisons {
		if err := comparison.Validate(); err != nil {
			return err
		}
		if comparison.TargetID != target.TargetID || comparison.TargetDigest != target.TargetDigest || comparison.PackageFamily != target.PackageFamily {
			return fmt.Errorf("native comparison %q does not bind its target evidence", comparison.ID)
		}
		if _, exists := seen[comparison.ID]; exists {
			return fmt.Errorf("native target evidence has duplicate comparison %q", comparison.ID)
		}
		seen[comparison.ID] = struct{}{}
	}
	return nil
}

func (set NativeEvidenceSet) Target(targetID string) (NativeTargetEvidence, bool) {
	for _, target := range set.Targets {
		if target.TargetID == targetID {
			return target, true
		}
	}
	return NativeTargetEvidence{}, false
}

func (set NativeEvidenceSet) Comparison(id string) (NativeComparisonRecord, bool) {
	for _, target := range set.Targets {
		for _, comparison := range target.Comparisons {
			if comparison.ID == id {
				return comparison, true
			}
		}
	}
	return NativeComparisonRecord{}, false
}

func nativeComparisonTruth(comparisons []NativeComparisonRecord) (Truth, error) {
	if len(comparisons) == 0 {
		return "", fmt.Errorf("native comparisons are required")
	}
	truths := make(map[Truth]struct{}, 2)
	for _, comparison := range comparisons {
		if err := comparison.Validate(); err != nil {
			return "", err
		}
		switch comparison.PredicateKind {
		case "", NativePredicateEVRLessThan:
			if comparison.Relation == "before" {
				truths[TruthAffected] = struct{}{}
			} else {
				truths[TruthFixed] = struct{}{}
			}
		case NativePredicateVersionEqualsZero:
			if comparison.Relation == "equal" {
				return "", fmt.Errorf("native zero-version comparison %q collides with the sentinel", comparison.ID)
			}
			truths[TruthNotAffected] = struct{}{}
		default:
			return "", fmt.Errorf("native comparison %q has an invalid predicate kind", comparison.ID)
		}
	}
	if len(truths) != 1 {
		return "", fmt.Errorf("target-native comparisons provide a split witness")
	}
	for truth := range truths {
		return truth, nil
	}
	return "", fmt.Errorf("native comparisons do not establish truth")
}

func DigestSourceEvidencePlan(plan SourceEvidencePlan) (string, error) {
	if err := plan.Validate(); err != nil {
		return "", err
	}
	copyPlan := plan
	copyPlan.Targets = append([]SourceEvidenceTarget(nil), plan.Targets...)
	sort.Slice(copyPlan.Targets, func(left, right int) bool { return copyPlan.Targets[left].TargetID < copyPlan.Targets[right].TargetID })
	for index := range copyPlan.Targets {
		copyPlan.Targets[index].Packages = append([]SourceEvidencePackage(nil), copyPlan.Targets[index].Packages...)
		sort.Slice(copyPlan.Targets[index].Packages, func(left, right int) bool {
			return copyPlan.Targets[index].Packages[left].Name < copyPlan.Targets[index].Packages[right].Name
		})
	}
	return digestCanonicalSourceEvidence(copyPlan)
}

func DigestSourceCaseEvidence(source SourceCaseEvidenceSet) (string, error) {
	if err := source.Validate(); err != nil {
		return "", err
	}
	copySource := source
	copySource.Cases = append([]SourceCaseEvidence(nil), source.Cases...)
	sort.Slice(copySource.Cases, func(left, right int) bool { return copySource.Cases[left].ID < copySource.Cases[right].ID })
	for index := range copySource.Cases {
		copySource.Cases[index].Citations = append([]ContentReference(nil), copySource.Cases[index].Citations...)
		sort.Slice(copySource.Cases[index].Citations, func(left, right int) bool {
			return copySource.Cases[index].Citations[left].Locator < copySource.Cases[index].Citations[right].Locator
		})
		copySource.Cases[index].NativeComparisonIDs = append([]string(nil), copySource.Cases[index].NativeComparisonIDs...)
		sort.Strings(copySource.Cases[index].NativeComparisonIDs)
	}
	return digestCanonicalSourceEvidence(copySource)
}

func DigestNativeEvidenceSet(evidence NativeEvidenceSet) (string, error) {
	if err := evidence.Validate(); err != nil {
		return "", err
	}
	copyEvidence := evidence
	copyEvidence.Targets = append([]NativeTargetEvidence(nil), evidence.Targets...)
	sort.Slice(copyEvidence.Targets, func(left, right int) bool {
		return copyEvidence.Targets[left].TargetID < copyEvidence.Targets[right].TargetID
	})
	for index := range copyEvidence.Targets {
		copyEvidence.Targets[index].Comparisons = append([]NativeComparisonRecord(nil), copyEvidence.Targets[index].Comparisons...)
		sort.Slice(copyEvidence.Targets[index].Comparisons, func(left, right int) bool {
			return copyEvidence.Targets[index].Comparisons[left].ID < copyEvidence.Targets[index].Comparisons[right].ID
		})
	}
	return digestCanonicalSourceEvidence(copyEvidence)
}

func DigestNativeTargetEvidence(evidence NativeTargetEvidence) (string, error) {
	if err := evidence.Validate(); err != nil {
		return "", err
	}
	copyEvidence := evidence
	copyEvidence.Comparisons = append([]NativeComparisonRecord(nil), evidence.Comparisons...)
	sort.Slice(copyEvidence.Comparisons, func(left, right int) bool {
		return copyEvidence.Comparisons[left].ID < copyEvidence.Comparisons[right].ID
	})
	return digestCanonicalSourceEvidence(copyEvidence)
}

func digestCanonicalSourceEvidence(value any) (string, error) {
	body, err := CanonicalJSON(value)
	if err != nil {
		return "", fmt.Errorf("encode source evidence: %w", err)
	}
	return SHA256Digest(body), nil
}
