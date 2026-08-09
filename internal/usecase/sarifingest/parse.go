// Package sarifingest accepts SARIF 2.1.0 from third-party scanners so external findings enter the same
// asset model, prioritisation and governance path as first-party ones — without ever being presented as
// this system's own analysis.
//
// A SARIF document is UNTRUSTED input. Every path it names is normalized and checked before use, every
// bound is enforced before anything is persisted, and every result that cannot be attributed is refused
// with a typed reason rather than silently dropped.
package sarifingest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Bounds on an untrusted document. Exceeding any of them is a typed error and NOTHING is persisted: a
// partially ingested report is worse than a refused one, because the gap is invisible.
const (
	DefaultMaxDocumentBytes = 64 << 20
	DefaultMaxRuns          = 64
	DefaultMaxResults       = 100000
)

// Limits are the ingest bounds.
type Limits struct {
	MaxDocumentBytes int
	MaxRuns          int
	MaxResults       int
}

// DefaultLimits returns the production bounds.
func DefaultLimits() Limits {
	return Limits{
		MaxDocumentBytes: DefaultMaxDocumentBytes,
		MaxRuns:          DefaultMaxRuns,
		MaxResults:       DefaultMaxResults,
	}
}

// sarifDocument is the subset of SARIF 2.1.0 this ingester reads. It is deliberately permissive about
// what it ignores and strict about what it uses.
type sarifDocument struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver     sarifDriver   `json:"driver"`
	Extensions []sarifDriver `json:"extensions"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	SemanticVersion string      `json:"semanticVersion"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	ShortDescription sarifText          `json:"shortDescription"`
	FullDescription  sarifText          `json:"fullDescription"`
	DefaultConfig    sarifConfiguration `json:"defaultConfiguration"`
	Properties       sarifProperties    `json:"properties"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifProperties struct {
	// Tools commonly carry their own severity here when SARIF level is too coarse.
	Severity        string   `json:"security-severity"`
	ProblemSeverity string   `json:"problem.severity"`
	Tags            []string `json:"tags"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	RuleIndex           *int               `json:"ruleIndex"`
	Level               string             `json:"level"`
	Message             sarifText          `json:"message"`
	Locations           []sarifLocation    `json:"locations"`
	RelatedLocations    []sarifLocation    `json:"relatedLocations"`
	PartialFingerprints map[string]string  `json:"partialFingerprints"`
	Suppressions        []sarifSuppression `json:"suppressions"`
	Properties          sarifProperties    `json:"properties"`
}

type sarifSuppression struct {
	Kind   string `json:"kind"`
	Status string `json:"status"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation  `json:"physicalLocation"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

type sarifLogicalLocation struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Name               string `json:"name"`
}

// parsed is one document's interpretation: the results that can be attributed, and the ones that cannot.
type parsed struct {
	digest   string
	results  []candidate
	refusals []importedfinding.RefusalReason
	coverage []importedfinding.CoverageIssue
}

// candidate is a result that survived parsing, before storage.
type candidate struct {
	runIndex    int
	resultIndex int
	toolName    string
	toolVersion string
	ruleID      string
	severity    shared.Severity
	title       string
	message     string
	location    importedfinding.Location
	suppressed  bool
	fingerprint string
}

// Digest returns the SHA-256 of a document, which is the idempotency key: re-ingesting identical bytes
// must not duplicate findings.
func Digest(document []byte) string {
	sum := sha256.Sum256(document)
	return hex.EncodeToString(sum[:])
}

// parseDocument interprets a SARIF document under the given bounds.
//
// A bound breach is an ERROR rather than a partial result, because the caller must persist nothing. A
// result-level problem is a typed refusal, so the caller can see exactly what was dropped.
func parseDocument(document []byte, limits Limits) (parsed, error) {
	if len(document) == 0 {
		return parsed{}, fmt.Errorf("%w: sarif document is empty", shared.ErrValidation)
	}
	if len(document) > limits.MaxDocumentBytes {
		return parsed{}, fmt.Errorf("%w: sarif document is %d bytes, over the %d byte bound; nothing was ingested",
			shared.ErrValidation, len(document), limits.MaxDocumentBytes)
	}

	var doc sarifDocument
	if err := json.Unmarshal(document, &doc); err != nil {
		return parsed{}, fmt.Errorf("%w: sarif document is not valid json", shared.ErrValidation)
	}
	if !strings.HasPrefix(strings.TrimSpace(doc.Version), "2.1") {
		return parsed{}, fmt.Errorf("%w: sarif version %q is not supported (2.1.0 expected)", shared.ErrValidation, doc.Version)
	}
	if len(doc.Runs) > limits.MaxRuns {
		return parsed{}, fmt.Errorf("%w: sarif document has %d runs, over the %d run bound; nothing was ingested",
			shared.ErrValidation, len(doc.Runs), limits.MaxRuns)
	}

	total := 0
	for _, run := range doc.Runs {
		total += len(run.Results)
	}
	if total > limits.MaxResults {
		return parsed{}, fmt.Errorf("%w: sarif document has %d results, over the %d result bound; nothing was ingested",
			shared.ErrValidation, total, limits.MaxResults)
	}

	out := parsed{digest: Digest(document)}
	for runIndex, run := range doc.Runs {
		rules := indexRules(run.Tool)
		toolName := strings.TrimSpace(run.Tool.Driver.Name)
		toolVersion := driverVersion(run.Tool.Driver)

		for resultIndex, result := range run.Results {
			candidate, refusal := interpretResult(runIndex, resultIndex, result, rules, toolName, toolVersion)
			if refusal != nil {
				out.refusals = append(out.refusals, *refusal)
				continue
			}
			out.results = append(out.results, *candidate)
		}
	}
	return out, nil
}

// driverVersion prefers the semantic version, falling back to the plain one. A tool with no version at
// all cannot satisfy provenance, which the caller enforces.
func driverVersion(driver sarifDriver) string {
	if v := strings.TrimSpace(driver.SemanticVersion); v != "" {
		return v
	}
	return strings.TrimSpace(driver.Version)
}

// indexRules collects rule metadata from the driver AND every extension, since tools split their rules
// across both.
func indexRules(tool sarifTool) map[string]sarifRule {
	out := map[string]sarifRule{}
	add := func(driver sarifDriver) {
		for _, rule := range driver.Rules {
			if id := strings.TrimSpace(rule.ID); id != "" {
				if _, exists := out[id]; !exists {
					out[id] = rule
				}
			}
		}
	}
	add(tool.Driver)
	for _, extension := range tool.Extensions {
		add(extension)
	}
	return out
}

// interpretResult turns one SARIF result into a candidate, or a typed refusal.
func interpretResult(runIndex, resultIndex int, result sarifResult, rules map[string]sarifRule, toolName, toolVersion string) (*candidate, *importedfinding.RefusalReason) {
	refuse := func(code importedfinding.RefusalCode, detail string) *importedfinding.RefusalReason {
		return &importedfinding.RefusalReason{RunIndex: runIndex, ResultIndex: resultIndex, Code: code, Detail: detail}
	}

	// A result may carry ruleId, ruleIndex, or neither. Without SOME rule identity the finding cannot be
	// attributed to a rule, so it cannot be re-checked against its source.
	ruleID := strings.TrimSpace(result.RuleID)
	if ruleID == "" && result.RuleIndex != nil {
		ruleID = ruleIDAtIndex(rules, *result.RuleIndex)
	}
	if ruleID == "" || toolName == "" || toolVersion == "" {
		return nil, refuse(importedfinding.RefusalNoProvenance,
			"result has no establishable tool and rule identity")
	}

	// Cyclic relatedLocations must never be followed. This ingester reads them only for depth, so a
	// cycle is detected by bounding the count rather than by traversal.
	if len(result.RelatedLocations) > maxRelatedLocations {
		return nil, refuse(importedfinding.RefusalCyclicRelation,
			"result declares more related locations than can be followed safely")
	}

	location, refusal := interpretLocation(result.Locations, refuse)
	if refusal != nil {
		return nil, refusal
	}

	rule := rules[ruleID]
	return &candidate{
		runIndex:    runIndex,
		resultIndex: resultIndex,
		toolName:    toolName,
		toolVersion: toolVersion,
		ruleID:      ruleID,
		severity:    MapSeverity(toolName, result, rule),
		title:       firstNonEmpty(rule.ShortDescription.Text, rule.Name, ruleID),
		message:     strings.TrimSpace(result.Message.Text),
		location:    location,
		suppressed:  isSuppressed(result.Suppressions),
		fingerprint: firstFingerprint(result.PartialFingerprints),
	}, nil
}

// maxRelatedLocations bounds how many related locations a single result may declare.
const maxRelatedLocations = 1024

func ruleIDAtIndex(rules map[string]sarifRule, index int) string {
	if index < 0 {
		return ""
	}
	// The map is keyed by id, so an index lookup needs a deterministic order.
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sortStrings(ids)
	if index >= len(ids) {
		return ""
	}
	return ids[index]
}

// interpretLocation normalizes the first physical location, refusing anything that points outside the
// scanned tree. A SARIF document is untrusted: an absolute path, a traversal, or a non-file URI scheme
// must never be followed.
func interpretLocation(locations []sarifLocation, refuse func(importedfinding.RefusalCode, string) *importedfinding.RefusalReason) (importedfinding.Location, *importedfinding.RefusalReason) {
	if len(locations) == 0 {
		// A result with no location is legitimate (a project-level finding); it simply has no path.
		return importedfinding.Location{}, nil
	}
	first := locations[0]
	uri := strings.TrimSpace(first.PhysicalLocation.ArtifactLocation.URI)

	out := importedfinding.Location{
		StartLine:   maxInt(first.PhysicalLocation.Region.StartLine, 0),
		StartColumn: maxInt(first.PhysicalLocation.Region.StartColumn, 0),
	}
	for _, logical := range first.LogicalLocations {
		if name := firstNonEmpty(logical.FullyQualifiedName, logical.Name); name != "" {
			out.LogicalName = name
			break
		}
	}
	if uri == "" {
		return out, nil
	}

	normalized, code := normalizeArtifactURI(uri)
	if code != "" {
		return importedfinding.Location{}, refuse(code, "artifact location is not a safe repository-relative path")
	}
	out.Path = normalized
	return out, nil
}

// normalizeArtifactURI converts a SARIF artifact URI into a repository-relative path, or returns the
// refusal code that explains why it cannot be used.
func normalizeArtifactURI(uri string) (string, importedfinding.RefusalCode) {
	if strings.IndexByte(uri, 0) >= 0 {
		return "", importedfinding.RefusalInvalidLocation
	}
	// Only the file scheme and a bare relative path are acceptable. http(s), ftp, data, jar and the
	// rest would point at something outside the scanned tree.
	if i := strings.Index(uri, "://"); i >= 0 {
		if !strings.EqualFold(uri[:i], "file") {
			return "", importedfinding.RefusalUnsupportedURI
		}
		uri = uri[i+len("://"):]
		// file:///abs/path leaves a leading slash, which is absolute.
		if strings.HasPrefix(uri, "/") {
			return "", importedfinding.RefusalAbsolutePath
		}
	} else if strings.Contains(uri, ":") && !strings.HasPrefix(uri, "./") {
		// A bare scheme such as "mailto:x" or a Windows volume "C:\..." is not a relative path.
		if looksLikeWindowsVolume(uri) {
			return "", importedfinding.RefusalAbsolutePath
		}
		return "", importedfinding.RefusalUnsupportedURI
	}

	cleaned := strings.ReplaceAll(uri, "\\", "/")
	if strings.HasPrefix(cleaned, "/") {
		return "", importedfinding.RefusalAbsolutePath
	}
	cleaned = path.Clean(cleaned)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", importedfinding.RefusalPathTraversal
	}
	if cleaned == "." || cleaned == "" {
		return "", importedfinding.RefusalInvalidLocation
	}
	return strings.TrimPrefix(cleaned, "./"), ""
}

func looksLikeWindowsVolume(p string) bool {
	return len(p) >= 2 && p[1] == ':' &&
		((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z'))
}

// isSuppressed reports whether the document marks this result suppressed. The flag is RECORDED, not
// acted on: an external tool's suppression is information, never authority over this system's gate.
func isSuppressed(suppressions []sarifSuppression) bool {
	for _, suppression := range suppressions {
		if strings.EqualFold(strings.TrimSpace(suppression.Status), "rejected") {
			continue
		}
		if strings.TrimSpace(suppression.Kind) != "" {
			return true
		}
	}
	return false
}

// firstFingerprint returns a stable fingerprint, chosen deterministically when the tool supplies several.
func firstFingerprint(fingerprints map[string]string) string {
	if len(fingerprints) == 0 {
		return ""
	}
	keys := make([]string, 0, len(fingerprints))
	for key := range fingerprints {
		keys = append(keys, key)
	}
	sortStrings(keys)
	return fingerprints[keys[0]]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func sortStrings(in []string) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j] < in[j-1]; j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
}
