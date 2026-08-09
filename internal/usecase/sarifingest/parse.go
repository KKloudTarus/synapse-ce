// Package sarifingest accepts SARIF 2.1.0 from third-party scanners so external findings enter the same
// asset model, prioritisation and governance path as first-party ones — without ever being presented as
// this system's own analysis.
//
// A SARIF document is UNTRUSTED input. It is decoded as a STREAM and every repeated array — runs,
// results, and the rule tables they reference — is bounded, so a document that fits the byte bound can
// never expand into an unbounded number of Go values. Everything derived from a rule is computed ONCE
// per rule rather than once per result, so shared data cannot be multiplied by the result budget. Every
// path the document names is percent-decoded and checked before use (see uri.go), every bound is
// enforced before anything is persisted, and every result that cannot be attributed is refused with a
// typed reason rather than silently dropped.
package sarifingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Bounds on an untrusted document. Exceeding any of them is a typed error and NOTHING is persisted: a
// partially ingested report is worse than a refused one, because the gap is invisible.
//
// The byte bound is deliberately modest. Because the parser streams and bounds every repeated array,
// peak memory is roughly the document itself plus the text it actually keeps, so the bound is a direct
// memory ceiling rather than a number that gets multiplied by the decoder. A report larger than this is
// refused with an explicit error that names the size — never truncated, which would look like a clean
// ingest of a smaller report.
const (
	DefaultMaxDocumentBytes = 32 << 20
	DefaultMaxRuns          = 64
	DefaultMaxResults       = 100000
	// DefaultMaxRules bounds one tool component's rule table. Without it a document could spend its
	// whole byte budget on rules: they are held for the length of the run, and a rule is far larger in
	// memory than the JSON that declares it. Real tools ship hundreds; CodeQL's full suite is under
	// two thousand.
	DefaultMaxRules = 20000
)

// Per-result count bounds. Each of these is a repeated array inside ONE result, so without a bound a
// single result could carry a large fraction of the document.
const (
	maxRelatedLocations = 1024
	maxLocations        = 256
	maxLogicalLocations = 256
	maxFingerprints     = 256
	maxTags             = 256
	maxSuppressions     = 256
	// maxRefusals bounds the refusal list returned to the caller. A breach is itself disclosed as a
	// coverage issue, so a truncated list is never mistaken for a complete one.
	maxRefusals = 2000
	// ctxCheckEvery is how often the result loop observes cancellation; a disconnected client must not
	// keep the parser running to completion.
	ctxCheckEvery = 256
)

// Limits are the ingest bounds.
type Limits struct {
	MaxDocumentBytes int
	MaxRuns          int
	MaxResults       int
	MaxRules         int
}

// DefaultLimits returns the production bounds.
func DefaultLimits() Limits {
	return Limits{
		MaxDocumentBytes: DefaultMaxDocumentBytes,
		MaxRuns:          DefaultMaxRuns,
		MaxResults:       DefaultMaxResults,
		MaxRules:         DefaultMaxRules,
	}
}

// The subset of SARIF 2.1.0 this ingester reads. It is deliberately permissive about what it ignores and
// strict about what it uses. No type here holds a whole document: `runs`, `results` and `rules` are all
// walked as streams.

type sarifTool struct {
	Driver     sarifDriver   `json:"driver"`
	Extensions []sarifDriver `json:"extensions"`
}

type sarifDriver struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	SemanticVersion string `json:"semanticVersion"`
	// Rules stays raw so the table can be decoded one rule at a time under a count bound.
	Rules json.RawMessage `json:"rules"`
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

// ruleInfo is everything one rule contributes, DERIVED ONCE when the rule table is read.
//
// This is the shape that keeps per-result work independent of rule size. Reading a rule's tag list or
// sanitizing its description inside the result loop would multiply shared data by the result budget: one
// rule with a million tags and a hundred thousand results referencing it is a few megabytes of JSON and
// 10^11 units of work.
type ruleInfo struct {
	id               string
	title            string
	problemSeverity  string
	tagSeverity      string
	securitySeverity string
	level            string
}

// ruleTable is one run's rules, addressable by id and by index.
type ruleTable struct {
	byID map[string]ruleInfo
	// driverIDs are the driver's rule ids in DOCUMENT order, which is what `ruleIndex` addresses.
	driverIDs []string
	// extensionIDs are the extensions' rule ids, used only when the driver declares no rules at all.
	extensionIDs []string
}

// parsed is one document's interpretation: the results that can be attributed, the ones that cannot, and
// the limitations of the ingest itself.
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

// ingestStats accumulates what the ingest could NOT fully represent, so the caller can report it instead
// of presenting a lossy ingest as a complete one.
type ingestStats struct {
	results         int
	unknownSeverity int
	suppressed      int
	truncated       int
	unresolvedIndex int
	droppedRefusals int
}

func (s ingestStats) coverage() []importedfinding.CoverageIssue {
	var out []importedfinding.CoverageIssue
	add := func(format string, n int) {
		if n > 0 {
			out = append(out, importedfinding.CoverageIssue{Detail: fmt.Sprintf(format, n)})
		}
	}
	if s.results == 0 {
		out = append(out, importedfinding.CoverageIssue{
			Detail: "the document declared no results, so an empty ingest here is not evidence of a clean scan",
		})
	}
	add("%d results carried a severity this ingester cannot map; they are stored as unknown rather than assigned a level", s.unknownSeverity)
	add("%d results were marked suppressed by the source tool; the flag is recorded but NOT obeyed", s.suppressed)
	add("%d stored text fields were longer than the stored bound and were truncated", s.truncated)
	add("%d results addressed a rule by index that the document does not declare", s.unresolvedIndex)
	add("%d further refusals were not listed: the refusal list is capped, so this ingest refused MORE than it reports", s.droppedRefusals)
	return out
}

// Digest returns the SHA-256 of a document, which is the idempotency key: re-ingesting identical bytes
// must not duplicate findings.
func Digest(document []byte) string {
	sum := sha256.Sum256(document)
	return hex.EncodeToString(sum[:])
}

func errNotJSON() error {
	return fmt.Errorf("%w: sarif document is not valid json", shared.ErrValidation)
}

// parseDocument interprets a SARIF document under the given bounds.
//
// A bound breach is an ERROR rather than a partial result, because the caller must persist nothing. A
// result-level problem is a typed refusal, so the caller can see exactly what was dropped.
func parseDocument(ctx context.Context, document []byte, limits Limits) (parsed, error) {
	if len(document) == 0 {
		return parsed{}, fmt.Errorf("%w: sarif document is empty", shared.ErrValidation)
	}
	if len(document) > limits.MaxDocumentBytes {
		return parsed{}, fmt.Errorf("%w: sarif document is %d bytes, over the %d byte bound; nothing was ingested",
			shared.ErrValidation, len(document), limits.MaxDocumentBytes)
	}

	dec := json.NewDecoder(bytes.NewReader(document))
	if err := expectDelim(dec, '{'); err != nil {
		return parsed{}, errNotJSON()
	}

	out := parsed{digest: Digest(document)}
	var stats ingestStats
	version := ""
	versionSeen := false

	for dec.More() {
		key, err := objectKey(dec)
		if err != nil {
			return parsed{}, errNotJSON()
		}
		switch key {
		case "version":
			if err := dec.Decode(&version); err != nil {
				return parsed{}, errNotJSON()
			}
			versionSeen = true
			if err := checkVersion(version); err != nil {
				return parsed{}, err
			}
		case "runs":
			// JSON does not guarantee key order. If the version has not been seen yet it is checked
			// after the walk; an unsupported version is an error either way and persists nothing.
			if err := walkRuns(ctx, dec, limits, &out, &stats); err != nil {
				return parsed{}, err
			}
		default:
			if err := skipValue(dec); err != nil {
				return parsed{}, errNotJSON()
			}
		}
	}
	if _, err := dec.Token(); err != nil { // closing '}'
		return parsed{}, errNotJSON()
	}
	// Anything after the top-level object means the bytes are not one SARIF document. Accepting trailing
	// content would also hand an attacker a one-byte way to change the digest and force a full re-ingest
	// of a report that was already stored.
	if dec.More() {
		return parsed{}, fmt.Errorf("%w: sarif document has trailing content after the top-level object", shared.ErrValidation)
	}
	if !versionSeen {
		if err := checkVersion(version); err != nil {
			return parsed{}, err
		}
	}
	out.coverage = stats.coverage()
	return out, nil
}

// checkVersion accepts the 2.1 line only. The test is on the MINOR component rather than a string
// prefix, so "2.15.0" — a different specification — is refused instead of being read as 2.1.
func checkVersion(version string) error {
	trimmed := strings.TrimSpace(version)
	if trimmed == "2.1" || strings.HasPrefix(trimmed, "2.1.") {
		return nil
	}
	// The version is attacker-controlled and reflected in the response, so it is stripped of control
	// characters and clamped before it is echoed.
	echoed, _ := sanitizeText(version, maxVersionEcho, false)
	return fmt.Errorf("%w: sarif version %q is not supported (2.1.0 expected)", shared.ErrValidation, echoed)
}

// walkRuns streams the runs array, enforcing the run bound as it goes.
func walkRuns(ctx context.Context, dec *json.Decoder, limits Limits, out *parsed, stats *ingestStats) error {
	opened, err := openArray(dec)
	if err != nil {
		return errNotJSON()
	}
	if !opened {
		return nil
	}
	runIndex := 0
	for dec.More() {
		if err := checkCancelled(ctx); err != nil {
			return err
		}
		if runIndex >= limits.MaxRuns {
			return fmt.Errorf("%w: sarif document declares more than %d runs, over the bound; nothing was ingested",
				shared.ErrValidation, limits.MaxRuns)
		}
		if err := walkRun(ctx, dec, runIndex, limits, out, stats); err != nil {
			return err
		}
		runIndex++
	}
	if _, err := dec.Token(); err != nil { // closing ']'
		return errNotJSON()
	}
	return nil
}

// walkRun streams one run: the tool component is decoded (its rule table is read under a bound), and the
// results array is consumed one result at a time.
func walkRun(ctx context.Context, dec *json.Decoder, runIndex int, limits Limits, out *parsed, stats *ingestStats) error {
	if err := expectDelim(dec, '{'); err != nil {
		return errNotJSON()
	}
	var (
		tool       sarifTool
		rules      ruleTable
		toolSeen   bool
		bufResults json.RawMessage
	)
	for dec.More() {
		key, err := objectKey(dec)
		if err != nil {
			return errNotJSON()
		}
		switch key {
		case "tool":
			if err := dec.Decode(&tool); err != nil {
				return errNotJSON()
			}
			rules, err = buildRuleTable(tool, limits, stats)
			if err != nil {
				return err
			}
			toolSeen = true
		case "results":
			if bufResults != nil {
				// Two results arrays in one run would each be walked, producing duplicate candidates
				// under colliding (run, result) indexes that no longer locate anything.
				return fmt.Errorf("%w: sarif run declares more than one results array", shared.ErrValidation)
			}
			if !toolSeen {
				// Every real tool emits `tool` before `results`; a document that does not would lose its
				// rule metadata, so in that rare case the array is buffered and replayed after the run.
				if err := dec.Decode(&bufResults); err != nil {
					return errNotJSON()
				}
				if bufResults == nil {
					bufResults = json.RawMessage("null")
				}
				continue
			}
			if err := streamResults(ctx, dec, runIndex, tool, rules, limits, out, stats); err != nil {
				return err
			}
		default:
			if err := skipValue(dec); err != nil {
				return errNotJSON()
			}
		}
	}
	if _, err := dec.Token(); err != nil { // closing '}'
		return errNotJSON()
	}
	if bufResults != nil {
		return streamResults(ctx, json.NewDecoder(bytes.NewReader(bufResults)), runIndex, tool, rules, limits, out, stats)
	}
	return nil
}

// streamResults decodes one result at a time, so a run cannot force the whole results array into memory.
func streamResults(ctx context.Context, dec *json.Decoder, runIndex int, tool sarifTool, rules ruleTable, limits Limits, out *parsed, stats *ingestStats) error {
	toolName, _ := sanitizeText(tool.Driver.Name, maxIdentifierBytes, false)
	toolVersion, _ := sanitizeText(driverVersion(tool.Driver), maxIdentifierBytes, false)

	opened, err := openArray(dec)
	if err != nil {
		return errNotJSON()
	}
	if !opened {
		return nil
	}
	resultIndex := 0
	for dec.More() {
		if resultIndex%ctxCheckEvery == 0 {
			if err := checkCancelled(ctx); err != nil {
				return err
			}
		}
		if stats.results >= limits.MaxResults {
			return fmt.Errorf("%w: sarif document declares more than %d results, over the bound; nothing was ingested",
				shared.ErrValidation, limits.MaxResults)
		}
		var result sarifResult
		if err := dec.Decode(&result); err != nil {
			return errNotJSON()
		}
		stats.results++
		accepted, refusal := interpretResult(runIndex, resultIndex, result, rules, toolName, toolVersion, stats)
		switch {
		case refusal != nil && len(out.refusals) < maxRefusals:
			out.refusals = append(out.refusals, *refusal)
		case refusal != nil:
			stats.droppedRefusals++
		default:
			out.results = append(out.results, *accepted)
		}
		resultIndex++
	}
	if _, err := dec.Token(); err != nil { // closing ']'
		return errNotJSON()
	}
	return nil
}

// driverVersion prefers the semantic version, falling back to the plain one. A tool with no version at
// all cannot satisfy provenance, which the caller enforces.
func driverVersion(driver sarifDriver) string {
	if v := strings.TrimSpace(driver.SemanticVersion); v != "" {
		return v
	}
	return strings.TrimSpace(driver.Version)
}

// buildRuleTable reads the driver's and the extensions' rule tables under a count bound, deriving each
// rule's contribution exactly once.
func buildRuleTable(tool sarifTool, limits Limits, stats *ingestStats) (ruleTable, error) {
	table := ruleTable{byID: map[string]ruleInfo{}}
	driverIDs, err := decodeRules(tool.Driver.Rules, limits, table.byID, stats)
	if err != nil {
		return ruleTable{}, err
	}
	table.driverIDs = driverIDs
	for _, extension := range tool.Extensions {
		ids, err := decodeRules(extension.Rules, limits, table.byID, stats)
		if err != nil {
			return ruleTable{}, err
		}
		table.extensionIDs = append(table.extensionIDs, ids...)
	}
	return table, nil
}

// decodeRules streams one rule table, adding each rule's DERIVED form to byID and returning the ids in
// document order. A rule id already present wins, so the driver's definition is not overwritten.
func decodeRules(raw json.RawMessage, limits Limits, byID map[string]ruleInfo, stats *ingestStats) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	opened, err := openArray(dec)
	if err != nil {
		return nil, errNotJSON()
	}
	if !opened {
		return nil, nil
	}
	var ordered []string
	for dec.More() {
		if len(ordered) >= limits.MaxRules {
			return nil, fmt.Errorf("%w: a sarif tool component declares more than %d rules, over the bound; nothing was ingested",
				shared.ErrValidation, limits.MaxRules)
		}
		var rule sarifRule
		if err := dec.Decode(&rule); err != nil {
			return nil, errNotJSON()
		}
		id, _ := sanitizeText(rule.ID, maxIdentifierBytes, false)
		if id == "" {
			// A rule with no id still occupies an INDEX, so it is recorded as an empty slot rather than
			// skipped: dropping it would shift every later rule's index by one.
			ordered = append(ordered, "")
			continue
		}
		ordered = append(ordered, id)
		if _, exists := byID[id]; exists {
			continue
		}
		byID[id] = deriveRule(id, rule, stats)
	}
	if _, err := dec.Token(); err != nil {
		return nil, errNotJSON()
	}
	return ordered, nil
}

// deriveRule computes everything a rule contributes, once.
func deriveRule(id string, rule sarifRule, stats *ingestStats) ruleInfo {
	title, truncated := sanitizeText(firstNonEmpty(rule.ShortDescription.Text, rule.Name, id), maxTitleBytes, false)
	if truncated {
		stats.truncated++
	}
	return ruleInfo{
		id:               id,
		title:            title,
		problemSeverity:  strings.TrimSpace(rule.Properties.ProblemSeverity),
		tagSeverity:      severityFromTags(rule.Properties.Tags),
		securitySeverity: strings.TrimSpace(rule.Properties.Severity),
		level:            strings.TrimSpace(rule.DefaultConfig.Level),
	}
}

// interpretResult turns one SARIF result into a candidate, or a typed refusal.
func interpretResult(runIndex, resultIndex int, result sarifResult, rules ruleTable,
	toolName, toolVersion string, stats *ingestStats) (*candidate, *importedfinding.RefusalReason) {
	refuse := func(code importedfinding.RefusalCode, detail string) *importedfinding.RefusalReason {
		return &importedfinding.RefusalReason{RunIndex: runIndex, ResultIndex: resultIndex, Code: code, Detail: detail}
	}

	// A result may carry ruleId, ruleIndex, or neither. Without SOME rule identity the finding cannot be
	// attributed to a rule, so it cannot be re-checked against its source.
	ruleID, _ := sanitizeText(result.RuleID, maxIdentifierBytes, false)
	if ruleID == "" && result.RuleIndex != nil {
		ruleID = rules.at(*result.RuleIndex)
		if ruleID == "" {
			stats.unresolvedIndex++
		}
	}
	if ruleID == "" || toolName == "" || toolVersion == "" {
		return nil, refuse(importedfinding.RefusalNoProvenance,
			"result has no establishable tool and rule identity")
	}

	// Every repeated array inside a result is bounded. This ingester never FOLLOWS a related location,
	// so an unbounded set cannot be traversed — but it is still a memory cost and a sign of a hostile
	// document, and a bound is the only thing that keeps per-result work bounded.
	for _, check := range []struct {
		count int
		limit int
		what  string
	}{
		{len(result.RelatedLocations), maxRelatedLocations, "related locations"},
		{len(result.Locations), maxLocations, "locations"},
		{len(result.PartialFingerprints), maxFingerprints, "partial fingerprints"},
		{len(result.Properties.Tags), maxTags, "property tags"},
		{len(result.Suppressions), maxSuppressions, "suppressions"},
	} {
		if check.count > check.limit {
			return nil, refuse(importedfinding.RefusalTooManyElements,
				"result declares more "+check.what+" than can be held safely")
		}
	}

	location, refusal := interpretLocation(result.Locations, refuse)
	if refusal != nil {
		return nil, refusal
	}

	rule := rules.byID[ruleID]
	severity := mapSeverity(toolName, result, rule)
	if severity == shared.SeverityUnknown {
		stats.unknownSeverity++
	}
	suppressed := isSuppressed(result.Suppressions)
	if suppressed {
		stats.suppressed++
	}

	title := rule.title
	if title == "" {
		title, _ = sanitizeText(ruleID, maxTitleBytes, false)
	}
	message, messageCut := sanitizeText(result.Message.Text, maxMessageBytes, true)
	fingerprint, fingerprintCut := sanitizeText(firstFingerprint(result.PartialFingerprints), maxIdentifierBytes, false)
	for _, cut := range []bool{messageCut, fingerprintCut} {
		if cut {
			stats.truncated++
		}
	}

	return &candidate{
		runIndex:    runIndex,
		resultIndex: resultIndex,
		toolName:    toolName,
		toolVersion: toolVersion,
		ruleID:      ruleID,
		severity:    severity,
		title:       title,
		message:     message,
		location:    location,
		suppressed:  suppressed,
		fingerprint: fingerprint,
	}, nil
}

// at resolves a `ruleIndex` against the run's rules in document order.
//
// The index addresses the DRIVER's rules. Extensions are consulted only when the driver declares no rule
// table at all — the shape several tools emit — because silently resolving an out-of-range index against
// an extension would attribute a finding to a rule the tool never associated with it, and provenance is
// the entire point of this type. An index that resolves to nothing is a disclosed refusal instead.
func (t ruleTable) at(index int) string {
	if index < 0 {
		return ""
	}
	ids := t.driverIDs
	if len(ids) == 0 {
		ids = t.extensionIDs
	}
	if index >= len(ids) {
		return ""
	}
	return ids[index]
}

// interpretLocation normalizes the first physical location, refusing anything that points outside the
// scanned tree. A SARIF document is untrusted: an absolute path, a traversal, a non-file URI scheme or a
// base directory that is not the repository root must never be followed.
func interpretLocation(locations []sarifLocation, refuse func(importedfinding.RefusalCode, string) *importedfinding.RefusalReason) (importedfinding.Location, *importedfinding.RefusalReason) {
	if len(locations) == 0 {
		// A result with no location is legitimate (a project-level finding); it simply has no path.
		return importedfinding.Location{}, nil
	}
	first := locations[0]
	if len(first.LogicalLocations) > maxLogicalLocations {
		return importedfinding.Location{}, refuse(importedfinding.RefusalTooManyElements,
			"location declares more logical locations than can be held safely")
	}

	// A negative line or column is not a position. It is refused rather than clamped to zero, because
	// clamping would silently rewrite the location the tool reported.
	if first.PhysicalLocation.Region.StartLine < 0 || first.PhysicalLocation.Region.StartColumn < 0 {
		return importedfinding.Location{}, refuse(importedfinding.RefusalInvalidLocation,
			"region start line or column is negative")
	}

	out := importedfinding.Location{
		StartLine:   first.PhysicalLocation.Region.StartLine,
		StartColumn: first.PhysicalLocation.Region.StartColumn,
	}
	for _, logical := range first.LogicalLocations {
		if name, _ := sanitizeText(firstNonEmpty(logical.FullyQualifiedName, logical.Name), maxIdentifierBytes, false); name != "" {
			out.LogicalName = name
			break
		}
	}

	uri := strings.TrimSpace(first.PhysicalLocation.ArtifactLocation.URI)
	if uri == "" {
		return out, nil
	}
	// `uriBaseId` names the directory the URI is relative to. An unrecognised base means the path is NOT
	// repository-relative, so storing it as one would relabel a file outside the scanned tree as a file
	// inside it — and would collapse two distinct results that share a URI under different bases.
	if !repositoryRootBase(first.PhysicalLocation.ArtifactLocation.URIBaseID) {
		return importedfinding.Location{}, refuse(importedfinding.RefusalUnsupportedURIBase,
			"artifact location is relative to a base directory that is not the repository root")
	}

	normalized, code := normalizeArtifactURI(uri)
	if code != "" {
		return importedfinding.Location{}, refuse(code, "artifact location is not a safe repository-relative path")
	}
	out.Path = normalized
	return out, nil
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
// The lowest key wins; it is found by a single scan rather than by sorting.
func firstFingerprint(fingerprints map[string]string) string {
	lowest, found := "", false
	for key := range fingerprints {
		if !found || key < lowest {
			lowest, found = key, true
		}
	}
	if !found {
		return ""
	}
	return fingerprints[lowest]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// Streaming helpers. They keep memory constant regardless of how large an ignored value is.

func checkCancelled(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("parse sarif document: %w", err)
	}
	return nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != want {
		return fmt.Errorf("expected %q", want)
	}
	return nil
}

// openArray consumes an array's opening bracket. It reports opened=false for JSON null, which is a
// legitimate way to say "no elements" — several tools write `"results": null` for a clean scan, and
// refusing the whole document for it would turn a clean scan into a parse error.
func openArray(dec *json.Decoder) (bool, error) {
	tok, err := dec.Token()
	if err != nil {
		return false, err
	}
	if tok == nil {
		return false, nil
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '[' {
		return false, fmt.Errorf("expected an array")
	}
	return true, nil
}

func objectKey(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	key, ok := tok.(string)
	if !ok {
		return "", fmt.Errorf("expected an object key")
	}
	return key, nil
}

// skipValue consumes one JSON value without materialising it, so an unread member (a huge $schema blob,
// an inlineExternalProperties section) costs nothing.
//
// It bounds nesting itself: json.Decoder.Token keeps one stack entry per open bracket and does NOT apply
// the decoder's depth limit, so a member of nothing but `[[[[…` would otherwise cost memory proportional
// to the document.
func skipValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '[' && delim != '{' {
		return fmt.Errorf("unexpected %q", delim)
	}
	depth := 1
	for depth > 0 {
		if depth > maxSkipDepth {
			return fmt.Errorf("ignored member is nested deeper than %d levels", maxSkipDepth)
		}
		next, err := dec.Token()
		if err != nil {
			return err
		}
		if d, isDelim := next.(json.Delim); isDelim {
			if d == '[' || d == '{' {
				depth++
			} else {
				depth--
			}
		}
	}
	return nil
}

// maxSkipDepth bounds nesting inside a member this ingester does not read.
const maxSkipDepth = 1000
