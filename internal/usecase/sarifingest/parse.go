// Package sarifingest accepts SARIF 2.1.0 from third-party scanners so external findings enter the same
// asset model, prioritisation and governance path as first-party ones — without ever being presented as
// this system's own analysis.
//
// A SARIF document is UNTRUSTED input. It is decoded as a STREAM so a document that fits the byte bound
// can never expand into an unbounded number of Go values; every path it names is percent-decoded and
// checked before use; every bound is enforced before anything is persisted; and every result that cannot
// be attributed is refused with a typed reason rather than silently dropped.
package sarifingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Bounds on an untrusted document. Exceeding any of them is a typed error and NOTHING is persisted: a
// partially ingested report is worse than a refused one, because the gap is invisible.
//
// The byte bound is deliberately modest. Because the parser streams, peak memory is roughly the document
// itself plus the text it actually keeps, so the bound is a direct memory ceiling rather than a number
// that gets multiplied by the decoder. A report larger than this is refused with an explicit error that
// names the size — never truncated, which would look like a clean ingest of a smaller report.
const (
	DefaultMaxDocumentBytes = 32 << 20
	DefaultMaxRuns          = 64
	DefaultMaxResults       = 100000
)

// Per-result bounds. Text from an external tool is stored, so it is capped and stripped of control
// characters HERE rather than trusted to every future renderer to handle safely.
const (
	maxTitleBytes      = 4 << 10
	maxMessageBytes    = 4 << 10
	maxIdentifierBytes = 512
	maxPathBytes       = 4096
	// maxRelatedLocations and maxLocations bound how many locations a single result may declare. They
	// are COUNT bounds, not traversal limits: this ingester never follows a related location, so a cycle
	// among them cannot be entered in the first place.
	maxRelatedLocations = 1024
	maxLocations        = 256
	maxLogicalLocations = 256
	// maxVersionEcho bounds how much of an attacker-controlled version string is reflected in an error.
	maxVersionEcho = 32
	// ctxCheckEvery is how often the result loop observes cancellation; a disconnected client must not
	// keep the parser running to completion.
	ctxCheckEvery = 1024
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

// The subset of SARIF 2.1.0 this ingester reads. It is deliberately permissive about what it ignores and
// strict about what it uses. Note that no type here holds a whole document: `runs` and `results` are
// walked as streams.

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
}

func (s ingestStats) coverage() []importedfinding.CoverageIssue {
	var out []importedfinding.CoverageIssue
	add := func(format string, n int) {
		if n > 0 {
			out = append(out, importedfinding.CoverageIssue{Detail: fmt.Sprintf(format, n)})
		}
	}
	add("%d results carried a severity this ingester cannot map; they are stored as unknown rather than assigned a level", s.unknownSeverity)
	add("%d results were marked suppressed by the source tool; the flag is recorded but NOT obeyed", s.suppressed)
	add("%d stored text fields were longer than the stored bound and were truncated", s.truncated)
	add("%d results addressed a rule by index that the document does not declare", s.unresolvedIndex)
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
//
// The document is walked with a streaming decoder: `runs` and `results` are never materialised as whole
// Go slices, so the number of decoded values a document can force is bounded by the result budget rather
// than by how many objects fit in the byte budget.
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
	if !versionSeen {
		if err := checkVersion(version); err != nil {
			return parsed{}, err
		}
	}
	out.coverage = stats.coverage()
	return out, nil
}

func checkVersion(version string) error {
	if strings.HasPrefix(strings.TrimSpace(version), "2.1") {
		return nil
	}
	// The version is attacker-controlled and reflected in the response, so it is stripped of control
	// characters and clamped before it is echoed.
	echoed, _ := sanitizeText(version, maxVersionEcho, false)
	return fmt.Errorf("%w: sarif version %q is not supported (2.1.0 expected)", shared.ErrValidation, echoed)
}

// walkRuns streams the runs array, enforcing the run bound as it goes.
func walkRuns(ctx context.Context, dec *json.Decoder, limits Limits, out *parsed, stats *ingestStats) error {
	if err := expectDelim(dec, '['); err != nil {
		return errNotJSON()
	}
	runIndex := 0
	for dec.More() {
		if err := ctx.Err(); err != nil {
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

// walkRun streams one run: the tool component is decoded (it carries the rule table), the results array
// is consumed one result at a time.
func walkRun(ctx context.Context, dec *json.Decoder, runIndex int, limits Limits, out *parsed, stats *ingestStats) error {
	if err := expectDelim(dec, '{'); err != nil {
		return errNotJSON()
	}
	var (
		tool       sarifTool
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
			toolSeen = true
		case "results":
			if !toolSeen {
				// Every real tool emits `tool` before `results`; a document that does not would lose its
				// rule metadata, so in that rare case the array is buffered and replayed after the run.
				if err := dec.Decode(&bufResults); err != nil {
					return errNotJSON()
				}
				continue
			}
			if err := streamResults(ctx, dec, runIndex, tool, limits, out, stats); err != nil {
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
		return streamResults(ctx, json.NewDecoder(bytes.NewReader(bufResults)), runIndex, tool, limits, out, stats)
	}
	return nil
}

// streamResults decodes one result at a time, so a run cannot force the whole results array into memory.
func streamResults(ctx context.Context, dec *json.Decoder, runIndex int, tool sarifTool, limits Limits, out *parsed, stats *ingestStats) error {
	rules, ruleIDs := indexRules(tool)
	toolName, _ := sanitizeText(tool.Driver.Name, maxIdentifierBytes, false)
	toolVersion, _ := sanitizeText(driverVersion(tool.Driver), maxIdentifierBytes, false)

	if err := expectDelim(dec, '['); err != nil {
		return errNotJSON()
	}
	resultIndex := 0
	for dec.More() {
		if resultIndex%ctxCheckEvery == 0 {
			if err := ctx.Err(); err != nil {
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
		accepted, refusal := interpretResult(runIndex, resultIndex, result, rules, ruleIDs, toolName, toolVersion, stats)
		if refusal != nil {
			out.refusals = append(out.refusals, *refusal)
		} else {
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

// indexRules collects rule metadata from the driver AND every extension, since tools split their rules
// across both. It returns the id->rule map and the ids in DOCUMENT order, which is what `ruleIndex`
// addresses — the order is computed once per run rather than rebuilt per result.
func indexRules(tool sarifTool) (map[string]sarifRule, []string) {
	out := map[string]sarifRule{}
	ordered := make([]string, 0, len(tool.Driver.Rules))
	add := func(driver sarifDriver) {
		for _, rule := range driver.Rules {
			id := strings.TrimSpace(rule.ID)
			if id == "" {
				continue
			}
			if _, exists := out[id]; !exists {
				out[id] = rule
			}
			ordered = append(ordered, id)
		}
	}
	add(tool.Driver)
	// Extensions follow the driver. A result that addresses a rule by index without naming a tool
	// component means the driver; extending the addressable range is a deliberate over-approximation so
	// documents that split rules across components still resolve, and it is deterministic either way.
	for _, extension := range tool.Extensions {
		add(extension)
	}
	return out, ordered
}

// interpretResult turns one SARIF result into a candidate, or a typed refusal.
func interpretResult(runIndex, resultIndex int, result sarifResult, rules map[string]sarifRule, ruleIDs []string,
	toolName, toolVersion string, stats *ingestStats) (*candidate, *importedfinding.RefusalReason) {
	refuse := func(code importedfinding.RefusalCode, detail string) *importedfinding.RefusalReason {
		return &importedfinding.RefusalReason{RunIndex: runIndex, ResultIndex: resultIndex, Code: code, Detail: detail}
	}

	// A result may carry ruleId, ruleIndex, or neither. Without SOME rule identity the finding cannot be
	// attributed to a rule, so it cannot be re-checked against its source.
	ruleID, _ := sanitizeText(result.RuleID, maxIdentifierBytes, false)
	if ruleID == "" && result.RuleIndex != nil {
		ruleID = ruleIDAtIndex(ruleIDs, *result.RuleIndex)
		if ruleID == "" {
			stats.unresolvedIndex++
		}
	}
	if ruleID == "" || toolName == "" || toolVersion == "" {
		return nil, refuse(importedfinding.RefusalNoProvenance,
			"result has no establishable tool and rule identity")
	}

	// Location counts are bounded. This ingester never FOLLOWS a related location, so an unbounded set
	// cannot be traversed — but an unbounded set is still a memory cost and a sign of a hostile document.
	if len(result.RelatedLocations) > maxRelatedLocations {
		return nil, refuse(importedfinding.RefusalCyclicRelation,
			"result declares more related locations than can be held safely")
	}
	if len(result.Locations) > maxLocations {
		return nil, refuse(importedfinding.RefusalMalformedResult,
			"result declares more locations than can be held safely")
	}

	location, refusal := interpretLocation(result.Locations, refuse)
	if refusal != nil {
		return nil, refusal
	}

	rule := rules[ruleID]
	severity := MapSeverity(toolName, result, rule)
	if severity == shared.SeverityUnknown {
		stats.unknownSeverity++
	}
	suppressed := isSuppressed(result.Suppressions)
	if suppressed {
		stats.suppressed++
	}

	title, titleCut := sanitizeText(firstNonEmpty(rule.ShortDescription.Text, rule.Name, ruleID), maxTitleBytes, false)
	message, messageCut := sanitizeText(result.Message.Text, maxMessageBytes, true)
	fingerprint, fingerprintCut := sanitizeText(firstFingerprint(result.PartialFingerprints), maxIdentifierBytes, false)
	for _, cut := range []bool{titleCut, messageCut, fingerprintCut} {
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

// ruleIDAtIndex resolves a `ruleIndex` against the run's rules in document order.
func ruleIDAtIndex(ruleIDs []string, index int) string {
	if index < 0 || index >= len(ruleIDs) {
		return ""
	}
	return ruleIDs[index]
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
		return importedfinding.Location{}, refuse(importedfinding.RefusalMalformedResult,
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

// repositoryRootBase reports whether a uriBaseId denotes the root of the scanned tree. Anything else is
// refused rather than assumed.
func repositoryRootBase(base string) bool {
	switch strings.ToUpper(strings.Trim(strings.TrimSpace(base), "%")) {
	case "", "SRCROOT", "PROJECTROOT", "REPOROOT", "WORKSPACEROOT", "ROOTPATH":
		return true
	}
	return false
}

// normalizeArtifactURI converts a SARIF artifact URI into a repository-relative path, or returns the
// refusal code that explains why it cannot be used.
//
// SARIF requires `artifactLocation.uri` to be a URI reference, i.e. percent-ENCODED. The value is
// therefore decoded BEFORE the traversal and absolute-path checks — checking the encoded form would let
// `%2e%2e%2f` walk straight past every guard — and a value that still carries an escape after one decode
// is refused, so double encoding cannot survive to a consumer that decodes again.
func normalizeArtifactURI(uri string) (string, importedfinding.RefusalCode) {
	if strings.IndexByte(uri, 0) >= 0 || len(uri) > maxPathBytes {
		return "", importedfinding.RefusalInvalidLocation
	}

	rest := uri
	if i := strings.Index(rest, "://"); i >= 0 {
		if !strings.EqualFold(rest[:i], "file") {
			return "", importedfinding.RefusalUnsupportedURI
		}
		parsedURI, err := url.Parse(rest)
		if err != nil {
			return "", importedfinding.RefusalInvalidLocation
		}
		// A file URI with a remote authority is not a local directory: file://evil.example/etc/passwd
		// must never be reinterpreted as the relative path "evil.example/etc/passwd".
		if host := parsedURI.Host; host != "" && !strings.EqualFold(host, "localhost") {
			return "", importedfinding.RefusalUnsupportedURI
		}
		rest = parsedURI.EscapedPath()
		if strings.HasPrefix(rest, "/") {
			return "", importedfinding.RefusalAbsolutePath
		}
	} else if code := refuseBareScheme(rest); code != "" {
		return "", code
	}

	decoded, err := url.PathUnescape(rest)
	if err != nil {
		return "", importedfinding.RefusalInvalidLocation
	}
	if containsPercentEscape(decoded) {
		return "", importedfinding.RefusalInvalidLocation
	}
	if strings.IndexByte(decoded, 0) >= 0 || !utf8.ValidString(decoded) || containsControlOrBidi(decoded) {
		return "", importedfinding.RefusalInvalidLocation
	}
	// Decoding can reveal a scheme or a Windows volume the encoded form hid.
	if code := refuseBareScheme(decoded); code != "" {
		return "", code
	}

	cleaned := strings.ReplaceAll(decoded, "\\", "/")
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

// refuseBareScheme rejects anything that is not a plain relative path: a bare scheme such as "mailto:x"
// or a Windows volume such as "C:\...".
func refuseBareScheme(p string) importedfinding.RefusalCode {
	if !strings.Contains(p, ":") || strings.HasPrefix(p, "./") {
		return ""
	}
	if looksLikeWindowsVolume(p) {
		return importedfinding.RefusalAbsolutePath
	}
	return importedfinding.RefusalUnsupportedURI
}

func looksLikeWindowsVolume(p string) bool {
	return len(p) >= 2 && p[1] == ':' &&
		((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z'))
}

func containsPercentEscape(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] == '%' && isHexDigit(s[i+1]) && isHexDigit(s[i+2]) {
			return true
		}
	}
	return false
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
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
// The lowest key wins; it is found by a single scan rather than by sorting, because a result may declare
// a very large fingerprint map.
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

// sanitizeText makes untrusted tool text safe to STORE, not merely safe to render.
//
// The report path is templated from stored data and the UI, the CSV export and the CLI all read the same
// row, so normalizing once at ingest is the only place the guarantee holds for every consumer. Control
// characters (which carry terminal escapes), C1 introducers and bidi overrides (which can make a stored
// path read as a different path) are dropped; the result is capped, and the caller records a truncation
// as a coverage issue rather than presenting a shortened value as the tool's own words.
func sanitizeText(in string, limit int, allowNewlines bool) (string, bool) {
	trimmed := strings.TrimSpace(in)
	if trimmed == "" {
		return "", false
	}
	var b strings.Builder
	b.Grow(min(len(trimmed), limit))
	truncated := false
	for _, r := range trimmed {
		if b.Len()+utf8.RuneLen(r) > limit {
			truncated = true
			break
		}
		switch {
		case r == '\t':
			b.WriteRune(r)
		case r == '\r':
			// Dropped: paired with \n it would double the line break, alone it is a cursor control.
		case r == '\n':
			if allowNewlines {
				b.WriteRune('\n')
			} else {
				b.WriteRune(' ')
			}
		case r < 0x20 || r == 0x7f:
		case r >= 0x80 && r <= 0x9f:
		case isBidiOrZeroWidth(r):
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String()), truncated
}

func containsControlOrBidi(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || isBidiOrZeroWidth(r) {
			return true
		}
	}
	return false
}

func isBidiOrZeroWidth(r rune) bool {
	switch r {
	case 0x061C, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0xFEFF:
		return true
	}
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

// Streaming helpers. They keep memory constant regardless of how large an ignored value is.

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
