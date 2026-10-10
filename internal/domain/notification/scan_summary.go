package notification

import (
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ScanFinding is the bounded, public-safe part of a finding used by a
// scan.completed notification. Identity is retained internally for deterministic
// comparison; templates receive only the explicitly declared presentation fields.
type ScanFinding struct {
	Identity string          `json:"identity"`
	ID       string          `json:"id"`
	Severity shared.Severity `json:"severity"`
	Title    string          `json:"title"`
	Status   string          `json:"status"`
}

// ScanSummary is persisted with the scan job at its terminal transition. It is
// an internal snapshot, not an event payload: it lets the notification capture
// path read the exact successful scan without consulting mutable finding rows.
type ScanSummary struct {
	TargetKey        string `json:"target_key"`
	Kind             string `json:"kind"`
	CoverageComplete bool   `json:"coverage_complete"`
	Truncated        bool   `json:"truncated"`
	Unstable         bool   `json:"unstable"`
	// Keys contains stable identities for comparison and is never exposed to a
	// template. Findings contains only the top presentation items.
	Keys           []string      `json:"keys"`
	Findings       []ScanFinding `json:"findings"`
	Total          int           `json:"total"`
	Critical       int           `json:"critical"`
	High           int           `json:"high"`
	Medium         int           `json:"medium"`
	Low            int           `json:"low"`
	Info           int           `json:"info"`
	New            int           `json:"new"`
	Fixed          int           `json:"fixed"`
	Unchanged      int           `json:"unchanged"`
	DeltaAvailable bool          `json:"delta_available"`
	BaselineJobID  string        `json:"baseline_job_id,omitempty"`
}

type scanSummaryCandidate struct {
	identity string
	id       string
	severity shared.Severity
	title    string
	status   string
}

const (
	maxScanSummaryFindings          = 10000
	maxScanSummaryEncodedBytes      = 768 * 1024
	maxScanSummaryKeyJSONBytes      = 192 * 1024
	maxScanSummaryIdentityBytes     = 4096
	maxScanSummaryPresentationID    = 512
	maxScanSummaryTargetKeyBytes    = 512
	maxScanSummaryKindBytes         = 64
	maxScanSummaryBaselineIDBytes   = 128
	maxScanSummaryPresentationBytes = 256
	maxScanSummaryStatusBytes       = 64
	unavailableComparisonScalar     = "[unavailable]"
)

// CanonicalScanTarget returns the comparison identity for a scan target. Repository
// and OCI references have established canonicalizers; local paths and uploaded
// source IDs are already authorized server-side values and may be case-sensitive.
func CanonicalScanTarget(target, kind string) string {
	raw := strings.TrimSpace(target)
	switch kind {
	case "git":
		if identity, err := scanrun.CanonicalizeRepositoryTarget(raw, strings.Repeat("0", 40)); err == nil {
			return identity.TargetIdentityCanonical
		}
	case "image":
		if identity, err := scanrun.CanonicalizeOCITarget(raw); err == nil {
			return identity.TargetIdentityCanonical
		}
	}
	return raw
}

// NewScanSummary filters findings through the common publication policy,
// deduplicates their stable identities and stores at most 10,000 entries. A
// truncated snapshot can still report aggregate counts but never fabricates a
// fixed/new delta.
// For N observations, exact dedup needs O(N) space. Retained comparison keys are
// capped both by count and a conservative encoded-JSON budget. Presentation keeps
// a sorted prefix of k=50, so selecting it is O(N*k) and never serializes the
// whole snapshot per observation.
func NewScanSummary(targetKey, kind string, coverageComplete bool, input []finding.Finding) ScanSummary {
	result := ScanSummary{CoverageComplete: coverageComplete}
	if value, ok := boundedComparisonScalar(targetKey, maxScanSummaryTargetKeyBytes); ok {
		result.TargetKey = value
	} else {
		// Keep the successful result snapshot available to notification capture,
		// while Unstable prevents this placeholder from ever matching another
		// admission identity.
		result.TargetKey = unavailableComparisonScalar
		result.Unstable = true
	}
	if value, ok := boundedComparisonScalar(kind, maxScanSummaryKindBytes); ok {
		result.Kind = value
	} else {
		result.Kind = unavailableComparisonScalar
		result.Unstable = true
	}

	type dedupKey struct {
		stable bool
		value  string
	}
	candidates := make(map[dedupKey]scanSummaryCandidate, len(input))
	stableIdentities := make([]string, 0, min(len(input), maxScanSummaryFindings))
	for i := range input {
		item := &input[i]
		if !item.CanPromote() {
			continue
		}
		identity := strings.TrimSpace(item.DedupKey)
		stableIdentity := false
		var key dedupKey
		if value, ok := boundedComparisonScalar(identity, maxScanSummaryIdentityBytes); ok {
			identity, stableIdentity, key = value, true, dedupKey{stable: true, value: value}
		} else {
			// An invalid or oversized key can still be used transiently to avoid
			// inflating aggregate counts, but must never become a persisted
			// comparison identity. A missing key uses the row id only for that
			// transient aggregation; it is never comparable across scans.
			result.Unstable = true
			fallback := strings.TrimSpace(item.ID.String())
			if fallback == "" {
				fallback = strconv.Itoa(i)
			}
			if identity != "" {
				fallback = identity
			}
			key = dedupKey{value: fallback}
		}
		candidate := scanSummaryCandidate{id: item.ID.String(), severity: item.Severity, title: item.Title, status: string(item.Status)}
		if stableIdentity {
			candidate.identity = identity
		}
		if existing, exists := candidates[key]; exists {
			if scanSummaryCandidateLess(candidate, existing) {
				candidates[key] = candidate
			}
			continue
		}
		candidates[key] = candidate
		result.Total++
		if stableIdentity {
			stableIdentities = append(stableIdentities, identity)
		}
	}
	// Counts describe the same deterministic representative selected for each
	// deduplicated key. Counting on first observation would make a high/critical
	// duplicate pair depend on source iteration order.
	for _, candidate := range candidates {
		switch candidate.severity {
		case shared.SeverityCritical:
			result.Critical++
		case shared.SeverityHigh:
			result.High++
		case shared.SeverityMedium:
			result.Medium++
		case shared.SeverityLow:
			result.Low++
		case shared.SeverityInfo:
			result.Info++
		}
	}
	sort.Strings(stableIdentities)
	keyBytes := 2 // []
	for _, identity := range stableIdentities {
		encoded := encodedJSONStringBytes(identity)
		if len(result.Keys) >= maxScanSummaryFindings || keyBytes+encoded+len(result.Keys) > maxScanSummaryKeyJSONBytes {
			result.Truncated = true
			continue
		}
		result.Keys = append(result.Keys, identity)
		keyBytes += encoded
	}
	top := make([]scanSummaryCandidate, 0, 50)
	for _, candidate := range candidates {
		top = addScanSummaryCandidate(top, candidate)
	}
	for _, candidate := range top {
		result.Findings = append(result.Findings, candidate.presentation())
	}
	return result
}

func summaryPresentationString(value string) string {
	return boundUTF8Bytes(snapshotString(value), maxScanSummaryPresentationBytes)
}

func summaryPresentationStatus(value string) string {
	return boundUTF8Bytes(snapshotString(value), maxScanSummaryStatusBytes)
}

func summaryPresentationSeverity(value shared.Severity) shared.Severity {
	if value.Valid() {
		return value
	}
	return shared.SeverityUnknown
}

// boundedComparisonScalar never truncates a comparison identity: retaining a
// prefix would create a different stable key and could fabricate a delta.
func boundedComparisonScalar(value string, maxBytes int) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 || len(value) > maxBytes {
		return "", false
	}
	return value, true
}

func boundUTF8Bytes(value string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= maxBytes {
		return value
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}

// encodedJSONStringBytes is the exact byte length encoding/json uses for a
// valid string. It lets the retained-key cap account for escaping without
// repeatedly serializing the full snapshot while observations are processed.
func encodedJSONStringBytes(value string) int {
	n := 2 // quotes
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '\\', '"', '\n', '\r', '\t', '\b', '\f':
			n += 2
		case '<', '>', '&':
			n += 6
		default:
			if value[i] < 0x20 {
				n += 6
			} else if i+2 < len(value) && value[i] == 0xe2 && value[i+1] == 0x80 && (value[i+2] == 0xa8 || value[i+2] == 0xa9) {
				n += 6
				i += 2
			} else {
				n++
			}
		}
	}
	return n
}

func (c scanSummaryCandidate) presentation() ScanFinding {
	identity := ""
	if value, ok := boundedComparisonScalar(c.identity, maxScanSummaryPresentationID); ok {
		identity = value
	}
	return ScanFinding{
		Identity: identity,
		ID:       summaryPresentationString(c.id),
		Severity: summaryPresentationSeverity(c.severity),
		Title:    summaryPresentationString(c.title),
		Status:   summaryPresentationStatus(c.status),
	}
}

func scanSummaryCandidateLess(left, right scanSummaryCandidate) bool {
	if leftRank, rightRank := shared.SeverityRank(left.severity), shared.SeverityRank(right.severity); leftRank != rightRank {
		return leftRank > rightRank
	}
	if left.identity != right.identity {
		return left.identity < right.identity
	}
	if left.id != right.id {
		return left.id < right.id
	}
	if left.title != right.title {
		return left.title < right.title
	}
	return left.status < right.status
}

func addScanSummaryCandidate(top []scanSummaryCandidate, candidate scanSummaryCandidate) []scanSummaryCandidate {
	position := sort.Search(len(top), func(i int) bool {
		return scanSummaryCandidateLess(candidate, top[i])
	})
	if position >= 50 {
		return top
	}
	if len(top) < 50 {
		top = append(top, scanSummaryCandidate{})
	}
	copy(top[position+1:], top[position:len(top)-1])
	top[position] = candidate
	return top
}

// WithBaseline produces the counts for a prior compatible successful scan. An
// incomplete, truncated, different-target or different-kind scan is deliberately
// unknown rather than presenting a plausible but false fixed count.
func (current ScanSummary) WithBaseline(previous ScanSummary) ScanSummary {
	return current.WithBaselineID(previous, "")
}

// WithBaselineID retains the persisted predecessor identity for deterministic
// history inspection. It remains internal to the job snapshot.
func (current ScanSummary) WithBaselineID(previous ScanSummary, baselineJobID string) ScanSummary {
	current.New, current.Fixed, current.Unchanged, current.DeltaAvailable, current.BaselineJobID = 0, 0, 0, false, ""
	if !current.comparableTo(previous) {
		return current
	}
	old := make(map[string]struct{}, len(previous.Keys))
	for _, identity := range previous.Keys {
		old[identity] = struct{}{}
	}
	next := make(map[string]struct{}, len(current.Keys))
	for _, identity := range current.Keys {
		next[identity] = struct{}{}
		if _, present := old[identity]; present {
			current.Unchanged++
		} else {
			current.New++
		}
	}
	for identity := range old {
		if _, present := next[identity]; !present {
			current.Fixed++
		}
	}
	current.DeltaAvailable = true
	if value, ok := boundedComparisonScalar(baselineJobID, maxScanSummaryBaselineIDBytes); ok {
		current.BaselineJobID = value
	}
	return current
}

func (current ScanSummary) comparableTo(previous ScanSummary) bool {
	return current.CoverageComplete && previous.CoverageComplete &&
		!current.Truncated && !previous.Truncated && !current.Unstable && !previous.Unstable &&
		current.TargetKey != "" && current.TargetKey == previous.TargetKey &&
		current.Kind != "" && current.Kind == previous.Kind
}

// TemplateValues exposes only the catalog contract. Stable identities and
// target-comparison data remain internal to the scan-job snapshot.
func (s ScanSummary) TemplateValues() (map[string]string, map[string][]map[string]string) {
	values := map[string]string{
		"total_count":     strconv.Itoa(s.Total),
		"critical_count":  strconv.Itoa(s.Critical),
		"high_count":      strconv.Itoa(s.High),
		"medium_count":    strconv.Itoa(s.Medium),
		"low_count":       strconv.Itoa(s.Low),
		"info_count":      strconv.Itoa(s.Info),
		"new_count":       strconv.Itoa(s.New),
		"fixed_count":     strconv.Itoa(s.Fixed),
		"unchanged_count": strconv.Itoa(s.Unchanged),
		"delta_available": strconv.FormatBool(s.DeltaAvailable),
	}
	items := make([]map[string]string, 0, min(len(s.Findings), 50))
	for i, item := range s.Findings {
		if i == 50 {
			break
		}
		items = append(items, map[string]string{
			"id": item.ID, "severity": string(item.Severity), "title": item.Title, "status": item.Status,
		})
	}
	if len(items) == 0 {
		return values, nil
	}
	return values, map[string][]map[string]string{"findings": items}
}

// Clone protects memory repositories and callers from sharing mutable slices.
func (s ScanSummary) Clone() ScanSummary {
	s.Keys = append([]string(nil), s.Keys...)
	s.Findings = append([]ScanFinding(nil), s.Findings...)
	return s
}
