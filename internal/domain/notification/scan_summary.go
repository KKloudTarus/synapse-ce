package notification

import (
	"sort"
	"strconv"
	"strings"

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

const maxScanSummaryFindings = 10000

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
// For N observations (benchmarked at 10k and 100k), exact dedup needs O(N) space.
// Presentation maintains a sorted prefix of k=50: O(N*k) worst-case insertion,
// with text scrubbing only for those k values. The small ordered slice avoids a
// heap and a second sort while preserving severity/identity order after each item.
func NewScanSummary(targetKey, kind string, coverageComplete bool, input []finding.Finding) ScanSummary {
	result := ScanSummary{TargetKey: strings.TrimSpace(targetKey), Kind: strings.TrimSpace(kind), CoverageComplete: coverageComplete}
	seen := make(map[string]struct{}, len(input))
	for i := range input {
		item := &input[i]
		if !item.CanPromote() {
			continue
		}
		identity := strings.TrimSpace(item.DedupKey)
		if identity == "" {
			// A per-run row ID is useful to display one item, but is not evidence
			// that two runs observed the same finding. Never derive a delta from it.
			identity = strings.TrimSpace(item.ID.String())
			result.Unstable = true
		}
		if identity == "" {
			result.Unstable = true
			identity = "unstable-" + strconv.Itoa(len(seen))
		}
		if _, exists := seen[identity]; exists {
			continue
		}
		seen[identity] = struct{}{}
		result.Total++
		switch item.Severity {
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
		candidate := ScanFinding{
			Identity: identity, ID: item.ID.String(), Severity: item.Severity,
			Title: item.Title, Status: string(item.Status),
		}
		result.addPresentationFinding(candidate)
		if len(result.Keys) >= maxScanSummaryFindings {
			result.Truncated = true
			continue
		}
		result.Keys = append(result.Keys, identity)
	}
	for i := range result.Findings {
		result.Findings[i].ID = summaryPresentationString(result.Findings[i].ID)
		result.Findings[i].Title = summaryPresentationString(result.Findings[i].Title)
	}
	sort.Strings(result.Keys)
	return result
}

func summaryPresentationString(value string) string {
	return boundRunes(snapshotString(value), 1000)
}

func (s *ScanSummary) addPresentationFinding(candidate ScanFinding) {
	position := sort.Search(len(s.Findings), func(i int) bool {
		stored := s.Findings[i]
		if left, right := shared.SeverityRank(candidate.Severity), shared.SeverityRank(stored.Severity); left != right {
			return left > right
		}
		if candidate.Identity != stored.Identity {
			return candidate.Identity < stored.Identity
		}
		return candidate.ID < stored.ID
	})
	if position >= 50 {
		return
	}
	if len(s.Findings) < 50 {
		s.Findings = append(s.Findings, ScanFinding{})
	}
	copy(s.Findings[position+1:], s.Findings[position:len(s.Findings)-1])
	s.Findings[position] = candidate
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
	current.BaselineJobID = strings.TrimSpace(baselineJobID)
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
