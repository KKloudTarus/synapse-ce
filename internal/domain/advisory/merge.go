package advisory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrNoObservations = errors.New("no advisory observations")
	ErrAliasConflict  = errors.New("advisory alias conflict")
	cvePattern        = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
)

// Merge materializes one canonical advisory. Input order is irrelevant. All
// observations must describe one connected identity and at most one CVE.
func Merge(observations []Observation) (Canonical, error) {
	if len(observations) == 0 {
		return Canonical{}, ErrNoObservations
	}
	idsByObservation := make([][]string, 0, len(observations))
	allIDs := map[string]struct{}{}
	for _, observation := range observations {
		ids := observationIDs(observation)
		if len(ids) == 0 {
			return Canonical{}, fmt.Errorf("%w: observation has no advisory id", ErrAliasConflict)
		}
		idsByObservation = append(idsByObservation, ids)
		for _, id := range ids {
			allIDs[id] = struct{}{}
		}
	}
	if !connectedIdentity(idsByObservation) {
		return Canonical{}, fmt.Errorf("%w: observations do not share an id or alias", ErrAliasConflict)
	}

	cves := make([]string, 0, 1)
	ids := mapKeys(allIDs)
	for _, id := range ids {
		if cvePattern.MatchString(id) {
			cves = append(cves, id)
		}
	}
	if len(cves) > 1 {
		return Canonical{}, fmt.Errorf("%w: multiple CVE identities %s", ErrAliasConflict, strings.Join(cves, ", "))
	}
	canonicalID := ids[0]
	if len(cves) == 1 {
		canonicalID = cves[0]
	}
	aliases := make([]string, 0, len(ids)-1)
	for _, id := range ids {
		if id != canonicalID {
			aliases = append(aliases, id)
		}
	}

	canonical := Canonical{
		Advisory: Advisory{ID: canonicalID, Aliases: aliases},
		Status:   StatusActive,
		Sources:  observationSources(observations),
	}
	canonical.Advisory.Summary = selectSummary(observations)
	canonical.Advisory.CVSSVector, canonical.Advisory.CVSSScore = selectCVSS(observations)
	canonical.Advisory.Affected = mergeAffected(observations)
	canonical.Advisory.CPEs = mergeCPEs(observations)
	canonical.PublishedAt, canonical.ModifiedAt = mergeDates(observations)
	canonical.Status = selectStatus(observations)
	canonical.KEV = mergeBool(observations, func(observation Observation) *bool { return observation.KEV })
	canonical.PublicExploit = mergeBool(observations, func(observation Observation) *bool { return observation.PublicExploit })
	canonical.ActiveExploitation = mergeBool(observations, func(observation Observation) *bool { return observation.ActiveExploitation })
	canonical.EPSS = selectFloat(observations, func(observation Observation) *float64 { return observation.EPSS })
	canonical.EPSSPercentile = selectFloat(observations, func(observation Observation) *float64 { return observation.EPSSPercentile })
	return canonical, nil
}

func observationIDs(observation Observation) []string {
	seen := map[string]struct{}{}
	for _, raw := range append([]string{observation.Advisory.ID}, observation.Advisory.Aliases...) {
		id := normalizeID(raw)
		if id != "" {
			seen[id] = struct{}{}
		}
	}
	return mapKeys(seen)
}

func normalizeID(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}

func connectedIdentity(groups [][]string) bool {
	connected := map[string]struct{}{}
	for _, id := range groups[0] {
		connected[id] = struct{}{}
	}
	used := make([]bool, len(groups))
	used[0] = true
	for changed := true; changed; {
		changed = false
		for index, group := range groups {
			if used[index] || !intersects(group, connected) {
				continue
			}
			used[index] = true
			changed = true
			for _, id := range group {
				connected[id] = struct{}{}
			}
		}
	}
	for _, value := range used {
		if !value {
			return false
		}
	}
	return true
}

func intersects(ids []string, set map[string]struct{}) bool {
	for _, id := range ids {
		if _, ok := set[id]; ok {
			return true
		}
	}
	return false
}

func mapKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func observationSources(observations []Observation) []string {
	sources := map[string]struct{}{}
	for _, observation := range observations {
		source := strings.TrimSpace(observation.SourceID)
		if source == "" {
			source = strings.TrimSpace(observation.SourceType)
		}
		if source != "" {
			sources[source] = struct{}{}
		}
	}
	return mapKeys(sources)
}

type textCandidate struct {
	value  string
	rank   int
	when   time.Time
	source string
	record string
}

func selectSummary(observations []Observation) string {
	candidates := make([]textCandidate, 0, len(observations))
	for _, observation := range observations {
		value := strings.TrimSpace(observation.Advisory.Summary)
		if value == "" {
			continue
		}
		candidates = append(candidates, textCandidate{
			value: value, rank: fieldRank(observation.SourceType, "summary"), when: observation.ModifiedAt,
			source: observation.SourceType, record: observation.RecordID,
		})
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.Slice(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if left.rank != right.rank {
			return left.rank > right.rank
		}
		if !left.when.Equal(right.when) {
			return left.when.After(right.when)
		}
		if len(left.value) != len(right.value) {
			return len(left.value) > len(right.value)
		}
		return candidateKey(left.source, left.record, left.value) < candidateKey(right.source, right.record, right.value)
	})
	return candidates[0].value
}

type cvssCandidate struct {
	vector string
	score  float64
	rank   int
	when   time.Time
	key    string
}

func selectCVSS(observations []Observation) (string, float64) {
	candidates := make([]cvssCandidate, 0, len(observations))
	for _, observation := range observations {
		vector := strings.TrimSpace(observation.Advisory.CVSSVector)
		score := observation.Advisory.CVSSScore
		if vector == "" && score == 0 {
			continue
		}
		if math.IsNaN(score) || math.IsInf(score, 0) || score < 0 || score > 10 {
			continue
		}
		candidates = append(candidates, cvssCandidate{
			vector: vector, score: score, rank: fieldRank(observation.SourceType, "cvss"), when: observation.ModifiedAt,
			key: candidateKey(observation.SourceType, observation.RecordID, fmt.Sprintf("%s|%020.10f", vector, score)),
		})
	}
	if len(candidates) == 0 {
		return "", 0
	}
	sort.Slice(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if left.rank != right.rank {
			return left.rank > right.rank
		}
		if !left.when.Equal(right.when) {
			return left.when.After(right.when)
		}
		if (left.vector != "") != (right.vector != "") {
			return left.vector != ""
		}
		if left.score != right.score {
			return left.score > right.score
		}
		return left.key < right.key
	})
	return candidates[0].vector, candidates[0].score
}

func fieldRank(sourceType, field string) int {
	sourceType = strings.ToLower(strings.TrimSpace(sourceType))
	if field == "summary" {
		switch sourceType {
		case "csaf", "vendor-csaf":
			return 100
		case "nvd":
			return 90
		case "osv", "ghsa":
			return 80
		case "oval":
			return 70
		}
	}
	if field == "cvss" {
		switch sourceType {
		case "nvd":
			return 100
		case "csaf", "vendor-csaf":
			return 90
		case "osv", "ghsa":
			return 80
		case "oval":
			return 70
		}
	}
	if field == "status" {
		switch sourceType {
		case "nvd":
			return 100
		case "csaf", "vendor-csaf":
			return 90
		case "oval":
			return 80
		case "osv", "ghsa":
			return 70
		}
	}
	return 10
}

func candidateKey(parts ...string) string {
	return strings.Join(parts, "\x00")
}

func mergeDates(observations []Observation) (time.Time, time.Time) {
	var published, modified time.Time
	for _, observation := range observations {
		if !observation.PublishedAt.IsZero() && (published.IsZero() || observation.PublishedAt.Before(published)) {
			published = observation.PublishedAt.UTC()
		}
		if !observation.ModifiedAt.IsZero() && observation.ModifiedAt.After(modified) {
			modified = observation.ModifiedAt.UTC()
		}
	}
	return published, modified
}

func selectStatus(observations []Observation) Status {
	type statusCandidate struct {
		status Status
		rank   int
		when   time.Time
		key    string
	}
	candidates := make([]statusCandidate, 0, len(observations))
	for _, observation := range observations {
		if !observation.Status.Valid() {
			continue
		}
		candidates = append(candidates, statusCandidate{
			status: observation.Status, rank: fieldRank(observation.SourceType, "status"), when: observation.ModifiedAt,
			key: candidateKey(observation.SourceType, observation.RecordID, string(observation.Status)),
		})
	}
	if len(candidates) == 0 {
		return StatusActive
	}
	sort.Slice(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if left.rank != right.rank {
			return left.rank > right.rank
		}
		if !left.when.Equal(right.when) {
			return left.when.After(right.when)
		}
		return left.key < right.key
	})
	return candidates[0].status
}

func mergeBool(observations []Observation, value func(Observation) *bool) *bool {
	seen := false
	for _, observation := range observations {
		candidate := value(observation)
		if candidate == nil {
			continue
		}
		seen = true
		if *candidate {
			result := true
			return &result
		}
	}
	if !seen {
		return nil
	}
	result := false
	return &result
}

func selectFloat(observations []Observation, value func(Observation) *float64) *float64 {
	type floatCandidate struct {
		value float64
		when  time.Time
		key   string
	}
	candidates := make([]floatCandidate, 0, len(observations))
	for _, observation := range observations {
		candidate := value(observation)
		if candidate == nil || math.IsNaN(*candidate) || math.IsInf(*candidate, 0) || *candidate < 0 || *candidate > 1 {
			continue
		}
		candidates = append(candidates, floatCandidate{value: *candidate, when: observation.ModifiedAt, key: candidateKey(observation.SourceType, observation.RecordID)})
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		if !candidates[i].when.Equal(candidates[j].when) {
			return candidates[i].when.After(candidates[j].when)
		}
		return candidates[i].key < candidates[j].key
	})
	result := candidates[0].value
	return &result
}

func mergeAffected(observations []Observation) []AffectedPackage {
	byKey := map[string]AffectedPackage{}
	for _, observation := range observations {
		for _, affected := range observation.Advisory.Affected {
			normalized := normalizeAffected(affected)
			if normalized.Ecosystem == "" || normalized.Package == "" {
				continue
			}
			encoded, _ := json.Marshal(normalized)
			byKey[string(encoded)] = normalized
		}
	}
	keys := mapKeysAny(byKey)
	result := make([]AffectedPackage, 0, len(keys))
	for _, key := range keys {
		result = append(result, byKey[key])
	}
	return result
}

func mergeCPEs(observations []Observation) []CPEMatch {
	byKey := map[string]CPEMatch{}
	for _, observation := range observations {
		for _, current := range observation.Advisory.CPEs {
			current.Criteria = strings.TrimSpace(current.Criteria)
			current.VersionStartIncluding = strings.TrimSpace(current.VersionStartIncluding)
			current.VersionStartExcluding = strings.TrimSpace(current.VersionStartExcluding)
			current.VersionEndIncluding = strings.TrimSpace(current.VersionEndIncluding)
			current.VersionEndExcluding = strings.TrimSpace(current.VersionEndExcluding)
			if current.Criteria == "" {
				continue
			}
			encoded, _ := json.Marshal(current)
			byKey[string(encoded)] = current
		}
	}
	keys := mapKeysAny(byKey)
	result := make([]CPEMatch, 0, len(keys))
	for _, key := range keys {
		result = append(result, byKey[key])
	}
	return result
}

func normalizeAffected(affected AffectedPackage) AffectedPackage {
	affected.Ecosystem = strings.TrimSpace(affected.Ecosystem)
	affected.Package = strings.TrimSpace(affected.Package)
	affected.FixedVersion = strings.TrimSpace(affected.FixedVersion)
	affected.Versions = uniqueSorted(affected.Versions)
	ranges := map[string]Range{}
	for _, current := range affected.Ranges {
		current.Type = strings.ToUpper(strings.TrimSpace(current.Type))
		events := make([]Event, 0, len(current.Events))
		for _, event := range current.Events {
			event.Introduced = strings.TrimSpace(event.Introduced)
			event.Fixed = strings.TrimSpace(event.Fixed)
			event.LastAffected = strings.TrimSpace(event.LastAffected)
			if event.Introduced != "" || event.Fixed != "" || event.LastAffected != "" {
				events = append(events, event)
			}
		}
		current.Events = events
		encoded, _ := json.Marshal(current)
		ranges[string(encoded)] = current
	}
	rangeKeys := mapKeysAny(ranges)
	affected.Ranges = make([]Range, 0, len(rangeKeys))
	for _, key := range rangeKeys {
		affected.Ranges = append(affected.Ranges, ranges[key])
	}
	return affected
}

func uniqueSorted(values []string) []string {
	unique := map[string]struct{}{}
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			unique[value] = struct{}{}
		}
	}
	return mapKeys(unique)
}

func mapKeysAny[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// ContentHash returns the SHA-256 of the canonical, sorted JSON representation.
func (canonical Canonical) ContentHash() (string, error) {
	data, err := canonicalJSON(canonical)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// CanonicalJSON returns the same normalized representation used by ContentHash.
// Persistence uses this snapshot so the stored revision and its hash cannot drift.
func (canonical Canonical) CanonicalJSON() ([]byte, error) { return canonicalJSON(canonical) }

func canonicalJSON(canonical Canonical) ([]byte, error) {
	canonical.Advisory.ID = normalizeID(canonical.Advisory.ID)
	canonical.Advisory.Aliases = uniqueSortedIDs(canonical.Advisory.Aliases, canonical.Advisory.ID)
	canonical.Advisory.Affected = mergeAffected([]Observation{{Advisory: canonical.Advisory}})
	canonical.Sources = uniqueSorted(canonical.Sources)
	canonical.PublishedAt = canonical.PublishedAt.UTC()
	canonical.ModifiedAt = canonical.ModifiedAt.UTC()
	return json.Marshal(canonical)
}

func uniqueSortedIDs(values []string, exclude string) []string {
	unique := map[string]struct{}{}
	for _, value := range values {
		if value = normalizeID(value); value != "" && value != exclude {
			unique[value] = struct{}{}
		}
	}
	return mapKeys(unique)
}

// Diff returns changed canonical fields in a fixed semantic order.
func Diff(previous, next Canonical) []ChangedField {
	changes := make([]ChangedField, 0, 9)
	if previous.Advisory.ID != next.Advisory.ID {
		changes = append(changes, ChangedIdentity)
	}
	if !reflect.DeepEqual(previous.Advisory.Aliases, next.Advisory.Aliases) {
		changes = append(changes, ChangedAliases)
	}
	if previous.Advisory.Summary != next.Advisory.Summary {
		changes = append(changes, ChangedSummary)
	}
	if previous.Advisory.CVSSVector != next.Advisory.CVSSVector || previous.Advisory.CVSSScore != next.Advisory.CVSSScore {
		changes = append(changes, ChangedCVSS)
	}
	if !previous.PublishedAt.Equal(next.PublishedAt) || !previous.ModifiedAt.Equal(next.ModifiedAt) {
		changes = append(changes, ChangedDates)
	}
	if !reflect.DeepEqual(previous.Advisory.Affected, next.Advisory.Affected) || !reflect.DeepEqual(previous.Advisory.CPEs, next.Advisory.CPEs) {
		changes = append(changes, ChangedAffected)
	}
	if previous.Status != next.Status {
		changes = append(changes, ChangedStatus)
	}
	if !reflect.DeepEqual(previous.KEV, next.KEV) || !reflect.DeepEqual(previous.EPSS, next.EPSS) ||
		!reflect.DeepEqual(previous.EPSSPercentile, next.EPSSPercentile) || !reflect.DeepEqual(previous.PublicExploit, next.PublicExploit) ||
		!reflect.DeepEqual(previous.ActiveExploitation, next.ActiveExploitation) {
		changes = append(changes, ChangedExploitability)
	}
	if !reflect.DeepEqual(previous.Sources, next.Sources) {
		changes = append(changes, ChangedSources)
	}
	return changes
}
