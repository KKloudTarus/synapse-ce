package ownership

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Input describes only routing-relevant facts, never mutable scanner counters,
// finding timestamps, or its optimistic version. Paths must be application source
// or introducing manifest locations from SourceRevision, not dependency vendor paths.
type Input struct {
	TenantID       shared.ID       `json:"tenant_id"`
	EngagementID   shared.ID       `json:"engagement_id"`
	FindingID      shared.ID       `json:"finding_id"`
	Repository     string          `json:"repository"`
	ProjectIDs     []shared.ID     `json:"project_ids"`
	AssetIDs       []shared.ID     `json:"asset_ids"`
	Kind           string          `json:"kind"`
	Severity       shared.Severity `json:"severity"`
	Paths          []string        `json:"paths"`
	SourceRevision string          `json:"source_revision"`
	SourceBound    bool            `json:"source_bound"`
	Supported      bool            `json:"supported"`
	Current        Assignment      `json:"current"`
	// Only policy-referenced teams are needed; eligibility is checked again at commit.
	ActiveTeams []shared.ID `json:"active_teams"`
}

type compiledRule struct {
	rule  Rule
	paths []*regexp.Regexp
}

type Resolver struct {
	policy     PolicyVersion
	hash       string
	snapshot   *Snapshot
	codeowners Codeowners
	rules      []compiledRule
	mappings   map[string]Mapping
	assets     map[shared.ID]shared.ID
}

func NewResolver(policy PolicyVersion, snapshot *Snapshot) (*Resolver, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	// Own all slices so a draft editor cannot mutate an already compiled version.
	encoded, _ := json.Marshal(policy)
	var frozen PolicyVersion
	if err := json.Unmarshal(encoded, &frozen); err != nil {
		return nil, err
	}
	frozen.TenantID = policy.TenantID
	r := &Resolver{policy: frozen, hash: policy.Hash(), mappings: map[string]Mapping{}, assets: map[shared.ID]shared.ID{}}
	if !policy.SnapshotID.IsZero() {
		if snapshot == nil || snapshot.ID != policy.SnapshotID || snapshot.TenantID != policy.TenantID || snapshot.EngagementID != policy.EngagementID || policy.Repository != "" && snapshot.Repository != policy.Repository {
			return nil, invalid("policy snapshot binding")
		}
		copy := *snapshot
		parsed, err := copy.Parse()
		if err != nil {
			return nil, err
		}
		r.snapshot, r.codeowners = &copy, parsed
	} else if snapshot != nil {
		return nil, invalid("unexpected snapshot")
	}
	sort.Slice(frozen.Rules, func(i, j int) bool { return frozen.Rules[i].Priority < frozen.Rules[j].Priority })
	for _, rule := range frozen.Rules {
		compiled := compiledRule{rule: rule}
		for _, pattern := range rule.When.Paths {
			m, err := compilePattern(pattern)
			if err != nil {
				return nil, err
			}
			compiled.paths = append(compiled.paths, m)
		}
		r.rules = append(r.rules, compiled)
	}
	for _, m := range frozen.Mappings {
		r.mappings[m.Repository+"\x00"+m.Owner] = m
	}
	for _, a := range frozen.Assets {
		r.assets[a.AssetID] = a.TeamID
	}
	return r, nil
}

func (r *Resolver) Resolve(input Input) (Result, error) {
	out := Result{Resolution: Unresolved, Reason: "no_matching_owner", Candidates: []shared.ID{}, Evidence: []PathEvidence{}, PolicyHash: r.hash}
	if input.TenantID != r.policy.TenantID || input.EngagementID != r.policy.EngagementID || input.FindingID.IsZero() || r.policy.Repository != "" && input.Repository != r.policy.Repository {
		return out, invalid("input scope")
	}
	if len(input.Paths) > MaxPaths || len(input.ProjectIDs) > 200 || len(input.AssetIDs) > 200 || len(input.ActiveTeams) > 20_000 {
		return out, invalid("input bounds")
	}
	if err := input.Current.Validate(); err != nil {
		return out, err
	}
	paths := make([]string, 0, len(input.Paths))
	invalidPath := false
	for _, raw := range input.Paths {
		if len(raw) > MaxPathBytes {
			return out, invalid("input path size")
		}
		path, err := NormalizePath(raw)
		if err != nil {
			invalidPath = true
			path = raw
		}
		paths = append(paths, path)
	}
	input.Paths = sortedUnique(paths)
	paths = input.Paths
	input.ProjectIDs = sortedUnique(input.ProjectIDs)
	input.AssetIDs = sortedUnique(input.AssetIDs)
	input.ActiveTeams = sortedUnique(input.ActiveTeams)
	// Optimistic versions are checked at persistence, not part of routing identity.
	fingerprint := input
	fingerprint.Current.Revision = 0
	encoded, _ := json.Marshal(fingerprint)
	out.InputHash = ContentHash(string(encoded))
	if r.snapshot != nil {
		out.SnapshotHash = r.snapshot.Hash
	}
	if input.Current.Mode == "manual" || input.Current.LegacyAssignee != "" {
		out.Reason = "manual_protected"
		out.TeamID = input.Current.TeamID
		if !out.TeamID.IsZero() {
			out.Resolution = Resolved
			out.Candidates = []shared.ID{out.TeamID}
		}
		return out, nil
	}
	if !input.Supported {
		out.Resolution = Unsupported
		out.Reason = "unsupported_finding"
		return out, nil
	}
	if invalidPath {
		out.Reason = "invalid_path"
		return out, nil
	}
	patternCount := len(r.codeowners.Patterns)
	for _, rule := range r.rules {
		patternCount += len(rule.paths)
	}
	pathBytes := 0
	for _, path := range paths {
		pathBytes += len(path)
	}
	if int64(pathBytes)*int64(patternCount) > MaxMatchWork {
		return out, fmt.Errorf("%w: ownership matcher work limit exceeded", shared.ErrSaturated)
	}
	for _, compiled := range r.rules {
		if ruleMatches(compiled, input, paths) {
			out.RuleID = compiled.rule.ID
			if compiled.rule.Exclude {
				out.Resolution = Excluded
				out.Reason = "explicit_exclusion"
				return out, nil
			}
			out.Reason = "explicit_rule"
			return resolveTeams(out, []shared.ID{compiled.rule.TeamID}, input.ActiveTeams), nil
		}
	}
	if len(paths) > 0 {
		if !input.SourceBound || !PinnedRevision(input.SourceRevision) || input.Repository == "" {
			out.Reason = "missing_source_binding"
			return out, nil
		}
		if r.snapshot != nil {
			if r.snapshot.Repository != input.Repository {
				out.Reason = "snapshot_repository_mismatch"
				return out, nil
			}
			if r.snapshot.Trust == "untrusted" {
				out.Reason = "untrusted_snapshot"
				return out, nil
			}
			if len(r.codeowners.Diagnostics) > 0 && !r.snapshot.AcceptDiagnostics {
				out.Reason = "unaccepted_diagnostics"
				return out, nil
			}
			var candidates []shared.ID
			missing, excluded, matched := false, false, false
			for _, path := range paths {
				pattern, ok := r.codeowners.Match(path)
				evidence := PathEvidence{Path: path, Reason: "no_matching_pattern"}
				if !ok {
					missing = true
					out.Evidence = append(out.Evidence, evidence)
					continue
				}
				matched = true
				evidence.Line = pattern.Line
				evidence.Pattern = pattern.Text
				evidence.Owners = pattern.Owners
				evidence.Reason = "codeowners"
				if len(pattern.Owners) == 0 {
					excluded = true
					evidence.Reason = "codeowners_exclusion"
				}
				for _, owner := range pattern.Owners {
					mapping, ok := r.mappings[input.Repository+"\x00"+owner]
					if !ok {
						missing = true
						evidence.Reason = "unmapped_owner"
						continue
					}
					candidates = append(candidates, mapping.TeamID)
				}
				out.Evidence = append(out.Evidence, evidence)
			}
			if matched {
				out.Candidates = sortedUnique(candidates)
				if missing {
					out.Reason = "incomplete_ownership"
					return out, nil
				}
				if excluded {
					if len(candidates) == 0 {
						out.Resolution = Excluded
						out.Reason = "codeowners_exclusion"
					} else {
						out.Resolution = Ambiguous
						out.Reason = "mixed_exclusion"
					}
					return out, nil
				}
				out.Reason = "codeowners"
				return resolveTeams(out, candidates, input.ActiveTeams), nil
			}
		}
	}
	var candidates []shared.ID
	for _, id := range input.AssetIDs {
		if team, ok := r.assets[id]; ok {
			candidates = append(candidates, team)
		}
	}
	if len(candidates) > 0 {
		out.Reason = "business_asset"
		return resolveTeams(out, candidates, input.ActiveTeams), nil
	}
	return out, nil
}

func resolveTeams(out Result, candidates, active []shared.ID) Result {
	out.Candidates = sortedUnique(candidates)
	for _, team := range out.Candidates {
		if !slices.Contains(active, team) {
			out.Resolution = Unresolved
			out.Reason = "inactive_team"
			return out
		}
	}
	if len(out.Candidates) > 1 {
		out.Resolution = Ambiguous
		out.Reason = "multiple_teams"
	} else if len(out.Candidates) == 1 {
		out.Resolution = Resolved
		out.TeamID = out.Candidates[0]
	}
	return out
}

func ruleMatches(compiled compiledRule, input Input, paths []string) bool {
	c := compiled.rule.When
	if len(c.EngagementIDs) > 0 && !slices.Contains(c.EngagementIDs, input.EngagementID) || len(c.Repositories) > 0 && !slices.Contains(c.Repositories, input.Repository) || len(c.Kinds) > 0 && !slices.Contains(c.Kinds, input.Kind) || len(c.Severities) > 0 && !slices.Contains(c.Severities, input.Severity) || len(c.ProjectIDs) > 0 && !intersects(c.ProjectIDs, input.ProjectIDs) || len(c.AssetIDs) > 0 && !intersects(c.AssetIDs, input.AssetIDs) {
		return false
	}
	if len(compiled.paths) == 0 {
		return true
	}
	if !input.SourceBound || !PinnedRevision(input.SourceRevision) {
		return false
	}
	// Every relevant path must be covered by a path rule. A rule matching just one
	// manifest must not hide another introducing dependency owned by a different team.
	if len(paths) == 0 {
		return false
	}
	for _, path := range paths {
		matched := false
		for _, pattern := range compiled.paths {
			if pattern.MatchString(path) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func intersects[T comparable](a, b []T) bool {
	for _, v := range a {
		if slices.Contains(b, v) {
			return true
		}
	}
	return false
}
func sortedUnique[T ~string](values []T) []T {
	out := append([]T{}, values...)
	slices.Sort(out)
	return slices.Compact(out)
}

// TransitionKey separates request replay from optimistic finding versions.
func TransitionKey(tenant, finding shared.ID, inputHash, policyHash string, generation int64) string {
	encoded, _ := json.Marshal([]string{tenant.String(), finding.String(), inputHash, policyHash, fmt.Sprint(generation)})
	return ContentHash(string(encoded))
}
