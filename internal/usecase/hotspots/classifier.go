// Package hotspots contains Project Security Hotspot projection use cases.
package hotspots

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Classify separates normal publishable findings from catalog-backed hotspot
// candidates. Unknown rules fail closed as normal findings; catalog failures other
// than a not-found lookup are returned because an unavailable catalog must not make
// a Project analysis appear complete with an incomplete projection.
func Classify(ctx context.Context, findings []finding.Finding, catalog ports.RuleCatalog) ([]finding.Finding, []hotspot.Candidate, error) {
	issues := make([]finding.Finding, 0, len(findings))
	byKey := make(map[string]hotspot.Candidate)
	for _, item := range findings {
		candidate, ok, err := classifyOne(ctx, item, catalog)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			issues = append(issues, item)
			continue
		}
		if current, exists := byKey[candidate.Key]; !exists || candidateLess(candidate, current) {
			byKey[candidate.Key] = candidate
		}
	}

	candidates := make([]hotspot.Candidate, 0, len(byKey))
	for _, candidate := range byKey {
		candidates = append(candidates, candidate)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Key < candidates[j].Key })
	return issues, candidates, nil
}

func classifyOne(ctx context.Context, item finding.Finding, catalog ports.RuleCatalog) (hotspot.Candidate, bool, error) {
	key := finding.Identity(item)
	if strings.TrimSpace(item.RuleKey) == "" || key == "" || catalog == nil {
		return hotspot.Candidate{}, false, nil
	}
	r, err := catalog.Get(ctx, rule.Key(strings.TrimSpace(item.RuleKey)))
	if errors.Is(err, shared.ErrNotFound) {
		return hotspot.Candidate{}, false, nil
	}
	if err != nil {
		return hotspot.Candidate{}, false, fmt.Errorf("resolve hotspot rule %q: %w", item.RuleKey, err)
	}
	if r.Type != rule.TypeSecurityHotspot {
		return hotspot.Candidate{}, false, nil
	}
	location := ""
	if file, line, ok := qualitygate.FileLineOf(item.DedupKey); ok {
		location = fmt.Sprintf("%s:%d", file, line)
	}
	return hotspot.Candidate{
		Key:             key,
		FindingIdentity: key,
		RuleKey:         strings.TrimSpace(item.RuleKey),
		Title:           item.Title,
		Description:     item.Description,
		Severity:        item.Severity,
		Kind:            item.Kind,
		CWE:             item.CWE,
		Location:        location,
	}, true, nil
}

func candidateLess(a, b hotspot.Candidate) bool {
	return candidateSortKey(a) < candidateSortKey(b)
}

func candidateSortKey(candidate hotspot.Candidate) string {
	return strings.Join([]string{
		candidate.RuleKey,
		candidate.Title,
		candidate.Description,
		string(candidate.Severity),
		string(candidate.Kind),
		candidate.CWE,
		candidate.Location,
	}, "\x00")
}
