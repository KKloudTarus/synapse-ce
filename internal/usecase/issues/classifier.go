// Package issues contains Project code-quality issue projection use cases.
package issues

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/issue"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Project turns the publishable, non-hotspot findings of one analysis into stable,
// deduplicated issue candidates. The catalog rule (when present) is the authority for
// the issue Type and Language; findings with unknown rule metadata fall back to a
// deterministic Type derived from the finding Kind and are never dropped. A catalog
// infrastructure failure (other than not-found) is returned so an incomplete
// projection can never make a Project analysis look complete.
func Project(ctx context.Context, findings []finding.Finding, catalog RuleCatalog) ([]issue.Candidate, error) {
	byKey := make(map[string]issue.Candidate)
	for _, item := range findings {
		candidate, ok, err := projectOne(ctx, item, catalog)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if _, exists := byKey[candidate.Key]; !exists {
			byKey[candidate.Key] = candidate
		}
	}
	out := make([]issue.Candidate, 0, len(byKey))
	for _, c := range byKey {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// RuleCatalog is the subset of the rule catalog the projector needs.
type RuleCatalog interface {
	Get(ctx context.Context, key rule.Key) (rule.Rule, error)
}

func projectOne(ctx context.Context, item finding.Finding, catalog RuleCatalog) (issue.Candidate, bool, error) {
	key := finding.Identity(item)
	if key == "" {
		return issue.Candidate{}, false, nil
	}
	issueType := deriveType(item.Kind)
	language := ""
	if rk := strings.TrimSpace(item.RuleKey); rk != "" && catalog != nil {
		r, err := catalog.Get(ctx, rule.Key(rk))
		switch {
		case errors.Is(err, shared.ErrNotFound):
			// keep the Kind-derived defaults
		case err != nil:
			return issue.Candidate{}, false, fmt.Errorf("resolve issue rule %q: %w", rk, err)
		default:
			if r.Type.Valid() && r.Type != rule.TypeSecurityHotspot {
				issueType = r.Type
			}
			language = strings.TrimSpace(r.Language)
		}
	}
	file, location := "", ""
	if f, line, ok := qualitygate.FileLineOf(item.DedupKey); ok {
		file = f
		location = fmt.Sprintf("%s:%d", f, line)
	}
	return issue.Candidate{
		Key:             key,
		FindingIdentity: key,
		RuleKey:         strings.TrimSpace(item.RuleKey),
		Type:            issueType,
		Title:           item.Title,
		Description:     item.Description,
		Severity:        item.Severity,
		Kind:            item.Kind,
		CWE:             item.CWE,
		Language:        language,
		File:            file,
		Location:        location,
	}, true, nil
}

// deriveType maps a finding Kind to an issue Type when no catalog rule is available.
func deriveType(kind finding.Kind) rule.Type {
	switch kind {
	case finding.KindQuality:
		return rule.TypeCodeSmell
	case finding.KindReliability:
		return rule.TypeBug
	case finding.KindSAST, finding.KindSecret, finding.KindMisconfig,
		finding.KindDAST, finding.KindExploitation, finding.KindSCA:
		return rule.TypeVulnerability
	default:
		return rule.TypeCodeSmell
	}
}

// DirOf returns the directory portion of an issue file path (for the file/dir facet).
func DirOf(file string) string {
	file = strings.TrimSpace(file)
	if file == "" {
		return ""
	}
	return path.Dir(file)
}
