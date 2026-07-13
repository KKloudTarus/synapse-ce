package rules

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Filter represents normalized catalog query parameters.
type Filter struct {
	Query      string
	Languages  []string
	Types      []rule.Type
	Severities []shared.Severity
	Tags       []string
	CWE        []string
}

const (
	maxQueryLen        = 256
	maxFilterValueLen  = 128
	maxFilterValues    = 32
	maxTotalFilterVals = 64
)

// NewFilter creates, normalizes, and validates a catalog filter.
func NewFilter(query string, languages, types, severities, tags, cwe []string) (Filter, error) {
	q := strings.TrimSpace(query)
	if utf8.RuneCountInString(q) > maxQueryLen {
		return Filter{}, fmt.Errorf("%w: query exceeds maximum length of %d", shared.ErrValidation, maxQueryLen)
	}

	totalVals := len(languages) + len(types) + len(severities) + len(tags) + len(cwe)
	if totalVals > maxTotalFilterVals {
		return Filter{}, fmt.Errorf("%w: total filter values exceed maximum of %d", shared.ErrValidation, maxTotalFilterVals)
	}

	checkDim := func(name string, slice []string) error {
		if len(slice) > maxFilterValues {
			return fmt.Errorf("%w: %s values exceed maximum of %d", shared.ErrValidation, name, maxFilterValues)
		}
		for _, v := range slice {
			if utf8.RuneCountInString(v) > maxFilterValueLen {
				return fmt.Errorf("%w: %s value exceeds maximum length of %d", shared.ErrValidation, name, maxFilterValueLen)
			}
		}
		return nil
	}

	if err := checkDim("languages", languages); err != nil {
		return Filter{}, err
	}
	if err := checkDim("types", types); err != nil {
		return Filter{}, err
	}
	if err := checkDim("severities", severities); err != nil {
		return Filter{}, err
	}
	if err := checkDim("tags", tags); err != nil {
		return Filter{}, err
	}
	if err := checkDim("cwe", cwe); err != nil {
		return Filter{}, err
	}

	f := Filter{Query: strings.ToLower(q)}

	// Normalize Languages
	langSet := make(map[string]struct{})
	for _, l := range languages {
		l = strings.TrimSpace(l)
		if l == "" {
			return Filter{}, fmt.Errorf("%w: empty language value", shared.ErrValidation)
		}
		lLower := strings.ToLower(l)
		if _, ok := langSet[lLower]; !ok {
			langSet[lLower] = struct{}{}
			f.Languages = append(f.Languages, lLower)
		}
	}

	// Normalize Types
	typeSet := make(map[rule.Type]struct{})
	for _, t := range types {
		t = strings.TrimSpace(t)
		if t == "" {
			return Filter{}, fmt.Errorf("%w: empty type value", shared.ErrValidation)
		}
		rt := rule.Type(strings.ToLower(t))
		switch rt {
		case rule.TypeBug, rule.TypeVulnerability, rule.TypeCodeSmell, rule.TypeSecurityHotspot:
			if _, ok := typeSet[rt]; !ok {
				typeSet[rt] = struct{}{}
				f.Types = append(f.Types, rt)
			}
		default:
			return Filter{}, fmt.Errorf("%w: invalid type value %q", shared.ErrValidation, t)
		}
	}

	// Normalize Severities
	sevSet := make(map[shared.Severity]struct{})
	for _, s := range severities {
		s = strings.TrimSpace(s)
		if s == "" {
			return Filter{}, fmt.Errorf("%w: empty severity value", shared.ErrValidation)
		}
		rs := shared.Severity(strings.ToLower(s))
		switch rs {
		case shared.SeverityLow, shared.SeverityMedium, shared.SeverityHigh, shared.SeverityCritical:
			if _, ok := sevSet[rs]; !ok {
				sevSet[rs] = struct{}{}
				f.Severities = append(f.Severities, rs)
			}
		default:
			return Filter{}, fmt.Errorf("%w: invalid severity value %q", shared.ErrValidation, s)
		}
	}

	// Normalize Tags
	tagSet := make(map[string]struct{})
	for _, tg := range tags {
		tg = strings.TrimSpace(tg)
		if tg == "" {
			return Filter{}, fmt.Errorf("%w: empty tag value", shared.ErrValidation)
		}
		tgLower := strings.ToLower(tg)
		if _, ok := tagSet[tgLower]; !ok {
			tagSet[tgLower] = struct{}{}
			f.Tags = append(f.Tags, tgLower)
		}
	}

	// Normalize CWE
	cweSet := make(map[string]struct{})
	for _, c := range cwe {
		c = strings.TrimSpace(strings.ToUpper(c))
		if c == "" {
			return Filter{}, fmt.Errorf("%w: empty CWE value", shared.ErrValidation)
		}
		c = strings.TrimPrefix(c, "CWE-")
		id, err := strconv.Atoi(c)
		if err != nil || id <= 0 || strings.Contains(c, ".") || strings.Contains(c, " ") || strings.HasPrefix(c, "-") || strings.HasPrefix(c, "+") {
			return Filter{}, fmt.Errorf("%w: invalid CWE value %q", shared.ErrValidation, c)
		}
		for _, r := range c {
			if r < '0' || r > '9' {
				return Filter{}, fmt.Errorf("%w: invalid CWE value %q", shared.ErrValidation, c)
			}
		}

		cweForm := fmt.Sprintf("CWE-%d", id)
		if _, ok := cweSet[cweForm]; !ok {
			cweSet[cweForm] = struct{}{}
			f.CWE = append(f.CWE, cweForm)
		}
	}

	return f, nil
}

// Service provides rule catalog queries.
type Service struct {
	catalog ports.RuleCatalog
}

// NewService creates a new Service.
func NewService(catalog ports.RuleCatalog) (*Service, error) {
	if catalog == nil {
		return nil, errors.New("catalog dependency is required")
	}
	return &Service{catalog: catalog}, nil
}

// List returns catalog rules matching the filter, sorted by key.
func (s *Service) List(ctx context.Context, filter Filter) ([]rule.Rule, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	all, err := s.catalog.List(ctx)
	if err != nil {
		return nil, err
	}

	langSet := make(map[string]bool, len(filter.Languages))
	for _, l := range filter.Languages {
		langSet[l] = true
	}
	typeSet := make(map[rule.Type]bool, len(filter.Types))
	for _, t := range filter.Types {
		typeSet[t] = true
	}
	sevSet := make(map[shared.Severity]bool, len(filter.Severities))
	for _, sev := range filter.Severities {
		sevSet[sev] = true
	}
	tagSet := make(map[string]bool, len(filter.Tags))
	for _, t := range filter.Tags {
		tagSet[t] = true
	}
	cweSet := make(map[string]bool, len(filter.CWE))
	for _, c := range filter.CWE {
		cweSet[c] = true
	}

	var results []rule.Rule
	for i, r := range all {
		if i%100 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}

		if len(langSet) > 0 && !langSet[strings.ToLower(r.Language)] {
			continue
		}
		if len(typeSet) > 0 && !typeSet[r.Type] {
			continue
		}
		if len(sevSet) > 0 && !sevSet[r.DefaultSeverity] {
			continue
		}
		if len(tagSet) > 0 {
			match := false
			for _, rt := range r.Tags {
				if tagSet[strings.ToLower(rt)] {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		if len(cweSet) > 0 {
			match := false
			for _, rc := range r.CWE {
				if cweSet[rc] {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}

		if filter.Query != "" {
			if !strings.Contains(strings.ToLower(string(r.Key)), filter.Query) &&
				!strings.Contains(strings.ToLower(r.Name), filter.Query) &&
				!strings.Contains(strings.ToLower(r.Language), filter.Query) &&
				!strings.Contains(strings.ToLower(string(r.Type)), filter.Query) &&
				!strings.Contains(strings.ToLower(string(r.DefaultSeverity)), filter.Query) &&
				!strings.Contains(strings.ToLower(r.Description), filter.Query) &&
				!strings.Contains(strings.ToLower(r.Rationale), filter.Query) &&
				!strings.Contains(strings.ToLower(r.Remediation), filter.Query) &&
				!strings.Contains(strings.ToLower(string(r.Detection)), filter.Query) &&
				!containsQualitySubstring(r.Qualities, filter.Query) &&
				!containsSubstring(r.Tags, filter.Query) &&
				!containsSubstring(r.CWE, filter.Query) &&
				!containsSubstring(r.OWASP, filter.Query) {
				continue
			}
		}

		results = append(results, cloneRule(r))
	}

	sort.Slice(results, func(i, j int) bool {
		return string(results[i].Key) < string(results[j].Key)
	})

	if results == nil {
		results = []rule.Rule{}
	}
	return results, nil
}

func containsSubstring(slice []string, q string) bool {
	for _, v := range slice {
		if strings.Contains(strings.ToLower(v), q) {
			return true
		}
	}
	return false
}

func containsQualitySubstring(slice []rule.Quality, q string) bool {
	for _, v := range slice {
		if strings.Contains(strings.ToLower(string(v)), q) {
			return true
		}
	}
	return false
}

// Get returns the exact rule by key.
func (s *Service) Get(ctx context.Context, key rule.Key) (rule.Rule, error) {
	if err := ctx.Err(); err != nil {
		return rule.Rule{}, err
	}
	if string(key) == "" {
		return rule.Rule{}, fmt.Errorf("%w: empty rule key", shared.ErrValidation)
	}
	r, err := s.catalog.Get(ctx, key)
	if err != nil {
		return rule.Rule{}, err
	}
	return cloneRule(r), nil
}

func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	if len(s) == 0 {
		return []string{}
	}
	return append([]string(nil), s...)
}

func cloneQualities(s []rule.Quality) []rule.Quality {
	if s == nil {
		return nil
	}
	if len(s) == 0 {
		return []rule.Quality{}
	}
	return append([]rule.Quality(nil), s...)
}

func cloneRule(r rule.Rule) rule.Rule {
	r.Qualities = cloneQualities(r.Qualities)
	r.Tags = cloneStrings(r.Tags)
	r.CWE = cloneStrings(r.CWE)
	r.OWASP = cloneStrings(r.OWASP)
	return r
}
