// Package exportcompose wires the published rule catalog into the report exporters. It sits in
// composition because it joins an infrastructure catalog to a usecase exporter, which neither layer may
// import from the other.
package exportcompose

import (
	"context"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
	exportuc "github.com/KKloudTarus/synapse-ce/internal/usecase/export"
)

// coverageMatrixURL is the rule reference that resolves today. The catalog's own entry is the
// authoritative description, and it travels in the SARIF itself, so this is the "read more" target rather
// than the carrier of the explanation.
const coverageMatrixURL = "https://github.com/KKloudTarus/synapse-ce/blob/main/docs/reference/rule-coverage-matrix.md"

// SARIFRuleMeta returns a lookup over the published rule catalog for the SARIF exporter. Every rule the
// engine can report is in the catalog (TestCatalogParity enforces that both ways), so a rule id that
// misses here is an advisory id, which the exporter already handles.
//
// An error building the catalog is returned rather than swallowed: exporting SARIF with no rule metadata
// is exactly the degraded output this exists to fix, so the caller decides whether to proceed.
func SARIFRuleMeta(ctx context.Context) (func(string) (exportuc.SARIFRuleMeta, bool), error) {
	catalog, err := rulecatalog.Default()
	if err != nil {
		return nil, err
	}
	rules, err := catalog.List(ctx)
	if err != nil {
		return nil, err
	}
	byKey := make(map[string]exportuc.SARIFRuleMeta, len(rules))
	for _, r := range rules {
		byKey[string(r.Key)] = sarifMeta(r)
	}
	return func(ruleID string) (exportuc.SARIFRuleMeta, bool) {
		meta, ok := byKey[ruleID]
		return meta, ok
	}, nil
}

func sarifMeta(r rule.Rule) exportuc.SARIFRuleMeta {
	return exportuc.SARIFRuleMeta{
		Name:        r.Name,
		Description: r.Description,
		Rationale:   r.Rationale,
		Remediation: r.Remediation,
		HelpURI:     helpURI(r),
		Tags:        append([]string{}, r.Tags...),
		CWE:         append([]string{}, r.CWE...),
		OWASP:       append([]string{}, r.OWASP...),
	}
}

// helpURI prefers the rule's own CWE page, which states the weakness class in a form a reviewer already
// knows how to read, and falls back to the coverage matrix for a rule that declares no CWE (a
// maintainability or reliability rule, mostly).
func helpURI(r rule.Rule) string {
	for _, id := range r.CWE {
		if n := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(id)), "CWE-"); n != "" && isDigits(n) {
			return "https://cwe.mitre.org/data/definitions/" + n + ".html"
		}
	}
	return coverageMatrixURL
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}
