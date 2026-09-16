package rulecatalog

import (
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulemeta"
)

// owasp2021DirectByCWE contains only CWE-to-category relationships that appear
// in OWASP Top 10:2021's own "List of Mapped CWEs" pages. Keep this table
// deliberately conservative: a CWE that is security-relevant but absent from
// OWASP's published crosswalk belongs in reviewedOWASP2021FallbackByCWE below,
// not here.
var owasp2021DirectByCWE = map[string]string{
	"CWE-201": "A01:2021",
	"CWE-276": "A01:2021",
	"CWE-322": "A02:2021",
	"CWE-760": "A02:2021",
	"CWE-98":  "A03:2021",
	"CWE-434": "A04:2021",
	"CWE-384": "A07:2021",
	"CWE-613": "A07:2021",
	"CWE-353": "A08:2021",
	"CWE-426": "A08:2021",
}

// reviewedOWASP2021FallbackByCWE is a Synapse-owned classification for shipped
// security rules whose CWE is not present in OWASP Top 10:2021's published
// mapped-CWE lists. These values are review decisions, not claims that OWASP
// publishes the same CWE crosswalk. Keeping them separate from
// owasp2021DirectByCWE makes that provenance explicit and reviewable.
var reviewedOWASP2021FallbackByCWE = map[string]string{
	"CWE-939":  "A01:2021",
	"CWE-119":  "A04:2021",
	"CWE-120":  "A04:2021",
	"CWE-242":  "A04:2021",
	"CWE-362":  "A04:2021",
	"CWE-367":  "A04:2021",
	"CWE-400":  "A04:2021",
	"CWE-404":  "A04:2021",
	"CWE-664":  "A04:2021",
	"CWE-697":  "A04:2021",
	"CWE-704":  "A04:2021",
	"CWE-758":  "A04:2021",
	"CWE-787":  "A04:2021",
	"CWE-823":  "A04:2021",
	"CWE-825":  "A04:2021",
	"CWE-908":  "A04:2021",
	"CWE-1007": "A04:2021",
	"CWE-1022": "A04:2021",
}

// A few catalog rules express a security-sensitive condition without a CWE.
// These are explicit rule-level review decisions for the same reason as the
// fallback table above.
var owasp2021ByRuleKey = map[rule.Key]string{
	"c:memset-cleared-by-compiler":     "A02:2021",
	"c:multiplication-overflow-malloc": "A04:2021",
	"c:vla-stack-allocation":           "A04:2021",
	"cloudformation-s3-no-versioning":  "A08:2021",
	"js-jquery-ajax-sync":              "A04:2021",
	"python-assert-for-validation":     "A04:2021",
	"python-bind-all-interfaces":       "A05:2021",
	"swift:keychain-accessible-always": "A02:2021",
	"swift:userdefaults-sensitive":     "A02:2021",
	"text:invisible-unicode":           "A08:2021",
}

// auditRuleMetadata completes OWASP coverage for security-quality rules. It
// first uses direct OWASP-published CWE mappings plus mappings already present
// in the catalog. If those do not apply, it falls back to an explicit
// Synapse-reviewed rule/CWE classification. New unmapped security rules fail
// closed so additions cannot silently ship without an audit decision.
func auditRuleMetadata(entries []rule.Rule) ([]rule.Rule, error) {
	byCWE := make(map[string]map[string]struct{})
	for cwe, category := range owasp2021DirectByCWE {
		addOWASPMapping(byCWE, cwe, category)
	}
	for _, entry := range entries {
		for _, cwe := range entry.CWE {
			for _, category := range entry.OWASP {
				addOWASPMapping(byCWE, cwe, category)
			}
		}
	}

	audited := make([]rule.Rule, len(entries))
	var unmapped []string
	for i, entry := range entries {
		current := entry.Clone()
		current.Name = rulemeta.DisplayName(string(current.Key), current.Name)
		if hasQuality(current, rule.QualitySecurity) && len(current.OWASP) == 0 {
			categories := make(map[string]struct{})
			if category, ok := owasp2021ByRuleKey[current.Key]; ok {
				categories[category] = struct{}{}
			}
			for _, cwe := range current.CWE {
				for category := range byCWE[normalizeCWE(cwe)] {
					categories[category] = struct{}{}
				}
			}
			if len(categories) == 0 {
				for _, cwe := range current.CWE {
					if category, ok := reviewedOWASP2021FallbackByCWE[normalizeCWE(cwe)]; ok {
						categories[category] = struct{}{}
					}
				}
			}
			current.OWASP = sortedSet(categories)
			if len(current.OWASP) == 0 {
				unmapped = append(unmapped, string(current.Key))
			}
		}
		audited[i] = current
	}
	if len(unmapped) > 0 {
		sort.Strings(unmapped)
		return nil, fmt.Errorf("security rules without an OWASP mapping: %s", strings.Join(unmapped, ", "))
	}
	return audited, nil
}

func addOWASPMapping(index map[string]map[string]struct{}, cwe, category string) {
	key := normalizeCWE(cwe)
	if index[key] == nil {
		index[key] = make(map[string]struct{})
	}
	index[key][category] = struct{}{}
}

func normalizeCWE(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func sortedSet(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func hasQuality(entry rule.Rule, want rule.Quality) bool {
	for _, quality := range entry.Qualities {
		if quality == want {
			return true
		}
	}
	return false
}
