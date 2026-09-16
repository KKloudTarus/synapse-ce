package rulecatalog_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

func TestDefault_CoverageMatrixMatchesPublishedCatalog(t *testing.T) {
	catalog, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}
	rules, err := catalog.List(context.Background())
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}

	want := renderCoverageMatrix(rules)
	matrixPath := filepath.Join("..", "..", "..", "docs", "reference", "rule-coverage-matrix.md")
	gotBytes, err := os.ReadFile(matrixPath)
	if err != nil {
		t.Fatalf("read published coverage matrix: %v\n\nCreate %s with:\n%s", err, matrixPath, want)
	}
	got := strings.ReplaceAll(string(gotBytes), "\r\n", "\n")
	if got != want {
		t.Fatalf("published coverage matrix is stale; update it from the shipped catalog\n\nwant:\n%s\n\ngot:\n%s", want, got)
	}
}

func TestDefault_SecurityRulesHaveOWASPAndSonarCategory(t *testing.T) {
	catalog, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}
	rules, err := catalog.List(context.Background())
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}

	for _, entry := range rules {
		if hasQuality(entry, rule.QualitySecurity) && len(entry.OWASP) == 0 {
			t.Errorf("security rule %s has no OWASP category", entry.Key)
		}
		if sonarEquivalentCategory(entry.Type) == "" {
			t.Errorf("rule %s has no Sonar-equivalent category for type %q", entry.Key, entry.Type)
		}
	}
}

func TestDefault_NoSemanticDuplicates(t *testing.T) {
	catalog, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}
	rules, err := catalog.List(context.Background())
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}

	seen := make(map[string]rule.Key, len(rules))
	for _, entry := range rules {
		signature := entry.Language + "|" + string(entry.Type) + "|" + entry.Name
		if first, ok := seen[signature]; ok {
			t.Errorf("semantic duplicate rules %s and %s share language/type/name signature %q", first, entry.Key, signature)
			continue
		}
		seen[signature] = entry.Key
	}
}

func renderCoverageMatrix(rules []rule.Rule) string {
	counts := make(map[string]map[rule.Type]int)
	securityRules, securityWithOWASP := 0, 0
	for _, entry := range rules {
		if counts[entry.Language] == nil {
			counts[entry.Language] = make(map[rule.Type]int)
		}
		counts[entry.Language][entry.Type]++
		if hasQuality(entry, rule.QualitySecurity) {
			securityRules++
			if len(entry.OWASP) > 0 {
				securityWithOWASP++
			}
		}
	}

	languages := make([]string, 0, len(counts))
	for language := range counts {
		languages = append(languages, language)
	}
	sort.Strings(languages)

	var b strings.Builder
	b.WriteString("# Rule catalog coverage matrix\n\n")
	b.WriteString("This matrix is generated from the shipped first-party rule catalog. The drift test fails whenever the catalog and this snapshot diverge.\n\n")
	b.WriteString("OWASP coverage is required for security-quality rules. An empty OWASP list on a non-security rule means not applicable. Direct CWE mappings follow OWASP Top 10:2021's published mapped-CWE lists where available; CWEs outside those lists use explicit Synapse-reviewed Top 10 classifications and are not presented as OWASP-published CWE crosswalks.\n\n")
	fmt.Fprintf(&b, "Catalogued rules: **%d**. Security-quality rules with an OWASP mapping: **%d/%d**.\n\n", len(rules), securityWithOWASP, securityRules)
	b.WriteString("## Sonar-equivalent type mapping\n\n")
	b.WriteString("| Synapse type | Sonar-equivalent category |\n")
	b.WriteString("| --- | --- |\n")
	for _, ruleType := range []rule.Type{rule.TypeBug, rule.TypeVulnerability, rule.TypeSecurityHotspot, rule.TypeCodeSmell} {
		fmt.Fprintf(&b, "| %s | %s |\n", ruleType, sonarEquivalentCategory(ruleType))
	}
	b.WriteString("\n## Coverage by language and type\n\n")
	b.WriteString("| Language | Bug | Vulnerability | Security hotspot | Code smell | Total |\n")
	b.WriteString("| --- | ---: | ---: | ---: | ---: | ---: |\n")
	for _, language := range languages {
		row := counts[language]
		total := row[rule.TypeBug] + row[rule.TypeVulnerability] + row[rule.TypeSecurityHotspot] + row[rule.TypeCodeSmell]
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d |\n", language, row[rule.TypeBug], row[rule.TypeVulnerability], row[rule.TypeSecurityHotspot], row[rule.TypeCodeSmell], total)
	}
	return b.String()
}

func sonarEquivalentCategory(ruleType rule.Type) string {
	switch ruleType {
	case rule.TypeBug:
		return "BUG"
	case rule.TypeVulnerability:
		return "VULNERABILITY"
	case rule.TypeSecurityHotspot:
		return "SECURITY_HOTSPOT"
	case rule.TypeCodeSmell:
		return "CODE_SMELL"
	default:
		return ""
	}
}

func hasQuality(entry rule.Rule, want rule.Quality) bool {
	for _, quality := range entry.Qualities {
		if quality == want {
			return true
		}
	}
	return false
}
