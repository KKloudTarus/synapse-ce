package export

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Every reported rule must carry a link, a description and a fix in the SARIF, not only an id and a
// title. Before the RuleMeta hook existed only CVE ids got a helpUri, so a SAST, secret or misconfig
// result gave a reader nothing to act on.
func TestSARIFCarriesRuleMetadata(t *testing.T) {
	meta := func(ruleID string) (SARIFRuleMeta, bool) {
		if ruleID != "weak-crypto-md5" {
			return SARIFRuleMeta{}, false
		}
		return SARIFRuleMeta{
			Name:        "MD5 used for a security purpose",
			Description: "The MD5 hash function is used where a collision-resistant hash is required.",
			Rationale:   "MD5 collisions are computationally cheap, so a signature over an MD5 digest can be forged.",
			Remediation: "Use SHA-256 or a password hash such as bcrypt or argon2id.",
			HelpURI:     "https://cwe.mitre.org/data/definitions/327.html",
			Tags:        []string{"go", "crypto"},
			CWE:         []string{"CWE-327"},
			OWASP:       []string{"A02:2021"},
		}, true
	}

	log := buildSARIF(firstPartyFindings(), "v9", SARIFOptions{Manifest: demoManifests, RuleMeta: meta})
	byID := map[string]SARIFRule{}
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		byID[r.ID] = r
	}

	got, ok := byID["weak-crypto-md5"]
	if !ok {
		t.Fatalf("missing rule weak-crypto-md5; rules present: %v", ruleIDsOf(byID))
	}
	if got.Name != "MD5 used for a security purpose" {
		t.Errorf("name = %q, want the catalog name", got.Name)
	}
	if got.HelpURI != "https://cwe.mitre.org/data/definitions/327.html" {
		t.Errorf("helpUri = %q, want the catalog link", got.HelpURI)
	}
	if got.FullDescription == nil || !strings.Contains(got.FullDescription.Text, "collision-resistant") {
		t.Errorf("fullDescription = %+v, want the catalog description", got.FullDescription)
	}
	if got.Help == nil {
		t.Fatalf("help must carry the rationale and the fix")
	}
	if !strings.Contains(got.Help.Text, "collisions are computationally cheap") {
		t.Errorf("help text = %q, want the rationale", got.Help.Text)
	}
	if !strings.Contains(got.Help.Text, "SHA-256") {
		t.Errorf("help text = %q, want the remediation", got.Help.Text)
	}
	if !strings.Contains(got.Help.Markdown, "**Remediation:**") {
		t.Errorf("help markdown = %q, want a markdown remediation heading", got.Help.Markdown)
	}
	tags, _ := got.Properties["tags"].([]string)
	for _, want := range []string{"go", "crypto", "external/cwe/cwe-327", "external/owasp/A02:2021"} {
		if !contains(tags, want) {
			t.Errorf("tags = %v, want %q", tags, want)
		}
	}
}

// An advisory keeps its own NVD page: the catalog hook must not overwrite a more specific link.
func TestSARIFAdvisoryHelpURIWins(t *testing.T) {
	meta := func(string) (SARIFRuleMeta, bool) {
		return SARIFRuleMeta{HelpURI: "https://example.invalid/generic"}, true
	}
	log := buildSARIF(firstPartyFindings(), "v9", SARIFOptions{Manifest: demoManifests, RuleMeta: meta})
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		if r.ID == "CVE-2020-7471" && r.HelpURI != "https://nvd.nist.gov/vuln/detail/CVE-2020-7471" {
			t.Errorf("CVE helpUri = %q, want the NVD page", r.HelpURI)
		}
	}
}

// A nil hook leaves the catalog-derived fields empty; it must not invent a description or a fix.
func TestSARIFRuleMetaIsOptional(t *testing.T) {
	log := buildSARIF(firstPartyFindings(), "v9", SARIFOptions{Manifest: demoManifests})
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		if r.Help != nil || r.FullDescription != nil || r.Name != "" {
			t.Errorf("rule %q gained catalog metadata with no RuleMeta hook: %+v", r.ID, r)
		}
	}
}

// A quality or reliability rule must not arrive as a security alert. Without this separation a few
// hundred style findings sit in the same list as the advisories, which is what made the output hard to
// triage: GitHub reads security-severity to place an alert in the security view.
func TestSARIFSeparatesQualityFromSecurity(t *testing.T) {
	// Shaped like the scan pipeline's own output: a rule-based kind carries RuleKey and SourceLocation.
	findings := []finding.Finding{
		{ID: "q1", Title: "Function is too long (app/svc.go:10)", Severity: shared.SeverityLow, Status: finding.StatusOpen, Kind: finding.KindQuality, RuleKey: "long-function", DedupKey: "cq:quality:long-function:app/svc.go:10", SourceLocation: &finding.SourceLocation{File: "app/svc.go", StartLine: 10, EndLine: 10}},
		{ID: "r1", Title: "Error is discarded (app/svc.go:20)", Severity: shared.SeverityLow, Status: finding.StatusOpen, Kind: finding.KindReliability, RuleKey: "ignored-error", DedupKey: "cq:reliability:ignored-error:app/svc.go:20", SourceLocation: &finding.SourceLocation{File: "app/svc.go", StartLine: 20, EndLine: 20}},
		{ID: "s1", Title: "MD5 is a weak hash (app/crypto.go:42)", Severity: shared.SeverityHigh, Status: finding.StatusOpen, Kind: finding.KindSAST, RuleKey: "weak-crypto-md5", DedupKey: "sast:weak-crypto-md5:app/crypto.go:42", SourceLocation: &finding.SourceLocation{File: "app/crypto.go", StartLine: 42, EndLine: 42}},
	}
	log := buildSARIF(findings, "v9", SARIFOptions{})
	byID := map[string]SARIFRule{}
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		byID[r.ID] = r
	}

	for ruleID, wantTag := range map[string]string{"long-function": "maintainability", "ignored-error": "reliability"} {
		r, ok := byID[ruleID]
		if !ok {
			t.Fatalf("missing rule %q; present: %v", ruleID, ruleIDsOf(byID))
		}
		if _, hasSec := r.Properties["security-severity"]; hasSec {
			t.Errorf("rule %q must not carry security-severity: %v", ruleID, r.Properties)
		}
		tags, _ := r.Properties["tags"].([]string)
		if !contains(tags, wantTag) {
			t.Errorf("rule %q tags = %v, want %q", ruleID, tags, wantTag)
		}
		if contains(tags, "security") {
			t.Errorf("rule %q must not be tagged security: %v", ruleID, tags)
		}
		if got := r.Properties["problem.severity"]; got != "recommendation" {
			t.Errorf("rule %q problem.severity = %v, want recommendation", ruleID, got)
		}
	}

	sec, ok := byID["weak-crypto-md5"]
	if !ok {
		t.Fatalf("missing the security rule; present: %v", ruleIDsOf(byID))
	}
	if got := sec.Properties["security-severity"]; got != "7.0" {
		t.Errorf("security-severity = %v, want 7.0 for a high finding", got)
	}
	if tags, _ := sec.Properties["tags"].([]string); !contains(tags, "security") {
		t.Errorf("security rule tags = %v, want security", tags)
	}
}

// The class tags and the catalog tags must both survive: the class says whether it is a security rule and
// the catalog says which language and category it belongs to.
func TestSARIFKeepsClassAndCatalogTags(t *testing.T) {
	meta := func(string) (SARIFRuleMeta, bool) {
		return SARIFRuleMeta{Tags: []string{"go", "crypto"}, Remediation: "Use SHA-256."}, true
	}
	log := buildSARIF(firstPartyFindings(), "v9", SARIFOptions{RuleMeta: meta})
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		if r.ID != "weak-crypto-md5" {
			continue
		}
		tags, _ := r.Properties["tags"].([]string)
		for _, want := range []string{"security", "go", "crypto"} {
			if !contains(tags, want) {
				t.Errorf("tags = %v, want %q", tags, want)
			}
		}
		if _, ok := r.Properties["security-severity"]; !ok {
			t.Errorf("the catalog hook must not drop security-severity: %v", r.Properties)
		}
	}
}

func ruleIDsOf(m map[string]SARIFRule) []string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// An advisory is not in the rule catalog, so without a fallback it carried only an id, a title and an NVD
// link. The finding's own description is the advisory summary and the resolver knows the release that fixes
// it, so an advisory alert gets the same two fields a catalog rule gets.
func TestSARIFAdvisoryCarriesDescriptionAndFix(t *testing.T) {
	findings := firstPartyFindings()
	for i := range findings {
		if findings[i].DedupKey == "vuln:CVE-2020-7471:django:2.2.0" {
			findings[i].Description = "django allows SQL injection via StringAgg delimiter\nFixed in: 2.2.10"
		}
	}
	fix := func(f finding.Finding) string {
		if f.DedupKey == "vuln:CVE-2020-7471:django:2.2.0" {
			return "2.2.10"
		}
		return ""
	}
	log := buildSARIF(findings, "v9", SARIFOptions{Manifest: demoManifests, Fix: fix})
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		if r.ID != "CVE-2020-7471" {
			continue
		}
		if r.FullDescription == nil || !strings.Contains(r.FullDescription.Text, "SQL injection") {
			t.Errorf("fullDescription = %+v, want the advisory summary", r.FullDescription)
		}
		if r.Help == nil || !strings.Contains(r.Help.Text, "django to 2.2.10") {
			t.Errorf("help = %+v, want the upgrade target", r.Help)
		}
		return
	}
	t.Fatal("the advisory rule is missing from the SARIF")
}

// A catalog rule's own description and fix must win over the finding's description.
func TestSARIFCatalogMetadataWinsOverFindingDescription(t *testing.T) {
	meta := func(string) (SARIFRuleMeta, bool) {
		return SARIFRuleMeta{Description: "catalog description", Remediation: "catalog remediation"}, true
	}
	log := buildSARIF(firstPartyFindings(), "v9", SARIFOptions{RuleMeta: meta})
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		if r.ID != "weak-crypto-md5" {
			continue
		}
		if r.FullDescription == nil || r.FullDescription.Text != "catalog description" {
			t.Errorf("fullDescription = %+v, want the catalog text", r.FullDescription)
		}
	}
}

// Only CVE ids had a link, so a GHSA, Go, PyPI or Rust advisory arrived with nowhere to read about it.
func TestAdvisoryHelpURICoversEveryIDFamily(t *testing.T) {
	cases := map[string]string{
		"CVE-2020-7471":       "https://nvd.nist.gov/vuln/detail/CVE-2020-7471",
		"GHSA-crmm-hgp2-wgrp": "https://github.com/advisories/GHSA-crmm-hgp2-wgrp",
		"GO-2026-5932":        "https://pkg.go.dev/vuln/GO-2026-5932",
		"PYSEC-2021-76":       "https://osv.dev/vulnerability/PYSEC-2021-76",
		"RUSTSEC-2021-0079":   "https://osv.dev/vulnerability/RUSTSEC-2021-0079",
		"weak-crypto-md5":     "", // a catalog rule takes its link from the catalog
	}
	for id, want := range cases {
		if got := advisoryHelpURI(id); got != want {
			t.Errorf("advisoryHelpURI(%q) = %q, want %q", id, got, want)
		}
	}
}

// An advisory with no fixed release still needs a remediation: waiting for one is not a plan.
func TestAdvisoryWithNoFixStatesWhatToDo(t *testing.T) {
	f := finding.Finding{
		ID: "v2", Title: "GO-2026-5932 in golang.org/x/crypto@v0.57.0", Severity: shared.SeverityMedium,
		Status: finding.StatusOpen, DedupKey: "vuln:GO-2026-5932:golang.org/x/crypto:v0.57.0",
		Description: "the openpgp package is unmaintained\nNo fix available.",
	}
	log := buildSARIF([]finding.Finding{f}, "v9", SARIFOptions{Fix: func(finding.Finding) string { return "" }})
	rule := log.Runs[0].Tool.Driver.Rules[0]
	if rule.HelpURI != "https://pkg.go.dev/vuln/GO-2026-5932" {
		t.Errorf("helpUri = %q, want the Go vulnerability page", rule.HelpURI)
	}
	if rule.Help == nil || !strings.Contains(rule.Help.Text, "No fixed release is available") {
		t.Errorf("help = %+v, want the no-fix remediation", rule.Help)
	}
}

// A denied license is a compliance obligation, not a vulnerability: left in the security class it arrives
// in a code-scanning security view beside the advisories.
func TestLicenseRuleIsNotASecurityRule(t *testing.T) {
	f := finding.Finding{
		ID: "l1", Title: "Denied license: cc-by-sa-4.0", Severity: shared.SeverityMedium,
		Status: finding.StatusOpen, DedupKey: "license:cc-by-sa-4.0",
		Description: "Policy-denied license used by: github.com/opencontainers/go-digest",
	}
	log := buildSARIF([]finding.Finding{f}, "v9", SARIFOptions{})
	rule := log.Runs[0].Tool.Driver.Rules[0]
	if _, ok := rule.Properties["security-severity"]; ok {
		t.Errorf("a license rule must not carry security-severity: %v", rule.Properties)
	}
	tags, _ := rule.Properties["tags"].([]string)
	if !contains(tags, "license") {
		t.Errorf("tags = %v, want license", tags)
	}
	if contains(tags, "security") {
		t.Errorf("tags = %v, must not claim security", tags)
	}
	if rule.HelpURI == "" || rule.Help == nil {
		t.Errorf("a license rule needs a reference and a remediation: %+v", rule)
	}
}
