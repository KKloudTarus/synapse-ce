package rulecatalog_test

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

func mustDefaultRules(t *testing.T) []rule.Rule {
	t.Helper()
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}
	if cat == nil {
		t.Fatal("Default() returned nil catalog")
	}

	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("List() returned empty rules slice")
	}
	return rules
}

func TestMetadata_NoEmptyFields(t *testing.T) {
	rules := mustDefaultRules(t)

	for _, r := range rules {
		if len(strings.TrimSpace(r.Description)) < 10 {
			t.Errorf("Rule %s has too short Description", r.Key)
		}
		if len(strings.TrimSpace(r.Rationale)) < 10 {
			t.Errorf("Rule %s has too short Rationale", r.Key)
		}
		if len(strings.TrimSpace(r.Remediation)) < 10 {
			t.Errorf("Rule %s has too short Remediation", r.Key)
		}
	}
}

func TestMetadata_RationaleLink(t *testing.T) {
	rules := mustDefaultRules(t)

	for _, r := range rules {
		// Look for standard source link suffix
		idx := strings.Index(r.Rationale, "\n\nSource: https://")
		if idx == -1 {
			t.Errorf("Rule %s missing correct source link suffix in Rationale", r.Key)
			continue
		}

		// Validate URL parsing
		link := strings.TrimSpace(r.Rationale[idx+10:])
		u, err := url.Parse(link)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			t.Errorf("Rule %s has invalid or non-https source link: %q", r.Key, link)
		}
	}
}

func TestMetadata_ValidTags(t *testing.T) {
	rules := mustDefaultRules(t)

	kebab := regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

	for _, r := range rules {
		for _, tag := range r.Tags {
			if !kebab.MatchString(tag) {
				t.Errorf("Rule %s has invalid tag format: %q", r.Key, tag)
			}
		}
	}
}

func TestMetadata_CWEFormat(t *testing.T) {
	rules := mustDefaultRules(t)

	cweRe := regexp.MustCompile(`^CWE-[1-9][0-9]*$`)

	for _, r := range rules {
		for _, cwe := range r.CWE {
			if !cweRe.MatchString(cwe) {
				t.Errorf("Rule %s has invalid CWE format: %q", r.Key, cwe)
			}
		}
	}
}

func TestMetadata_OWASPFormat(t *testing.T) {
	rules := mustDefaultRules(t)

	owaspRe := regexp.MustCompile(`^A[0-9]{2}:20[0-9]{2}$`)

	for _, r := range rules {
		for _, owasp := range r.OWASP {
			if !owaspRe.MatchString(owasp) {
				t.Errorf("Rule %s has invalid OWASP format: %q", r.Key, owasp)
			}
		}
	}
}

func TestMetadata_MeaningfulExamples(t *testing.T) {
	rules := mustDefaultRules(t)

	generic := []string{
		"// safe implementation",
		"// unsafe implementation",
		"// safe configuration",
		"// unsafe configuration",
	}

	for _, r := range rules {
		c := strings.TrimSpace(r.CompliantExample)
		nc := strings.TrimSpace(r.NoncompliantExample)

		if len(c) < 5 {
			t.Errorf("Rule %s CompliantExample too short", r.Key)
		}
		if len(nc) < 5 {
			t.Errorf("Rule %s NoncompliantExample too short", r.Key)
		}
		if c == nc {
			t.Errorf("Rule %s examples are identical", r.Key)
		}

		cl := strings.ToLower(c)
		ncl := strings.ToLower(nc)
		for _, g := range generic {
			if cl == g || ncl == g {
				t.Errorf("Rule %s uses generic placeholder example", r.Key)
			}
		}
	}
}

func TestMetadata_RemediationEffortBuckets(t *testing.T) {
	rules := mustDefaultRules(t)

	buckets := map[int]bool{5: true, 15: true, 30: true, 60: true, 120: true, 240: true, 480: true}

	for _, r := range rules {
		if !buckets[r.RemediationEffort] {
			t.Errorf("Rule %s RemediationEffort not in allowed buckets: %d", r.Key, r.RemediationEffort)
		}
	}
}

func TestMetadata_NoPlaceholders(t *testing.T) {
	rules := mustDefaultRules(t)

	bad := []string{
		"TODO", "FIXME", "XXX", "TBD", "lorem", "coming soon",
		"Unknown Description",
		"Review the configuration and apply least-privilege principles according to vendor documentation.",
		"Review the code and implement secure alternatives such as using strong cryptography, parameterized queries, and safe templating functions.",
	}

	for _, r := range rules {
		fields := []string{r.Description, r.Rationale, r.Remediation}
		for _, f := range fields {
			for _, b := range bad {
				if strings.Contains(f, b) {
					// EXCEPTION: quality-todo-comment is about TODO/FIXME
					if r.Key == "quality-todo-comment" && (b == "TODO" || b == "FIXME" || b == "XXX") {
						continue
					}
					t.Errorf("Rule %s leaked placeholder/generic text %q in metadata", r.Key, b)
				}
			}
		}
	}
}

func TestMetadata_ApprovedLanguage(t *testing.T) {
	rules := mustDefaultRules(t)

	approved := map[string]bool{
		"General":               true,
		"Python":                true,
		"JavaScript/TypeScript": true,
		"C/C++/Objective-C":     true,
		"Go":                    true,
		"Dockerfile":            true,
		"Docker Compose":        true,
		"Terraform":             true,
		"Kubernetes":            true,
		"CloudFormation":        true,
		"GitHub Actions":        true,
		"Secrets":               true,
	}

	for _, r := range rules {
		if !approved[r.Language] {
			t.Errorf("Rule %s has unapproved language: %q", r.Key, r.Language)
		}
	}
}
