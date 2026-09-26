package exportcompose

import (
	"context"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

// Every rule in the published catalog must resolve to SARIF metadata that carries a link, a description
// and a fix. A rule that resolves to an empty help URI or an empty remediation would export an alert a
// reader cannot act on, which is the whole point of the lookup.
func TestSARIFRuleMetaCoversEveryCatalogRule(t *testing.T) {
	ctx := context.Background()
	lookup, err := SARIFRuleMeta(ctx)
	if err != nil {
		t.Fatalf("build lookup: %v", err)
	}
	catalog, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	rules, err := catalog.List(ctx)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("the catalog is empty, so this test proves nothing")
	}
	for _, r := range rules {
		meta, ok := lookup(string(r.Key))
		if !ok {
			t.Fatalf("rule %q has no SARIF metadata", r.Key)
		}
		if !strings.HasPrefix(meta.HelpURI, "https://") {
			t.Errorf("rule %q: helpUri = %q, want an https link", r.Key, meta.HelpURI)
		}
		if strings.TrimSpace(meta.Remediation) == "" {
			t.Errorf("rule %q: no remediation to export", r.Key)
		}
		if strings.TrimSpace(meta.Description) == "" {
			t.Errorf("rule %q: no description to export", r.Key)
		}
	}
}

// A rule that declares a CWE links to that weakness class rather than to the generic matrix page.
func TestSARIFRuleMetaPrefersCWELink(t *testing.T) {
	lookup, err := SARIFRuleMeta(context.Background())
	if err != nil {
		t.Fatalf("build lookup: %v", err)
	}
	meta, ok := lookup("terraform-open-cidr")
	if !ok {
		t.Fatal("terraform-open-cidr must be in the catalog")
	}
	if meta.HelpURI != "https://cwe.mitre.org/data/definitions/284.html" {
		t.Errorf("helpUri = %q, want the CWE-284 page", meta.HelpURI)
	}
}

// An unknown id is reported as missing rather than returning a zero value that would export empty fields.
func TestSARIFRuleMetaMissIsExplicit(t *testing.T) {
	lookup, err := SARIFRuleMeta(context.Background())
	if err != nil {
		t.Fatalf("build lookup: %v", err)
	}
	if _, ok := lookup("CVE-2020-7471"); ok {
		t.Error("an advisory id must not resolve to a catalog rule")
	}
}
