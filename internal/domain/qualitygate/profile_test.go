package qualitygate

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func boolp(b bool) *bool { return &b }

func TestRuleIDOf(t *testing.T) {
	cases := map[string]string{
		"quality:quality-todo-comment:a.go:3": "quality-todo-comment",
		"sast:weak-hash-md5:x/y.go:12":        "weak-hash-md5",
		"CVE-2024-1234:pkg:1.0.0":             "CVE-2024-1234", // SCA: no kind prefix -> first field
	}
	for dedup, want := range cases {
		if got := RuleIDOf(dedup); got != want {
			t.Errorf("RuleIDOf(%q) = %q, want %q", dedup, got, want)
		}
	}
}

func TestFileLineOf(t *testing.T) {
	f, l, ok := FileLineOf("quality:quality-todo-comment:pkg/a.go:42")
	if !ok || f != "pkg/a.go" || l != 42 {
		t.Errorf("got (%q,%d,%v), want (pkg/a.go,42,true)", f, l, ok)
	}
	if _, _, ok := FileLineOf("CVE-2024-1: pkg:1.0"); ok {
		t.Error("an SCA (non-line-anchored) key must return ok=false")
	}
}

func TestProfileApply(t *testing.T) {
	findings := []finding.Finding{
		{DedupKey: "quality:quality-todo-comment:a.go:1", Severity: shared.SeverityInfo},
		{DedupKey: "reliability:reliability-self-comparison:b.go:2", Severity: shared.SeverityMedium},
		{DedupKey: "sast:weak-hash-md5:c.go:3", Severity: shared.SeverityMedium},
	}
	p := Profile{Rules: map[string]RuleConfig{
		"quality-todo-comment":        {Enabled: boolp(false)},                 // drop
		"reliability-self-comparison": {Severity: string(shared.SeverityHigh)}, // override
	}}
	out := p.Apply(findings)
	if len(out) != 2 {
		t.Fatalf("want 2 findings (todo dropped), got %d: %+v", len(out), out)
	}
	for _, f := range out {
		switch RuleIDOf(f.DedupKey) {
		case "quality-todo-comment":
			t.Error("disabled rule must be dropped")
		case "reliability-self-comparison":
			if f.Severity != shared.SeverityHigh {
				t.Errorf("severity override failed: %s", f.Severity)
			}
		case "weak-hash-md5":
			if f.Severity != shared.SeverityMedium {
				t.Errorf("untouched rule severity changed: %s", f.Severity)
			}
		}
	}
}

func TestEmptyProfileNoOp(t *testing.T) {
	in := []finding.Finding{{DedupKey: "quality:x:a:1"}}
	if got := (Profile{}).Apply(in); len(got) != 1 {
		t.Errorf("empty profile must pass findings through, got %d", len(got))
	}
}
