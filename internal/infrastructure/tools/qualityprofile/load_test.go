package qualityprofile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
)

func TestLoadGate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gate.yaml")
	os.WriteFile(p, []byte("conditions:\n  - metric: new_critical\n    op: \"<=\"\n    threshold: 0\n  - metric: coverage\n    op: \">=\"\n    threshold: 80\n"), 0o644)
	g, found, err := LoadGate(p)
	if err != nil || !found {
		t.Fatalf("load: found=%v err=%v", found, err)
	}
	if len(g.Conditions) != 2 || g.Conditions[0].Metric != "new_critical" || g.Conditions[1].Op != qualitygate.OpGE {
		t.Errorf("parsed gate wrong: %+v", g)
	}
}

func TestLoadProfile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rules.yaml")
	os.WriteFile(p, []byte("rules:\n  quality-todo-comment:\n    enabled: false\n  reliability-self-comparison:\n    severity: high\n"), 0o644)
	prof, found, err := LoadProfile(p)
	if err != nil || !found {
		t.Fatalf("load: found=%v err=%v", found, err)
	}
	if prof.Rules["quality-todo-comment"].Enabled == nil || *prof.Rules["quality-todo-comment"].Enabled {
		t.Errorf("expected enabled=false for todo rule: %+v", prof.Rules["quality-todo-comment"])
	}
	if prof.Rules["reliability-self-comparison"].Severity != "high" {
		t.Errorf("expected severity override high: %+v", prof.Rules["reliability-self-comparison"])
	}
}

func TestLoadGateRejectsBadConfig(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"typo-key.yaml":       "condition:\n  - metric: new_critical\n    op: \"<=\"\n    threshold: 0\n",  // wrong top key -> empty -> rejected
		"unknown-metric.yaml": "conditions:\n  - metric: new_criticl\n    op: \"<=\"\n    threshold: 0\n",  // typo'd metric
		"bad-op.yaml":         "conditions:\n  - metric: new_critical\n    op: \"~=\"\n    threshold: 0\n", // unknown op
		"empty.yaml":          "conditions: []\n",                                                          // no conditions
	}
	for name, body := range cases {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o644)
		if _, _, err := LoadGate(p); err == nil {
			t.Errorf("%s: expected a load error (fail-closed), got nil", name)
		}
	}
}

func TestLoadProfileRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rules.yaml")
	os.WriteFile(p, []byte("ruls:\n  x:\n    enabled: false\n"), 0o644) // "ruls" typo
	if _, _, err := LoadProfile(p); err == nil {
		t.Error("a misspelled profile key must be rejected")
	}
}

func TestMissingFilesNotFound(t *testing.T) {
	if _, found, err := LoadGate(""); found || err != nil {
		t.Errorf("empty path: want (not-found, no error)")
	}
	if _, found, err := LoadProfile(filepath.Join(t.TempDir(), "nope.yaml")); found || err != nil {
		t.Errorf("absent file: want (not-found, no error)")
	}
}
