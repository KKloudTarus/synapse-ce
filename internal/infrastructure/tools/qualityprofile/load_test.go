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

func TestMissingFilesNotFound(t *testing.T) {
	if _, found, err := LoadGate(""); found || err != nil {
		t.Errorf("empty path: want (not-found, no error)")
	}
	if _, found, err := LoadProfile(filepath.Join(t.TempDir(), "nope.yaml")); found || err != nil {
		t.Errorf("absent file: want (not-found, no error)")
	}
}
