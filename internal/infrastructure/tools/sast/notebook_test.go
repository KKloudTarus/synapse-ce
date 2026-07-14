package sast

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzerNotebookReusesPythonRules(t *testing.T) {
	root := t.TempDir()
	data := `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"markdown","source":"hashlib.md5(data)"},{"cell_type":"code","source":"hashlib.md5(data)","outputs":[]}]}`
	if err := os.WriteFile(filepath.Join(root, "security.ipynb"), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := New().AnalyzeSource(context.Background(), root)
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}
	for _, finding := range findings {
		if finding.RuleID == "weak-hash-md5" {
			if finding.File != "security.ipynb#cell-2" || finding.Line != 1 {
				t.Fatalf("unexpected finding: %+v", finding)
			}
			return
		}
	}
	t.Fatalf("weak-hash-md5 missing: %+v", findings)
}
