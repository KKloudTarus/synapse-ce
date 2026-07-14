//go:build cgo

package astwalk

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestQualityForNotebookSharesPythonStateAcrossCells(t *testing.T) {
	root := t.TempDir()
	data := `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","source":"import json"},{"cell_type":"code","source":"json.dumps({})"}]}`
	if err := os.WriteFile(filepath.Join(root, "state.IPYNB"), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	quality, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	for _, finding := range quality.Findings {
		if finding.Rule == "python-unused-import" {
			t.Fatalf("cross-cell import was reported unused: %+v", finding)
		}
	}
}
