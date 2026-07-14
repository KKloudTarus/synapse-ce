package astwalk

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestWalkSourceExpandsNotebookCodeCells(t *testing.T) {
	root := t.TempDir()
	data := `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"markdown","source":"def ignored(): pass"},{"cell_type":"code","source":"def included():\n    return 1"}]}`
	if err := os.WriteFile(filepath.Join(root, "functions.ipynb"), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	var got []string
	_, err := walkSource(context.Background(), root, func(rel, lang string, content []byte) {
		got = append(got, rel+"|"+lang+"|"+string(content))
	})
	if err != nil {
		t.Fatalf("walkSource: %v", err)
	}
	if len(got) != 1 || got[0] != "functions.ipynb#cell-2|Python|def included():\n    return 1" {
		t.Fatalf("walkSource = %#v", got)
	}
}
