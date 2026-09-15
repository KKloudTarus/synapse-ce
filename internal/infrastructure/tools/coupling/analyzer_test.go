package coupling

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jsimports"
)

func TestAnalyzerBuildsGoAndJSCoupling(t *testing.T) {
	root := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		filename := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.test/app\n\ngo 1.24\n")
	write("a/a.go", "package a\nimport _ \"example.test/app/b\"\n")
	write("b/b.go", "package b\n")
	write("web/a.ts", "import './b'\n")
	write("web/b.ts", "export const b = 1\n")

	report, err := New(jsimports.New()).AnalyzeCoupling(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Complete {
		t.Fatalf("unexpected gaps: %+v", report.Gaps)
	}
	if len(report.Modules) != 4 || len(report.Edges) != 2 {
		t.Fatalf("modules=%d edges=%d: %+v", len(report.Modules), len(report.Edges), report)
	}
	goMetrics := report.MetricsForPath("a", "directory")
	if goMetrics.Efferent.Value == nil || *goMetrics.Efferent.Value != 1 {
		t.Fatalf("go Ce = %+v", goMetrics.Efferent)
	}
	jsMetrics := report.MetricsForPath("web/b.ts", "file")
	if jsMetrics.Afferent.Value == nil || *jsMetrics.Afferent.Value != 1 {
		t.Fatalf("js Ca = %+v", jsMetrics.Afferent)
	}
	repeated, err := New(jsimports.New()).AnalyzeCoupling(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report, repeated) {
		t.Fatalf("coupling evidence changed between runs:\nfirst=%+v\nsecond=%+v", report, repeated)
	}
}

func TestAnalyzerMakesMalformedSourceIncomplete(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "broken.go"), []byte("package"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := New(jsimports.New()).AnalyzeCoupling(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if report.Complete || len(report.Gaps) == 0 {
		t.Fatalf("malformed source was silent: %+v", report)
	}
}

func TestAnalyzerMakesDuplicateGoModulePathsIncomplete(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"one", "two"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, "go.mod"), []byte("module duplicate.test/module\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, "main.go"), []byte("package module\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	report, err := New(jsimports.New()).AnalyzeCoupling(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if report.Complete || len(report.Modules) != 2 || report.Gaps[0].Reason != "ambiguous_module_import_path" {
		t.Fatalf("ambiguous module paths were not retained as a coverage gap: %+v", report)
	}
}
