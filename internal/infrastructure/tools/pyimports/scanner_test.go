package pyimports

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func has(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestScanImports(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"app/__init__.py": "",
		"app/main.py": `import os, sys
import requests
import sqlalchemy.orm as orm
from flask import Flask
from . import helper          # relative → first-party, ignored
from .sub import thing        # relative → ignored
# import commented_out        # comment → ignored
`,
		"app/helper.py":       "from click import command\n",
		"venv/lib/evil.py":    "import should_be_skipped\n", // in a skipped tree
		"node_modules/pkg.py": "import also_skipped\n",
		"README.md":           "import not_python\n", // non-.py, ignored
	})
	g, err := New().ScanImports(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, want := range []string{"requests", "sqlalchemy", "flask", "click", "os", "sys"} {
		if !has(g.ImportedModules, want) {
			t.Errorf("imported modules missing %q: %v", want, g.ImportedModules)
		}
	}
	// Relative imports, comments, skipped trees, and non-.py files contribute nothing.
	for _, bad := range []string{"helper", "sub", "commented_out", "should_be_skipped", "also_skipped", "not_python"} {
		if has(g.ImportedModules, bad) {
			t.Errorf("imported modules must not include %q: %v", bad, g.ImportedModules)
		}
	}
	if !has(g.FirstPartyModules, "app") {
		t.Errorf("first-party modules must include app: %v", g.FirstPartyModules)
	}
	if g.DynamicImports {
		t.Error("no dynamic imports in this tree")
	}
}

func TestScanDetectsDynamicImports(t *testing.T) {
	for name, body := range map[string]string{
		"__import__":     "mod = __import__('os')\n",
		"import_module":  "import importlib\nm = importlib.import_module('os')\n",
		"importlib_dund": "import importlib\nimportlib.__import__('os')\n",
	} {
		dir := writeTree(t, map[string]string{"m.py": body})
		g, err := New().ScanImports(context.Background(), dir)
		if err != nil {
			t.Fatalf("%s: scan: %v", name, err)
		}
		if !g.DynamicImports {
			t.Errorf("%s: dynamic imports must be detected in %q", name, body)
		}
	}
}

func TestScanCompoundAndContinuation(t *testing.T) {
	// Compound (`;`) and backslash-continued imports must be FULLY counted — a missed import is the
	// dangerous direction (it can yield a false not_reachable).
	dir := writeTree(t, map[string]string{
		"m.py": "import os; import requests\n" +
			"from collections import OrderedDict; import click\n" +
			"import foo, \\\n    bar\n",
	})
	g, err := New().ScanImports(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, want := range []string{"os", "requests", "collections", "click", "foo", "bar"} {
		if !has(g.ImportedModules, want) {
			t.Errorf("compound/continuation import %q must be counted: %v", want, g.ImportedModules)
		}
	}
}

func TestScanDetectsMoreDynamicForms(t *testing.T) {
	for name, body := range map[string]string{
		"from-import_module": "from importlib import import_module\nm = import_module('os')\n",
		"imp_load":           "import imp\nimp.load_module('m', f, p, d)\n",
		"runpy":              "import runpy\nrunpy.run_module('pkg')\n",
		"exec":               "exec('import os')\n",
	} {
		dir := writeTree(t, map[string]string{"m.py": body})
		g, err := New().ScanImports(context.Background(), dir)
		if err != nil {
			t.Fatalf("%s: scan: %v", name, err)
		}
		if !g.DynamicImports {
			t.Errorf("%s: dynamic-import mechanism must be detected in %q", name, body)
		}
	}
}

func TestScanNoPythonIsNoCoverage(t *testing.T) {
	dir := writeTree(t, map[string]string{"go.mod": "module x\n", "main.go": "package main\n"})
	_, err := New().ScanImports(context.Background(), dir)
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("a non-Python target must be no-coverage (ErrNotFound), got %v", err)
	}
}

func TestScanEmptyDirRejected(t *testing.T) {
	if _, err := New().ScanImports(context.Background(), ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty dir must be rejected, got %v", err)
	}
}
