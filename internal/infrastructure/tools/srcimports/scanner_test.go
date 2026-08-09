package srcimports

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func writeFile(t *testing.T, file, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func imported(graph ports.SourceImportGraph) map[string]bool {
	out := map[string]bool{}
	for _, name := range graph.ImportedPackages {
		out[name] = true
	}
	return out
}

// --- Rust ---

func TestRustScannerObservesCrateReferences(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Cargo.toml"), "[package]\nname = \"my-app\"\n")
	writeFile(t, filepath.Join(root, "src", "main.rs"), `
use serde::Serialize;
use tokio::net::TcpListener;
use std::collections::HashMap;
use crate::internal::helper;
use self::local;
extern crate legacy_crate;
pub use reqwest::Client;
use {itertools, rayon::prelude::*};
// use commented_out::Thing;
`)

	graph, err := NewRustScanner().ScanImports(context.Background(), root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := imported(graph)
	for _, want := range []string{"serde", "tokio", "legacy_crate", "reqwest", "itertools", "rayon"} {
		if !got[want] {
			t.Errorf("expected crate %q among %v", want, graph.ImportedPackages)
		}
	}
	// The language's own libraries and the current crate are not dependencies.
	for _, unwanted := range []string{"std", "crate", "self", "commented_out"} {
		if got[unwanted] {
			t.Errorf("%q must not be reported as a dependency reference", unwanted)
		}
	}
	if !graph.Complete() {
		t.Fatalf("a fully observable crate must be complete, got %v", graph.CoverageReasons)
	}
}

func TestRustDynamicConstructsDegradeCoverage(t *testing.T) {
	t.Parallel()

	// Each of these can reference a crate without a visible `use`, so each must produce an unknown
	// region rather than a silent gap.
	tests := map[string]string{
		"macro definition":  "macro_rules! shout { () => {} }",
		"include":           `include!("generated.rs");`,
		"derive macro":      "#[derive(Serialize)]\nstruct S;",
		"proc macro":        "use proc_macro::TokenStream;",
		"foreign interface": "extern \"C\" { fn c_fn(); }",
	}
	for name, src := range tests {
		name, src := name, src
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "src", "lib.rs"), "use serde::Serialize;\n"+src)

			graph, err := NewRustScanner().ScanImports(context.Background(), root)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if graph.Complete() {
				t.Fatalf("%s must degrade coverage", name)
			}
		})
	}
}

// --- PHP ---

func TestPHPScannerObservesNamespaceReferences(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "composer.json"), `{"autoload":{"psr-4":{"App\\":"src/"}}}`)
	writeFile(t, filepath.Join(root, "src", "Service.php"), `<?php
use Monolog\Logger;
use Symfony\Component\Console\Command;
use function GuzzleHttp\json_decode;
use Doctrine\ORM\EntityManager as EM;
require __DIR__ . '/bootstrap.php';
// use CommentedOut\Thing;
`)

	graph, err := NewPHPScanner().ScanImports(context.Background(), root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := imported(graph)
	for _, want := range []string{"monolog", "symfony", "guzzlehttp", "doctrine"} {
		if !got[want] {
			t.Errorf("expected namespace %q among %v", want, graph.ImportedPackages)
		}
	}
	if got["commentedout"] {
		t.Error("a commented-out use must not be a reference")
	}
}

func TestPHPDynamicConstructsDegradeCoverage(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"variable function name": `<?php $fn = 'x'; call_user_func($fn);`,
		"variable class name":    `<?php $c = 'X'; $o = new $c();`,
		"computed include":       `<?php include $path;`,
		"eval":                   `<?php eval($code);`,
		"reflection":             `<?php $r = new ReflectionClass($name);`,
		"custom autoloader":      `<?php spl_autoload_register(function ($c) {});`,
	}
	for name, src := range tests {
		name, src := name, src
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "src", "a.php"), src)

			graph, err := NewPHPScanner().ScanImports(context.Background(), root)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if graph.Complete() {
				t.Fatalf("%s must degrade coverage", name)
			}
		})
	}
}

// --- Ruby ---

func TestRubyScannerObservesGemReferences(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Gemfile"), "source 'https://rubygems.org'\n")
	writeFile(t, filepath.Join(root, "lib", "app.rb"), `
require 'rails'
require "nokogiri"
require 'active_support/core_ext'
require_relative 'local_helper'
# require 'commented_out'
`)

	graph, err := NewRubyScanner().ScanImports(context.Background(), root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := imported(graph)
	for _, want := range []string{"rails", "nokogiri", "active_support"} {
		if !got[want] {
			t.Errorf("expected gem %q among %v", want, graph.ImportedPackages)
		}
	}
	// require_relative always names a first-party file, never a gem.
	if got["local_helper"] {
		t.Error("require_relative must not be reported as a gem reference")
	}
	if got["commented_out"] {
		t.Error("a commented-out require must not be a reference")
	}
	if !graph.Complete() {
		t.Fatalf("a fully observable project must be complete, got %v", graph.CoverageReasons)
	}
}

func TestRubyDynamicConstructsDegradeCoverage(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"const_get":         `Object.const_get(name)`,
		"send":              `obj.send(:method_name)`,
		"method_missing":    `def method_missing(m, *args); end`,
		"define_method":     `define_method(:x) { }`,
		"instance_eval":     `obj.instance_eval(code)`,
		"computed require":  `require gem_name`,
		"interpolated path": `require "lib/#{name}"`,
		"autoload":          `autoload :Thing, 'thing'`,
	}
	for name, src := range tests {
		name, src := name, src
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "lib", "a.rb"), "require 'rails'\n"+src)

			graph, err := NewRubyScanner().ScanImports(context.Background(), root)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if graph.Complete() {
				t.Fatalf("%s must degrade coverage", name)
			}
		})
	}
}

// --- shared behaviour ---

func TestScannersRefuseAnUnusableTarget(t *testing.T) {
	t.Parallel()

	scanners := map[string]ports.SourceImportScanner{
		"rust": NewRustScanner(), "php": NewPHPScanner(), "ruby": NewRubyScanner(),
	}
	for lang, scanner := range scanners {
		lang, scanner := lang, scanner
		t.Run(lang, func(t *testing.T) {
			t.Parallel()
			if _, err := scanner.ScanImports(context.Background(), "  "); !errors.Is(err, shared.ErrValidation) {
				t.Errorf("a blank target must be a validation error, got %v", err)
			}
			// No source of this language is NO COVERAGE, never an empty clean observation a caller
			// could read as "nothing is imported".
			empty := t.TempDir()
			writeFile(t, filepath.Join(empty, "readme.txt"), "nothing here")
			if _, err := scanner.ScanImports(context.Background(), empty); !errors.Is(err, shared.ErrNotFound) {
				t.Errorf("no source must be ErrNotFound, got %v", err)
			}
		})
	}
}

func TestScannersNeverFollowSymlinks(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secret.rb"), "require 'exfiltrated'")
	writeFile(t, filepath.Join(root, "lib", "a.rb"), "require 'rails'")
	if err := os.Symlink(filepath.Join(outside, "secret.rb"), filepath.Join(root, "lib", "linked.rb")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	graph, err := NewRubyScanner().ScanImports(context.Background(), root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if imported(graph)["exfiltrated"] {
		t.Fatal("a symlink was followed outside the target")
	}
	if graph.Complete() {
		t.Fatal("an unfollowed symlink must degrade coverage")
	}
}

func TestScannersAreDeterministic(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "src", "a.rs"), "use serde::Serialize;\nuse tokio::net::TcpListener;")
	writeFile(t, filepath.Join(root, "src", "b.rs"), "use reqwest::Client;")

	first, err := NewRustScanner().ScanImports(context.Background(), root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	second, err := NewRustScanner().ScanImports(context.Background(), root)
	if err != nil {
		t.Fatalf("scan again: %v", err)
	}
	if len(first.ImportedPackages) != len(second.ImportedPackages) {
		t.Fatal("repeated scans must be identical")
	}
	for i := range first.ImportedPackages {
		if first.ImportedPackages[i] != second.ImportedPackages[i] {
			t.Fatal("repeated scans must be identically ordered")
		}
	}
}

func TestCandidateNamers(t *testing.T) {
	t.Parallel()

	// A dependency is referenced under several plausible names; over-matching biases toward reachable,
	// which is the safe direction.
	if got := RustCandidates("serde-json"); !contains(got, "serde_json") || !contains(got, "serde-json") {
		t.Errorf("rust candidates must cover both hyphen and underscore forms, got %v", got)
	}
	if got := PHPCandidates("monolog/monolog"); !contains(got, "monolog") {
		t.Errorf("php candidates must include the package segment, got %v", got)
	}
	if got := PHPCandidates("symfony/console"); !contains(got, "symfony") || !contains(got, "console") {
		t.Errorf("php candidates must include vendor and package, got %v", got)
	}
	if got := RubyCandidates("rest-client"); !contains(got, "rest_client") || !contains(got, "rest-client") {
		t.Errorf("ruby candidates must cover both forms, got %v", got)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
