package jsimports_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jsimports"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jsresolve"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.JSImportScanner = (*jsimports.Scanner)(nil)

func write(t *testing.T, file, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestScannerGraphIsAcceptedByTheResolver is the load-bearing contract between phase R1 (this scanner)
// and phase R2 (jsresolve.Resolver). The resolver REFUSES an internally inconsistent graph — in
// particular an unresolved relative edge with no matching coverage issue at the same line — so this test
// proves the scanner's coverage attribution satisfies the resolver rather than merely looking plausible.
func TestScannerGraphIsAcceptedByTheResolver(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	write(t, filepath.Join(root, "package.json"), `{"name":"app","version":"1.0.0","workspaces":["packages/*"]}`)
	write(t, filepath.Join(root, "packages", "shared", "package.json"), `{"name":"@workspace/shared","version":"0.1.0"}`)
	write(t, filepath.Join(root, "packages", "shared", "src", "index.ts"), `export const shared = 1;`)
	write(t, filepath.Join(root, "src", "index.ts"), `
import lodash from "lodash";
import * as fs from "node:fs";
import path from "path";
import { shared } from "@workspace/shared";
import { local } from "./local";
import type { T } from "some-types";
export * from "./reexported";
const cjs = require("commonjs-pkg");
await import("dynamic-pkg");
import missing from "./absent";
require(computed);
`)
	write(t, filepath.Join(root, "src", "local.ts"), `export const local = 1;`)
	write(t, filepath.Join(root, "src", "reexported.ts"), `export const re = 1;`)

	graph, err := jsimports.New().Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// The resolver validates the graph shape and errors on an inconsistency.
	result, err := jsresolve.NewResolver().Resolve(context.Background(), root, graph, nil)
	if err != nil {
		t.Fatalf("resolver rejected the scanner graph: %v", err)
	}

	byStatus := map[jsresolution.Status][]string{}
	for _, imp := range result.Imports {
		byStatus[imp.Status] = append(byStatus[imp.Status], imp.Specifier)
	}

	// Node built-ins must never be mistaken for npm dependencies.
	assertContains(t, byStatus[jsresolution.StatusBuiltin], "node:fs")
	assertContains(t, byStatus[jsresolution.StatusBuiltin], "path")
	// A first-party workspace package must never be classified as a third-party component. At this
	// phase the resolver reports it as AMBIGUOUS with a reason (workspace linking and a same-named
	// registry package are indistinguishable without lockfile importer context, which phase R2C adds);
	// what this test locks is that it is never silently a component.
	assertContains(t, byStatus[jsresolution.StatusAmbiguous], "@workspace/shared")
	if contains(byStatus[jsresolution.StatusComponent], "@workspace/shared") {
		t.Error("a local workspace package must never resolve to a third-party component")
	}
	// Third-party specifiers stay unresolved at this phase: no SBOM was supplied, and R2C owns
	// component correlation. What matters is that they are explicit, never silently dropped.
	for _, specifier := range []string{"lodash", "some-types", "commonjs-pkg", "dynamic-pkg"} {
		if !containsAny(byStatus, specifier) {
			t.Errorf("specifier %q disappeared from resolution output", specifier)
		}
	}

	// The unobservable computed require and the unresolved relative import must both leave the
	// combined result incomplete, so no analyzer can draw a negative conclusion from this graph.
	if result.Complete {
		t.Fatal("a graph containing a computed require and an unresolved relative import must not be complete")
	}
	if len(result.GraphCoverage) == 0 {
		t.Fatal("scanner coverage issues must survive into the resolver result")
	}
}

// TestScannerCleanProjectYieldsCompleteResolution proves the converse: a fully observable project
// produces no coverage issues, which is the precondition for any later negative reachability proof.
func TestScannerCleanProjectYieldsCompleteResolution(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	write(t, filepath.Join(root, "package.json"), `{"name":"clean","version":"1.0.0"}`)
	write(t, filepath.Join(root, "src", "index.ts"), "import * as fs from \"node:fs\";\nimport { helper } from \"./helper\";\nexport const run = () => helper(fs);\n")
	write(t, filepath.Join(root, "src", "helper.ts"), "export const helper = (x: unknown) => x;\n")

	graph, err := jsimports.New().Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(graph.Coverage) != 0 {
		t.Fatalf("a fully observable project must produce no coverage issues, got %+v", graph.Coverage)
	}

	result, err := jsresolve.NewResolver().Resolve(context.Background(), root, graph, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !result.Complete {
		t.Fatalf("expected complete resolution for a clean project, got coverage %+v", result.Coverage)
	}
}

func assertContains(t *testing.T, values []string, want string) {
	t.Helper()
	if !contains(values, want) {
		t.Errorf("expected %q among %v", want, values)
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

func containsAny(byStatus map[jsresolution.Status][]string, want string) bool {
	for _, values := range byStatus {
		for _, value := range values {
			if value == want {
				return true
			}
		}
	}
	return false
}
