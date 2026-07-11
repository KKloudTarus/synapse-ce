package licensefile

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

const mitText = `MIT License

Copyright (c) 2024 Example

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`

func writeFile(t *testing.T, dir string, rel string, content string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestResolveNodeModulesDependency(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "node_modules/lodash/LICENSE", mitText)
	writeFile(t, dir, "node_modules/@scope/pkg/LICENSE.md", mitText)
	comps := []sbom.Component{
		{Name: "lodash", Version: "4.17.21"},
		{Name: "@scope/pkg", Version: "1.0.0"},
	}
	if n := New().Resolve(context.Background(), dir, comps); n != 2 {
		t.Fatalf("resolved = %d, want 2", n)
	}
	for i := range comps {
		if len(comps[i].Licenses) == 0 || comps[i].Licenses[0].SPDXID != "MIT" {
			t.Fatalf("%s license = %+v, want MIT", comps[i].Name, comps[i].Licenses)
		}
		if comps[i].LicenseSource != sbom.LicenseSourceLicenseFile {
			t.Errorf("%s source = %q, want local-file", comps[i].Name, comps[i].LicenseSource)
		}
		if comps[i].LicenseConfidencePct <= 0 {
			t.Errorf("%s confidence = %v, want > 0", comps[i].Name, comps[i].LicenseConfidencePct)
		}
	}
}

func TestResolveVendoredDependencyByDir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "packages/mypkg/COPYING", mitText)
	comps := []sbom.Component{{Name: "mypkg", Version: "2.0.0"}}
	if n := New().Resolve(context.Background(), dir, comps); n != 1 {
		t.Fatalf("resolved = %d, want 1", n)
	}
	if comps[0].Licenses[0].SPDXID != "MIT" {
		t.Fatalf("license = %+v", comps[0].Licenses)
	}
}

func TestResolveRootLicenseGoesToFirstPartyOnly(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "LICENSE", mitText)
	comps := []sbom.Component{
		{Name: "my-app", FirstParty: true},                                                     // the project itself → gets the root LICENSE
		{Name: "some-dep", Version: "1.0.0"},                                                   // a dependency declared at root → must NOT
		{Name: "declared", FirstParty: true, Licenses: []sbom.License{{SPDXID: "Apache-2.0"}}}, // already set → untouched
	}
	if n := New().Resolve(context.Background(), dir, comps); n != 1 {
		t.Fatalf("resolved = %d, want 1 (first-party only)", n)
	}
	if comps[0].Licenses[0].SPDXID != "MIT" {
		t.Errorf("first-party license = %+v, want MIT", comps[0].Licenses)
	}
	if len(comps[1].Licenses) != 0 {
		t.Errorf("dependency wrongly licensed from root LICENSE: %+v", comps[1].Licenses)
	}
	if comps[2].Licenses[0].SPDXID != "Apache-2.0" {
		t.Errorf("declared license overwritten: %+v", comps[2].Licenses)
	}
}

func TestResolveSkipsAmbiguousName(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "node_modules/utils/LICENSE", mitText)
	comps := []sbom.Component{
		{Name: "utils", Version: "1.0.0"},
		{Name: "utils", Version: "2.0.0"}, // same name → ambiguous → never guessed
	}
	if n := New().Resolve(context.Background(), dir, comps); n != 0 {
		t.Fatalf("ambiguous name must not be resolved, got %d", n)
	}
}

func TestChainRunsResolversInOrder(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "node_modules/lodash/LICENSE", mitText)
	comps := []sbom.Component{{Name: "lodash", Version: "4.17.21"}}
	// Chain with a nil + the real resolver; nil is skipped, real one resolves.
	if n := NewChain(nil, New()).Resolve(context.Background(), dir, comps); n != 1 {
		t.Fatalf("chain resolved = %d, want 1", n)
	}
	if comps[0].Licenses[0].SPDXID != "MIT" {
		t.Fatalf("license = %+v", comps[0].Licenses)
	}
}

// A symlink named LICENSE must NOT be followed – that would read an arbitrary host file
// outside the workspace (and attribute it to a component). Security guard.
func TestResolveIgnoresSymlinkedLicense(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "mit.txt")
	if err := os.WriteFile(outside, []byte(mitText), 0o644); err != nil {
		t.Fatal(err)
	}
	depDir := filepath.Join(dir, "node_modules", "lodash")
	if err := os.MkdirAll(depDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(depDir, "LICENSE")); err != nil {
		t.Skipf("symlinks unsupported here: %v", err)
	}
	comps := []sbom.Component{{Name: "lodash", Version: "4.17.21"}}
	if n := New().Resolve(context.Background(), dir, comps); n != 0 {
		t.Fatalf("symlinked LICENSE must be skipped, got resolved=%d", n)
	}
	if len(comps[0].Licenses) != 0 {
		t.Fatalf("symlinked license wrongly attributed: %+v", comps[0].Licenses)
	}
}
