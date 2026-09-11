package srcimports

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeDotNetFile(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// TestDotNetScanImportsObservesNamespaces: a `using` names a namespace, which the scanner emits with its
// dotted prefixes so a package matches whether source imports its root namespace or a sub-namespace. With no
// dynamic construct the observation is complete (a negative conclusion is safe).
func TestDotNetScanImportsObservesNamespaces(t *testing.T) {
	dir := t.TempDir()
	writeDotNetFile(t, dir, "Program.cs", `using System;
using Newtonsoft.Json.Linq;
using static Dapper.SqlMapper;
using Log = Serilog.Log;

namespace App { class P { static void Main() {} } }
`)
	graph, err := NewDotNetScanner().ScanImports(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !graph.Complete() {
		t.Fatalf("no dynamic construct, so the scan must be complete; reasons=%v", graph.CoverageReasons)
	}
	refs := map[string]bool{}
	for _, p := range graph.ImportedPackages {
		refs[p] = true
	}
	for _, want := range []string{"newtonsoft.json.linq", "newtonsoft.json", "newtonsoft", "dapper", "serilog"} {
		if !refs[want] {
			t.Errorf("missing observed namespace/prefix %q in %v", want, graph.ImportedPackages)
		}
	}
}

// TestDotNetReflectionMakesScanIncomplete: a reflection construct means a package could be reached without a
// visible using, so the scan records a coverage reason and no negative conclusion is safe.
func TestDotNetReflectionMakesScanIncomplete(t *testing.T) {
	dir := t.TempDir()
	writeDotNetFile(t, dir, "Loader.cs", `using System;
using System.Reflection;
class L { object M(string n) { return Activator.CreateInstance(Type.GetType(n)); } }
`)
	graph, err := NewDotNetScanner().ScanImports(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if graph.Complete() {
		t.Error("reflection must make the observation incomplete (no safe negative conclusion)")
	}
}

// TestNuGetDirectDependencies: PackageReference and central-package-management PackageVersion entries across
// project and props files are the direct dependencies.
func TestNuGetDirectDependencies(t *testing.T) {
	dir := t.TempDir()
	writeDotNetFile(t, dir, "src/App.csproj", `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Version="2.1.35" Include="Dapper" />
  </ItemGroup>
</Project>
`)
	writeDotNetFile(t, dir, "Directory.Packages.props", `<Project>
  <ItemGroup>
    <PackageVersion Include="Serilog" Version="3.1.1" />
  </ItemGroup>
</Project>
`)
	// A build-output copy must be skipped (bin/obj), so a stale reference there does not leak in.
	writeDotNetFile(t, dir, "src/obj/App.csproj", `<Project><ItemGroup><PackageReference Include="Ghost.Package" /></ItemGroup></Project>`)

	got, ok := DirectDependencies(context.Background(), dir, "nuget")
	if !ok {
		t.Fatal("a .csproj must be found")
	}
	for _, want := range []string{"newtonsoft.json", "dapper", "serilog"} {
		if !got[want] {
			t.Errorf("missing direct dep %q in %v", want, got)
		}
	}
	if got["ghost.package"] {
		t.Error("a PackageReference under obj/ must be skipped")
	}
}

// TestNuGetDirectDependenciesAbsent: with no project file, coverage is absent (found=false), so the analyzer
// refuses a negative conclusion rather than treating a subject as un-referenced.
func TestNuGetDirectDependenciesAbsent(t *testing.T) {
	dir := t.TempDir()
	writeDotNetFile(t, dir, "Program.cs", "class P {}")
	if _, ok := DirectDependencies(context.Background(), dir, "nuget"); ok {
		t.Error("with no project file, direct-dependency coverage must be absent")
	}
}

// TestDotNetCandidates: a package name expands to itself and its dotted prefixes, so it matches an imported
// root or sub-namespace.
func TestDotNetCandidates(t *testing.T) {
	got := DotNetCandidates("Microsoft.Extensions.Logging")
	want := map[string]bool{"microsoft.extensions.logging": true, "microsoft.extensions": true, "microsoft": true}
	for _, c := range got {
		delete(want, c)
	}
	if len(want) != 0 {
		t.Errorf("DotNetCandidates missing %v; got %v", want, got)
	}
}

// TestDotNetReferenceFormsAreObserved covers the reference forms a package can appear in WITHOUT a plain
// `using X;`, each of which must still be observed so it is never falsely reported un-referenced: an inline
// fully-qualified reference (including a lowercase namespace segment), a C# `global::` qualifier, a VB
// `Global.` qualifier, and a Razor single-segment `@using`.
func TestDotNetReferenceFormsAreObserved(t *testing.T) {
	dir := t.TempDir()
	writeDotNetFile(t, dir, "Program.cs", `namespace App {
  class P {
    static void Main() {
      var s = new Newtonsoft.Json.JsonSerializer();          // inline FQN, PascalCase
      var w = new mycompany.legacy.Widget();                 // inline FQN, lowercase segment
      var g = new global::Serilog.Core.Logger();             // C# global:: qualifier
    }
  }
}
`)
	writeDotNetFile(t, dir, "Legacy.vb", "Dim x = New Global.RestSharp.RestClient()\n")                 // VB Global. qualifier
	writeDotNetFile(t, dir, "View.razor", "@using MudBlazor\n<Component />\n")                          // Razor single-segment @using
	writeDotNetFile(t, dir, "Alias.cs", "using MB = global::MudBlazor;\nusing NS = UI::NServiceBus;\n") // alias to a ::-qualified single-segment namespace
	graph, err := NewDotNetScanner().ScanImports(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	refs := map[string]bool{}
	for _, p := range graph.ImportedPackages {
		refs[p] = true
	}
	for _, want := range []string{"newtonsoft.json", "mycompany.legacy", "serilog", "serilog.core", "restsharp", "mudblazor", "nservicebus"} {
		if !refs[want] {
			t.Errorf("reference %q must be observed (a missed reference becomes a false not-referenced); got %v", want, graph.ImportedPackages)
		}
	}
}

// TestDotNetProjectGlobalUsingsObserved: a package reached through a GLOBAL using (a project-declared
// `<Using Include>`, a VB `<Import Include>`, or an SDK/package-generated global using written under obj/)
// is observed even though no scanned source file names it. With the generated global-using set present, the
// observation of implicit usings is complete, so the scan stays complete.
func TestDotNetProjectGlobalUsingsObserved(t *testing.T) {
	dir := t.TempDir()
	writeDotNetFile(t, dir, "src/App.csproj", `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
  <ItemGroup>
    <Using Include="NServiceBus" />
    <Import Include="RestSharp" />
  </ItemGroup>
</Project>
`)
	// The generated set the SDK writes under obj/ (skipped by the source walk) records a package-contributed
	// global using; it must still be read so a package used unqualified is observed.
	writeDotNetFile(t, dir, "src/obj/Debug/net8.0/App.GlobalUsings.g.cs",
		"// <auto-generated/>\nglobal using global::System;\nglobal using MudBlazor;\n")
	// A source file that uses those namespaces only unqualified (no `using`, no dotted reference).
	writeDotNetFile(t, dir, "src/Program.cs", "class P { void M(EndpointConfiguration c) {} }\n")

	graph, err := NewDotNetScanner().ScanImports(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !graph.Complete() {
		t.Fatalf("implicit usings with a generated global-using set present must be complete; reasons=%v", graph.CoverageReasons)
	}
	refs := map[string]bool{}
	for _, p := range graph.ImportedPackages {
		refs[p] = true
	}
	for _, want := range []string{"nservicebus", "restsharp", "mudblazor"} {
		if !refs[want] {
			t.Errorf("global using %q must be observed (a missed global using becomes a false not-referenced); got %v", want, graph.ImportedPackages)
		}
	}
}

// TestDotNetImplicitUsingsWithoutGeneratedSetIsIncomplete: implicit usings on, no generated global-using
// set to enumerate. A package could be contributed as a global using by its own build props and referenced
// unqualified, which the source tree cannot reveal, so the scan must be INCOMPLETE (no negative conclusion,
// the safe direction) rather than report an actually-used package as un-referenced.
func TestDotNetImplicitUsingsWithoutGeneratedSetIsIncomplete(t *testing.T) {
	dir := t.TempDir()
	writeDotNetFile(t, dir, "App.csproj", `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
</Project>
`)
	writeDotNetFile(t, dir, "Program.cs", "using System;\nclass P { static void Main() {} }\n")

	graph, err := NewDotNetScanner().ScanImports(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if graph.Complete() {
		t.Errorf("implicit usings with no generated global-using set must be incomplete (no safe negative); reasons=%v", graph.CoverageReasons)
	}
}

// TestDotNetImplicitUsingsDisabledStaysComplete: with implicit usings off, a package can only be reached by
// a form the scanner already observes, so the scan is complete.
func TestDotNetImplicitUsingsDisabledStaysComplete(t *testing.T) {
	dir := t.TempDir()
	writeDotNetFile(t, dir, "App.csproj", `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <ImplicitUsings>disable</ImplicitUsings>
  </PropertyGroup>
</Project>
`)
	writeDotNetFile(t, dir, "Program.cs", "using Serilog;\nclass P { static void Main() {} }\n")

	graph, err := NewDotNetScanner().ScanImports(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !graph.Complete() {
		t.Fatalf("implicit usings disabled must stay complete; reasons=%v", graph.CoverageReasons)
	}
	refs := map[string]bool{}
	for _, p := range graph.ImportedPackages {
		refs[p] = true
	}
	if !refs["serilog"] {
		t.Errorf("serilog must be observed; got %v", graph.ImportedPackages)
	}
}

// TestDotNetPerProjectImplicitUsingsGate: the implicit-usings completeness gate is PER PROJECT. Project A
// (implicit usings, unbuilt: no generated set) must make the whole scan incomplete even though unrelated
// project B (implicit usings, built) has a generated set. A single global "found a generated file" flag
// would wrongly clear A's gap and let a package globally imported in A be reported un-referenced.
func TestDotNetPerProjectImplicitUsingsGate(t *testing.T) {
	dir := t.TempDir()
	writeDotNetFile(t, dir, "a/A.csproj", `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><ImplicitUsings>enable</ImplicitUsings></PropertyGroup>
</Project>
`)
	writeDotNetFile(t, dir, "a/Program.cs", "using System;\nclass A {}\n")
	writeDotNetFile(t, dir, "b/B.csproj", `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><ImplicitUsings>enable</ImplicitUsings></PropertyGroup>
</Project>
`)
	writeDotNetFile(t, dir, "b/Program.cs", "using System;\nclass B {}\n")
	writeDotNetFile(t, dir, "b/obj/Debug/net8.0/B.GlobalUsings.g.cs", "global using System;\n")

	graph, err := NewDotNetScanner().ScanImports(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if graph.Complete() {
		t.Errorf("project A (implicit usings, no generated set) must make the scan incomplete even though B is built; reasons=%v", graph.CoverageReasons)
	}
}

// TestDotNetUsingItemQuoteAndListForms: a global-using item may use either quote style and is an MSBuild
// item LIST, and an item resolved from an MSBuild property cannot be observed. Each must be handled so a
// listed package is observed and an unresolvable one blocks the conclusion rather than being dropped.
func TestDotNetUsingItemQuoteAndListForms(t *testing.T) {
	dir := t.TempDir()
	writeDotNetFile(t, dir, "App.csproj", `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <Using Include='Serilog' />
    <Using Include="System;NServiceBus" />
    <Using Include="$(BusNamespace)" />
  </ItemGroup>
</Project>
`)
	writeDotNetFile(t, dir, "Program.cs", "class P {}\n")

	graph, err := NewDotNetScanner().ScanImports(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	refs := map[string]bool{}
	for _, p := range graph.ImportedPackages {
		refs[p] = true
	}
	for _, want := range []string{"serilog", "nservicebus"} {
		if !refs[want] {
			t.Errorf("using item %q must be observed; got %v", want, graph.ImportedPackages)
		}
	}
	if graph.Complete() {
		t.Errorf("a using item resolved from an MSBuild property must make the scan incomplete; reasons=%v", graph.CoverageReasons)
	}
}

// TestDotNetNamespaceDeclarationAndRootNamespaceObserved: a file declared in a package's own namespace, or a
// project whose RootNamespace is a package namespace, reaches that package's types unqualified, so both are
// observed.
func TestDotNetNamespaceDeclarationAndRootNamespaceObserved(t *testing.T) {
	dir := t.TempDir()
	writeDotNetFile(t, dir, "App.csproj", `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><RootNamespace>RestSharp</RootNamespace></PropertyGroup>
</Project>
`)
	writeDotNetFile(t, dir, "Handler.cs", "namespace NServiceBus;\nclass P { void M(EndpointConfiguration c) {} }\n")
	writeDotNetFile(t, dir, "Legacy.vb", "Namespace Serilog\n  Class L\n  End Class\nEnd Namespace\n")

	graph, err := NewDotNetScanner().ScanImports(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	refs := map[string]bool{}
	for _, p := range graph.ImportedPackages {
		refs[p] = true
	}
	for _, want := range []string{"nservicebus", "serilog", "restsharp"} {
		if !refs[want] {
			t.Errorf("declared namespace/root namespace %q must be observed; got %v", want, graph.ImportedPackages)
		}
	}
}

// TestDotNetGeneratedObjSourceObserved: a package named only by generated source under obj/ (a source
// generator's or a compiled Razor view's output) must be observed, because the hand-written source may
// reference only the generated type. Dynamic markers in generated AssemblyInfo must NOT poison the scan.
func TestDotNetGeneratedObjSourceObserved(t *testing.T) {
	dir := t.TempDir()
	writeDotNetFile(t, dir, "App.csproj", `<Project Sdk="Microsoft.NET.Sdk"></Project>`)
	writeDotNetFile(t, dir, "Program.cs", "class P { void M(App.Protos.Client c) {} }\n")
	// Generated gRPC client under obj names the runtime package the hand-written source never does.
	writeDotNetFile(t, dir, "obj/Debug/net8.0/Protos.g.cs", "namespace App.Protos { class Client : Grpc.Core.ClientBase { } }\n")
	// Generated AssemblyInfo names System.Reflection; it must not add a reflection coverage reason.
	writeDotNetFile(t, dir, "obj/Debug/net8.0/App.AssemblyInfo.g.cs", "[assembly: System.Reflection.AssemblyCompanyAttribute(\"App\")]\n")

	graph, err := NewDotNetScanner().ScanImports(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	refs := map[string]bool{}
	for _, p := range graph.ImportedPackages {
		refs[p] = true
	}
	if !refs["grpc.core"] {
		t.Errorf("a package named only by generated obj source must be observed; got %v", graph.ImportedPackages)
	}
	if !graph.Complete() {
		t.Errorf("generated AssemblyInfo naming System.Reflection must not poison the scan; reasons=%v", graph.CoverageReasons)
	}
}

// TestDotNetVBGlobalQualifierCaseInsensitive: VB is case-insensitive, so an uppercase `GLOBAL.` root
// qualifier must be stripped like `Global.`, leaving the package namespace observable.
func TestDotNetVBGlobalQualifierCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	writeDotNetFile(t, dir, "Legacy.vb", "Dim c = New GLOBAL.RestSharp.RestClient()\n")

	graph, err := NewDotNetScanner().ScanImports(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	refs := map[string]bool{}
	for _, p := range graph.ImportedPackages {
		refs[p] = true
	}
	if !refs["restsharp"] {
		t.Errorf("an uppercase GLOBAL. qualifier must be stripped; got %v", graph.ImportedPackages)
	}
}

// TestDotNetVBCommaImportsObserved: a VB `Imports` line names several namespaces separated by commas; a
// later single-segment one must be observed, not just the first.
func TestDotNetVBCommaImportsObserved(t *testing.T) {
	dir := t.TempDir()
	writeDotNetFile(t, dir, "Legacy.vb", "Imports System, Dapper, JsonNet = Newtonsoft.Json\nClass L\nEnd Class\n")

	graph, err := NewDotNetScanner().ScanImports(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	refs := map[string]bool{}
	for _, p := range graph.ImportedPackages {
		refs[p] = true
	}
	for _, want := range []string{"dapper", "newtonsoft.json"} {
		if !refs[want] {
			t.Errorf("VB comma import %q must be observed; got %v", want, graph.ImportedPackages)
		}
	}
}

// TestDotNetUnresolvedMSBuildFormsBlockConclusion: an implicit-usings, using-item, or root-namespace value
// driven by an MSBuild property/item resolves only at build time, so each must block a negative conclusion
// rather than be silently dropped.
func TestDotNetUnresolvedMSBuildFormsBlockConclusion(t *testing.T) {
	cases := []struct {
		name string
		proj string
	}{
		{"implicit-usings property", `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><ImplicitUsings>$(UseImplicitUsings)</ImplicitUsings></PropertyGroup></Project>`},
		{"using-item item-expression", `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><Using Include="@(GlobalUsings)" /></ItemGroup></Project>`},
		{"root-namespace property", `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><RootNamespace>$(Ns)</RootNamespace></PropertyGroup></Project>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeDotNetFile(t, dir, "App.csproj", tc.proj)
			writeDotNetFile(t, dir, "Program.cs", "using System;\nclass P {}\n")
			graph, err := NewDotNetScanner().ScanImports(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			if graph.Complete() {
				t.Errorf("%s must block the negative conclusion; reasons=%v", tc.name, graph.CoverageReasons)
			}
		})
	}
}
