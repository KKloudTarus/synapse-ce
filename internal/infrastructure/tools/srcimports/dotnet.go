package srcimports

import (
	"context"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// DotNetScanner observes namespace references in first-party C#/VB.NET source. A NuGet package is reached
// through a `using`/`Imports` of one (or a sub-namespace) of the namespaces it ships, so the scanner emits
// each imported namespace and its dotted prefixes; the candidate namer emits the package name and its
// prefixes, and a match on any shared prefix is a reference (over-matching biases to "reachable", the safe
// direction). It is source-only: it lexes text and never runs dotnet, msbuild or a runtime.
//
// A package can also be reached WITHOUT any visible per-file `using`, which observeProjectImports handles on
// a second pass over the project/props files and the obj/ build output (both skipped by the source walk):
//   - a GLOBAL using imports a namespace project-wide, so source references its types unqualified. These
//     come from a project `<Using Include="X"/>` (C#) or `<Import Include="X"/>` (VB), or the generated
//     `*GlobalUsings.g.cs` (SDK- and package-contributed usings). The declared ones are parsed; the
//     generated set is read from obj/.
//   - generated source under obj/ (a source generator, a compiled Razor view) can name a package the
//     hand-written source never does, so every `.cs`/`.vb` under obj/ is scanned for references too.
//   - a file declared IN a package's own namespace (`namespace NServiceBus;`) reaches that package's types
//     unqualified, so `namespace` declarations and `<RootNamespace>` are emitted.
//
// When a project enables `<ImplicitUsings>` but its generated global-using set is absent (an unbuilt tree),
// a package contributed as a global using by its own build props would be reachable unqualified yet
// unobservable, so a per-project coverage reason blocks any negative conclusion for that project.
type DotNetScanner struct{ limits scanLimits }

var _ ports.SourceImportScanner = (*DotNetScanner)(nil)

// NewDotNetScanner returns a scanner with production bounds.
func NewDotNetScanner() *DotNetScanner { return &DotNetScanner{limits: defaultScanLimits()} }

// Lang reports the package-URL type this scanner observes.
func (DotNetScanner) Lang() string { return "nuget" }

// dotnetDynamic are constructs under which a package can be reached without a visible `using`: .NET resolves
// types and methods at runtime from strings via reflection, and a DI container or assembly load can
// materialize a type the source never names.
var dotnetDynamic = []dynamicConstruct{
	{marker: "System.Reflection", reason: "reflection resolves a type or method from a runtime value"},
	{marker: "Activator.CreateInstance", reason: "Activator.CreateInstance resolves a type from a runtime value"},
	{marker: "Type.GetType", reason: "Type.GetType resolves a type name from a runtime string"},
	{marker: "Assembly.Load", reason: "an assembly is loaded from a name computed at runtime"},
	{marker: "AppDomain", reason: "AppDomain can load an assembly at runtime"},
	{marker: ".GetMethod(", reason: "a method is resolved by name from a runtime value"},
	{marker: ".GetType(", reason: "a type is resolved by name from a runtime value"},
	{marker: ".Invoke(", reason: "a member is invoked reflectively"},
	{marker: "dynamic ", reason: "a dynamic binding resolves members at runtime"},
}

// csharpUsingRe matches a C# `using`/Razor `@using` directive and a VB `Imports` (plain, `static`, aliased,
// or `global`). It captures the trailing namespace, which may be a SINGLE segment (`@using MudBlazor`), so it
// is not covered by the dotted-reference regex below. The C# form's trailing `;` is optional so Razor
// (`@using X`, no semicolon) is included. An optional `<qualifier>::` prefix (a `global::` or an extern-alias
// `UI::`) on the target is consumed so the captured namespace starts at the real name, not the qualifier,
// which matters for an alias to a single-segment namespace (`using MB = global::MudBlazor;`).
var csharpUsingRe = regexp.MustCompile(`(?im)^\s*(?:@)?(?:global\s+)?(?:using|imports)\s+(?:static\s+)?(?:[A-Za-z_][A-Za-z0-9_]*\s*=\s*)?(?:[A-Za-z_][A-Za-z0-9_]*::)?([A-Za-z_][A-Za-z0-9_.]*)`)

// csharpDottedRe matches ANY dotted identifier (any case), which is how a package is referenced by its
// fully-qualified name with no `using` (`new Newtonsoft.Json.Foo()`, `foo.bar.Widget.Do()`). It deliberately
// over-matches a `list.Where` chain because that only ADDS reachability (the safe direction) and never hides a
// real reference; the point is that a package's namespace never fails to be observed. A `global::` C#
// qualifier is split by the `::` (not in the character class), so `global::Newtonsoft.Json` yields the token
// `Newtonsoft.Json`; a VB `Global.` prefix is stripped when the token is emitted.
var csharpDottedRe = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\b`)

// csharpNamespaceRe matches a C# `namespace X.Y` (block or file-scoped) or a VB `Namespace X` declaration.
// A file declared in a package's own namespace can reference that package's types with no qualifier, so the
// declared namespace is emitted. `(?i)` covers VB's capitalised keyword; over-matching a first-party
// namespace only adds reachability (the safe direction).
var csharpNamespaceRe = regexp.MustCompile(`(?im)^\s*namespace\s+([A-Za-z_][A-Za-z0-9_.]*)`)

// dotnetSkipDir are build-output and tooling directories that hold no first-party source.
var dotnetSkipDir = map[string]bool{
	"bin": true, "obj": true, "packages": true, ".vs": true, ".git": true, "node_modules": true,
	"TestResults": true, ".idea": true,
}

// ScanImports walks dir and returns the namespace references it can observe.
func (s *DotNetScanner) ScanImports(ctx context.Context, dir string) (ports.SourceImportGraph, error) {
	walker := newSourceWalker(s.limits, []string{".cs", ".vb", ".cshtml", ".razor"}, dotnetSkipDir).
		withExemptCoverage(dotnetSkipDir)
	scan, err := walker.walk(ctx, dir, func(p string, content []byte, out *scanAccumulator) {
		raw := string(content)
		emitDotNetReferences(out, stripLineComments(raw, "//"))
		out.noteDynamic(raw, dotnetDynamic, p)
	})
	if err != nil {
		return ports.SourceImportGraph{}, err
	}
	// Second pass over what the source walk cannot see: project/props declarations, the generated
	// global-using set, and generated source under obj/. Runs on the same accumulator so its observations
	// join the source ones.
	s.observeProjectImports(ctx, dir, scan)
	return scan.graph(), nil
}

// emitDotNetReferences records every namespace a body references: a per-file/global `using`, a dotted
// fully-qualified reference, and the file's own `namespace` declaration (a file declared in a package's
// namespace reaches that package's types unqualified). It is emit-only; dynamic-construct detection is the
// caller's job, so generated code (whose AssemblyInfo names System.Reflection) never falsely marks a scan
// incomplete.
func emitDotNetReferences(out *scanAccumulator, body string) {
	for _, m := range csharpUsingRe.FindAllStringSubmatch(body, -1) {
		emitDotNetName(out, m[1])
	}
	for _, m := range csharpDottedRe.FindAllStringSubmatch(body, -1) {
		emitDotNetName(out, m[1])
	}
	for _, m := range csharpNamespaceRe.FindAllStringSubmatch(body, -1) {
		emitDotNetName(out, m[1])
	}
	// VB `Imports A, B` names several namespaces on one line; emit every comma clause (an XML-namespace
	// import clause starts with `<` and is skipped, an alias clause keeps its right side).
	for _, m := range vbImportsRe.FindAllStringSubmatch(body, -1) {
		for _, clause := range strings.Split(m[1], ",") {
			clause = strings.TrimSpace(clause)
			if clause == "" || strings.HasPrefix(clause, "<") {
				continue
			}
			if _, alias, ok := strings.Cut(clause, "="); ok {
				clause = strings.TrimSpace(alias)
			}
			emitDotNetName(out, clause)
		}
	}
}

// emitDotNetName records a namespace token and its dotted prefixes. A `Global.` root qualifier is not part
// of any package's namespace, so it is dropped first; VB is case-insensitive, so `Global.`, `global.` and
// `GLOBAL.` are all recognised (Global.Newtonsoft.Json -> Newtonsoft.Json).
func emitDotNetName(out *scanAccumulator, token string) {
	if idx := strings.IndexByte(token, '.'); idx > 0 && strings.EqualFold(token[:idx], "global") {
		token = token[idx+1:]
	}
	for _, name := range dottedPrefixes(token) {
		out.addPackage(name)
	}
}

// DotNetCandidates expands a NuGet package name into the source-level namespaces that reference it: the
// package name is (almost always) its root namespace, so the package name and its dotted prefixes are the
// candidates. Matching either the full name or a prefix against an observed namespace (or its prefix) counts
// as a reference.
func DotNetCandidates(packageName string) []string {
	return normalizeNames(dottedPrefixes(strings.ToLower(strings.TrimSpace(packageName))))
}

// dottedPrefixes returns a dotted name and each of its leading prefixes, longest first
// ("a.b.c" -> ["a.b.c", "a.b", "a"]). It biases matching toward "reachable": a package whose namespace is a
// prefix of an imported sub-namespace (or vice versa) still matches.
func dottedPrefixes(name string) []string {
	name = strings.Trim(strings.TrimSpace(name), ".")
	if name == "" {
		return nil
	}
	segments := strings.Split(name, ".")
	out := make([]string, 0, len(segments))
	for i := len(segments); i >= 1; i-- {
		out = append(out, strings.Join(segments[:i], "."))
	}
	return out
}

// dotnetUsingItemRe matches an MSBuild global-using item: a C# `<Using Include="X" .../>` or a VB
// `<Import Include="X" .../>`. Such an item imports X into EVERY file in the project, so source can
// reference X's types with no visible `using`; emitting X observes the package regardless. The Include
// value uses either quote style and is an MSBuild item list (`Include="A;B"`), so the caller splits it on
// `;`. The `\b` after the tag name excludes `<UsingTask>` and `<ImportGroup>`; a VB `<Import Project="..."/>`
// (an MSBuild file import, not a namespace) carries no Include attribute and is not matched.
var dotnetUsingItemRe = regexp.MustCompile(`(?is)<(?:Using|Import)\b[^>]*\bInclude\s*=\s*(?:"([^"]*)"|'([^']*)')`)

// dotnetRootNamespaceRe matches `<RootNamespace>X</RootNamespace>`. Types in a file with no namespace
// declaration fall under the root namespace, so a package sharing it is reachable unqualified; emitting X
// observes it. A value carrying an MSBuild property is left to the property handling.
var dotnetRootNamespaceRe = regexp.MustCompile(`(?is)<RootNamespace>\s*([^<]+?)\s*</RootNamespace>`)

// dotnetImplicitUsingsRe captures the `<ImplicitUsings>` value. `enable`/`true` turns implicit usings on;
// a value carrying an MSBuild property (`$(UseImplicitUsings)`) resolves at build time and cannot be read
// here, so it is treated as possibly-on (the safe direction). When on, the SDK compiles project- and
// package-contributed `<Using>` items into a generated `obj/…GlobalUsings.g.cs` the source tree lacks.
var dotnetImplicitUsingsRe = regexp.MustCompile(`(?is)<ImplicitUsings>\s*([^<]*?)\s*</ImplicitUsings>`)

// vbImportsRe captures the clause list of a VB `Imports` line, which unlike C# `using` may name several
// namespaces separated by commas (`Imports System, Dapper`). The first is also seen by csharpUsingRe, but a
// later single-segment namespace is not, so the whole list is split on `,` and each clause emitted.
var vbImportsRe = regexp.MustCompile(`(?im)^\s*imports\s+(.+?)\s*$`)

// isUnresolvedMSBuild reports whether a value embeds an MSBuild property (`$(...)`) or item (`@(...)`)
// expression, which resolves only at build time and so names a namespace this scan cannot know.
func isUnresolvedMSBuild(value string) bool {
	return strings.Contains(value, "$(") || strings.Contains(value, "@(")
}

// implicitUsingsInPlay reports whether a manifest turns implicit usings on, treating a property-driven
// value as possibly-on.
func implicitUsingsInPlay(body string) bool {
	for _, m := range dotnetImplicitUsingsRe.FindAllStringSubmatch(body, -1) {
		value := strings.TrimSpace(m[1])
		if strings.EqualFold(value, "enable") || strings.EqualFold(value, "true") || isUnresolvedMSBuild(value) {
			return true
		}
	}
	return false
}

// dotnetImportSkipDir are directories the second pass skips. Unlike the source walk it does NOT skip obj/,
// because the generated GlobalUsings.g.cs and other generated source (the authoritative record of global
// usings and of code a source generator emits) live there.
var dotnetImportSkipDir = map[string]bool{
	"bin": true, "packages": true, ".vs": true, ".git": true, "node_modules": true,
	"TestResults": true, ".idea": true,
}

// isGeneratedGlobalUsings reports whether a file is an SDK-generated global-usings file
// (GlobalUsings.g.cs or <Project>.GlobalUsings.g.cs), which enumerates every global using in effect.
func isGeneratedGlobalUsings(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), "globalusings.g.cs")
}

// isDotNetSourceExt reports whether a file name is compilable .NET source.
func isDotNetSourceExt(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".cs") || strings.HasSuffix(lower, ".vb")
}

// hasObjSegment reports whether a slash path descends through an obj/ build-output directory.
func hasObjSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "obj" {
			return true
		}
	}
	return false
}

// observeProjectImports is the second pass over what the source walk cannot see. It parses project/props
// files for declared global usings and root namespaces, reads generated source under obj/ (the global-using
// set and any source-generator output), and, per project, records a coverage reason when implicit usings
// are enabled but that project's generated global-using set is absent. It mutates out in place and never
// fails the scan; an unreadable tree simply contributes nothing.
func (s *DotNetScanner) observeProjectImports(ctx context.Context, dir string, out *scanAccumulator) {
	if ctx == nil || ctx.Err() != nil {
		return
	}
	rootDir, err := os.OpenRoot(strings.TrimSpace(dir))
	if err != nil {
		return
	}
	defer func() { _ = rootDir.Close() }()

	// A project's generated global-using set lives under <projectDir>/obj. implicitObjPrefixes collects that
	// prefix for each project with implicit usings enabled; generatedPaths collects every generated
	// global-usings file. A project whose prefix has no matching generated file was not built, so its global
	// usings are unobservable.
	var implicitObjPrefixes []string
	var generatedPaths []string
	files := 0
	entries := 0
	_ = fs.WalkDir(rootDir.FS(), ".", func(p string, d fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			return fs.SkipAll
		}
		if walkErr != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		entries++
		if entries > s.limits.maxEntries {
			out.addReason("directory entry budget exceeded before project imports were fully observed")
			return fs.SkipAll
		}
		if d.IsDir() {
			if p != "." && (dotnetImportSkipDir[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		name := d.Name()
		isManifest := isNuGetManifest(name)
		// Generated source under obj/ can name a package the hand-written source never does; the source walk
		// skips obj/, so it is read here (references only, no dynamic detection).
		isObjSource := isDotNetSourceExt(name) && hasObjSegment(p)
		if !isManifest && !isObjSource {
			return nil
		}
		if files >= s.limits.maxFiles {
			out.addReason("file budget exceeded before project imports were fully observed")
			return fs.SkipAll
		}
		files++
		content, ok := readThroughRoot(rootDir, p, s.limits.maxFileBytes)
		if !ok {
			out.addReason("a project or generated source file could not be read (" + p + ")")
			return nil
		}
		body := string(content)
		if isManifest {
			s.observeManifest(out, p, body)
			if implicitUsingsInPlay(body) {
				implicitObjPrefixes = append(implicitObjPrefixes, path.Join(path.Dir(p), "obj")+"/")
			}
		}
		if isObjSource {
			emitDotNetReferences(out, stripLineComments(body, "//"))
			if isGeneratedGlobalUsings(name) {
				generatedPaths = append(generatedPaths, p)
			}
		}
		return nil
	})
	for _, prefix := range implicitObjPrefixes {
		built := false
		for _, g := range generatedPaths {
			if strings.HasPrefix(g, prefix) {
				built = true
				break
			}
		}
		if !built {
			out.addReason("implicit/global usings are enabled for a project (" + prefix + ") but its generated global-using set is absent, so a package contributed as a global using and referenced unqualified cannot be observed; build the project or reference such packages explicitly")
		}
	}
}

// observeManifest emits the global usings and root namespace an MSBuild project or props file declares. A
// `<Using Include>` (or VB `<Import Include>`) value is an item list split on `;`; an item or root namespace
// carrying an unresolved MSBuild property or item expression names a namespace the scan cannot know, so it
// records a coverage reason instead of guessing.
func (s *DotNetScanner) observeManifest(out *scanAccumulator, p, body string) {
	for _, m := range dotnetUsingItemRe.FindAllStringSubmatch(body, -1) {
		value := m[1]
		if value == "" {
			value = m[2]
		}
		for _, item := range strings.Split(value, ";") {
			item = strings.TrimSpace(item)
			switch {
			case item == "":
				continue
			case isUnresolvedMSBuild(item):
				out.addReason("a global using is declared with an unresolved MSBuild expression (" + p + "), so its namespace cannot be observed")
			default:
				emitDotNetName(out, item)
			}
		}
	}
	for _, m := range dotnetRootNamespaceRe.FindAllStringSubmatch(body, -1) {
		value := strings.TrimSpace(m[1])
		switch {
		case value == "":
			continue
		case isUnresolvedMSBuild(value):
			out.addReason("a root namespace is declared with an unresolved MSBuild expression (" + p + "), so a package sharing it cannot be ruled out")
		default:
			emitDotNetName(out, value)
		}
	}
}
