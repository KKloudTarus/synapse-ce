package jsresolution

import (
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
)

// NormalizeResult validates, deduplicates, and deterministically sorts package
// resolution output without mutating the caller's slices. Complete is derived
// from package-resolution coverage and explicit unresolved states. Source graph
// coverage is preserved separately for the later reachability gate.
func NormalizeResult(in Result) (Result, error) {
	in.DeclaredDependencies = normalizeNameList(in.DeclaredDependencies)
	out := Result{}
	out.Imports = make([]ImportResolution, 0, len(in.Imports))
	for _, resolution := range in.Imports {
		normalized, err := normalizeImportResolution(resolution)
		if err != nil {
			return Result{}, err
		}
		out.Imports = append(out.Imports, normalized)
	}
	sort.Slice(out.Imports, func(i, j int) bool { return importResolutionLess(out.Imports[i], out.Imports[j]) })
	out.Imports = deduplicateImportResolutions(out.Imports)

	out.Coverage = make([]CoverageIssue, 0, len(in.Coverage))
	for _, issue := range in.Coverage {
		if !issue.Kind.Valid() {
			return Result{}, fmt.Errorf("jsresolution: invalid coverage issue kind %q", issue.Kind)
		}
		if issue.Path != "" {
			loc, err := NormalizeRepositoryLocation(issue.Path)
			if err != nil {
				return Result{}, fmt.Errorf("normalize coverage path %q: %w", issue.Path, err)
			}
			issue.Path = loc
		}
		issue.Detail = strings.TrimSpace(issue.Detail)
		out.Coverage = append(out.Coverage, issue)
	}
	sort.Slice(out.Coverage, func(i, j int) bool {
		a, b := out.Coverage[i], out.Coverage[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Detail < b.Detail
	})
	out.Coverage = deduplicateCoverage(out.Coverage)

	out.GraphCoverage = make([]modulegraph.CoverageIssue, 0, len(in.GraphCoverage))
	for _, issue := range in.GraphCoverage {
		if !issue.Kind.Valid() {
			return Result{}, fmt.Errorf("jsresolution: invalid graph coverage issue kind %q", issue.Kind)
		}
		if issue.Line < 0 {
			return Result{}, fmt.Errorf("jsresolution: negative graph coverage line for %q", issue.Path)
		}
		if issue.Path != "" {
			loc, err := modulegraph.NormalizeRepositoryPath(issue.Path)
			if err != nil {
				return Result{}, fmt.Errorf("normalize graph coverage path %q: %w", issue.Path, err)
			}
			issue.Path = loc
		}
		issue.Detail = strings.TrimSpace(issue.Detail)
		out.GraphCoverage = append(out.GraphCoverage, issue)
	}
	sort.Slice(out.GraphCoverage, func(i, j int) bool {
		a, b := out.GraphCoverage[i], out.GraphCoverage[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Detail < b.Detail
	})
	out.GraphCoverage = deduplicateGraphCoverage(out.GraphCoverage)

	out.Complete = len(out.Coverage) == 0
	for _, resolution := range out.Imports {
		switch resolution.Status {
		case StatusBuiltin, StatusLocal, StatusWorkspace, StatusComponent:
		default:
			out.Complete = false
		}
	}
	return out, nil
}

func normalizeImportResolution(in ImportResolution) (ImportResolution, error) {
	if !in.Status.Valid() {
		return ImportResolution{}, fmt.Errorf("jsresolution: invalid resolution status %q", in.Status)
	}
	if !in.Kind.Valid() {
		return ImportResolution{}, fmt.Errorf("jsresolution: invalid import kind %q", in.Kind)
	}
	if in.Position.Line < 0 || in.Position.Column < 0 {
		return ImportResolution{}, fmt.Errorf("jsresolution: negative source position for %q", in.From)
	}
	from, err := modulegraph.NormalizeRepositoryPath(in.From)
	if err != nil {
		return ImportResolution{}, fmt.Errorf("normalize resolution source %q: %w", in.From, err)
	}
	in.From = from
	if in.Specifier == "" || strings.IndexByte(in.Specifier, 0) >= 0 {
		return ImportResolution{}, fmt.Errorf("jsresolution: invalid empty or NUL module specifier from %q", from)
	}
	in.Package, err = normalizeIdentity(in.Package, in.Status == StatusBuiltin)
	if err != nil {
		return ImportResolution{}, fmt.Errorf("normalize package identity for %q: %w", in.Specifier, err)
	}
	in.Candidates = append([]PackageIdentity(nil), in.Candidates...)
	for i := range in.Candidates {
		in.Candidates[i], err = normalizeIdentity(in.Candidates[i], false)
		if err != nil {
			return ImportResolution{}, fmt.Errorf("normalize candidate for %q: %w", in.Specifier, err)
		}
	}
	sort.Slice(in.Candidates, func(i, j int) bool { return identityLess(in.Candidates[i], in.Candidates[j]) })
	in.Candidates = deduplicateIdentities(in.Candidates)
	in.Reason = strings.TrimSpace(in.Reason)
	if err := validateResolutionShape(in); err != nil {
		return ImportResolution{}, fmt.Errorf("jsresolution: invalid resolution for %q: %w", in.Specifier, err)
	}
	return in, nil
}

func validateResolutionShape(in ImportResolution) error {
	zeroPackage := PackageIdentity{}
	switch in.Status {
	case StatusBuiltin:
		if !strings.HasPrefix(in.Package.Name, "node:") || in.Package.Path != "" || in.Package.Version != "" || in.Package.PURL != "" || in.Package.Workspace {
			return fmt.Errorf("builtin status requires a canonical node: identity only")
		}
		if len(in.Candidates) != 0 {
			return fmt.Errorf("builtin status cannot carry candidates")
		}
	case StatusLocal:
		if in.Package.Path == "" || in.Package.Workspace || in.Package.PURL != "" {
			return fmt.Errorf("local status requires a non-workspace repository path and no component PURL")
		}
		if len(in.Candidates) != 0 {
			return fmt.Errorf("local status cannot carry candidates")
		}
	case StatusWorkspace:
		if in.Package.Path == "" || !in.Package.Workspace || in.Package.PURL != "" {
			return fmt.Errorf("workspace status requires a workspace repository path and no component PURL")
		}
		if len(in.Candidates) != 0 {
			return fmt.Errorf("workspace status cannot carry candidates")
		}
	case StatusComponent:
		if in.Package.PURL == "" || in.Package.Workspace {
			return fmt.Errorf("component status requires a non-workspace PURL identity")
		}
		if len(in.Candidates) != 0 {
			return fmt.Errorf("component status cannot carry candidates")
		}
	case StatusUnresolved:
		if len(in.Candidates) != 0 || in.Package.Workspace || in.Package.PURL != "" || in.Package.Path != "" {
			return fmt.Errorf("unresolved status may carry only an optional lexical package name")
		}
		if in.Reason == "" {
			return fmt.Errorf("unresolved status requires a reason")
		}
	case StatusAmbiguous:
		if in.Package != zeroPackage || len(in.Candidates) < 2 || in.Reason == "" {
			return fmt.Errorf("ambiguous status requires at least two candidates, no selected package, and a reason")
		}
	case StatusUnsupported:
		if in.Package != zeroPackage || len(in.Candidates) != 0 || in.Reason == "" {
			return fmt.Errorf("unsupported status requires no package or candidates and a reason")
		}
	}
	return nil
}

func normalizeIdentity(in PackageIdentity, builtin bool) (PackageIdentity, error) {
	var err error
	if in.Name != "" {
		if builtin {
			if !strings.HasPrefix(in.Name, "node:") {
				return PackageIdentity{}, fmt.Errorf("builtin identity %q is not canonical node: form", in.Name)
			}
			name := strings.TrimPrefix(in.Name, "node:")
			if !isNodeBuiltin(name) {
				return PackageIdentity{}, fmt.Errorf("builtin identity %q is not a known Node built-in module", in.Name)
			}
		} else {
			if strings.HasPrefix(in.Name, "node:") {
				return PackageIdentity{}, fmt.Errorf("node: identity %q is only valid with builtin status", in.Name)
			}
			in.Name, err = NormalizePackageName(in.Name)
			if err != nil {
				return PackageIdentity{}, err
			}
		}
	}
	in.Version = strings.TrimSpace(in.Version)
	in.PURL = strings.TrimSpace(in.PURL)
	if in.Path != "" {
		in.Path, err = NormalizeRepositoryLocation(in.Path)
		if err != nil {
			return PackageIdentity{}, err
		}
	}
	return in, nil
}

func importResolutionLess(a, b ImportResolution) bool {
	if a.From != b.From {
		return a.From < b.From
	}
	if a.Specifier != b.Specifier {
		return a.Specifier < b.Specifier
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Position.Line != b.Position.Line {
		return a.Position.Line < b.Position.Line
	}
	if a.Position.Column != b.Position.Column {
		return a.Position.Column < b.Position.Column
	}
	if a.TypeOnly != b.TypeOnly {
		return !a.TypeOnly && b.TypeOnly
	}
	if a.DeclarationOnly != b.DeclarationOnly {
		return !a.DeclarationOnly && b.DeclarationOnly
	}
	if a.Status != b.Status {
		return a.Status < b.Status
	}
	if identityLess(a.Package, b.Package) {
		return true
	}
	if identityLess(b.Package, a.Package) {
		return false
	}
	if a.Reason != b.Reason {
		return a.Reason < b.Reason
	}
	return identitiesLess(a.Candidates, b.Candidates)
}

func identityLess(a, b PackageIdentity) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	if a.PURL != b.PURL {
		return a.PURL < b.PURL
	}
	if a.Workspace != b.Workspace {
		return !a.Workspace && b.Workspace
	}
	return a.Path < b.Path
}

func identitiesLess(a, b []PackageIdentity) bool {
	limit := len(a)
	if len(b) < limit {
		limit = len(b)
	}
	for i := 0; i < limit; i++ {
		if a[i] == b[i] {
			continue
		}
		return identityLess(a[i], b[i])
	}
	return len(a) < len(b)
}

func deduplicateIdentities(in []PackageIdentity) []PackageIdentity {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for _, value := range in[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func deduplicateImportResolutions(in []ImportResolution) []ImportResolution {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for _, value := range in[1:] {
		if !importResolutionsEqual(value, out[len(out)-1]) {
			out = append(out, value)
		}
	}
	return out
}

func importResolutionsEqual(a, b ImportResolution) bool {
	if a.From != b.From || a.Specifier != b.Specifier || a.Position != b.Position || a.Kind != b.Kind ||
		a.TypeOnly != b.TypeOnly || a.DeclarationOnly != b.DeclarationOnly || a.Status != b.Status ||
		a.Package != b.Package || a.Reason != b.Reason || len(a.Candidates) != len(b.Candidates) {
		return false
	}
	for i := range a.Candidates {
		if a.Candidates[i] != b.Candidates[i] {
			return false
		}
	}
	return true
}

func deduplicateGraphCoverage(in []modulegraph.CoverageIssue) []modulegraph.CoverageIssue {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for _, value := range in[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

// normalizeNameList sorts and deduplicates a package-name list so resolution output does not depend on
// manifest key order.
func normalizeNameList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, name := range in {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	result := out[:1]
	for _, name := range out[1:] {
		if name != result[len(result)-1] {
			result = append(result, name)
		}
	}
	return result
}
