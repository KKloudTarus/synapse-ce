package jsresolution

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// NormalizePackageName canonicalizes an npm package name. It preserves scoped
// package roots and rejects strings that cannot safely identify an npm package.
func NormalizePackageName(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(raw))
	if name == "" {
		return "", fmt.Errorf("jsresolution: empty package name")
	}
	if strings.ContainsAny(name, "\\\x00\r\n\t ") {
		return "", fmt.Errorf("jsresolution: invalid package name %q", raw)
	}
	if strings.HasPrefix(name, "@") {
		parts := strings.Split(name[1:], "/")
		if len(parts) != 2 || !validPackagePart(parts[0]) || !validPackagePart(parts[1]) {
			return "", fmt.Errorf("jsresolution: invalid scoped package name %q", raw)
		}
		return "@" + parts[0] + "/" + parts[1], nil
	}
	if strings.Contains(name, "/") || !validPackagePart(name) {
		return "", fmt.Errorf("jsresolution: invalid package name %q", raw)
	}
	return name, nil
}

func validPackagePart(part string) bool {
	if part == "" || strings.HasPrefix(part, ".") || strings.HasPrefix(part, "_") {
		return false
	}
	for _, r := range part {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || strings.ContainsRune("-._~", r) {
			continue
		}
		return false
	}
	return true
}

// NormalizeRepositoryLocation canonicalizes a slash-separated repository
// location. Filesystem adapters are responsible for converting native path
// separators before constructing domain values. Backslash and colon remain
// ordinary filename characters here so POSIX paths such as "c:tmp" and
// "packages\\private" cannot be conflated with Windows path syntax.
func NormalizeRepositoryLocation(raw string) (string, error) {
	if strings.IndexByte(raw, 0) >= 0 {
		return "", fmt.Errorf("jsresolution: repository location contains NUL")
	}
	if raw == "" || raw == "." {
		return ".", nil
	}
	if strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("jsresolution: absolute repository location %q", raw)
	}
	cleaned := path.Clean(raw)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("jsresolution: repository location %q escapes root", raw)
	}
	return strings.TrimPrefix(cleaned, "./"), nil
}

// NormalizeInventory validates, deduplicates, and deterministically sorts an
// inventory without mutating the input. Complete is derived from coverage.
func NormalizeInventory(in Inventory) (Inventory, error) {
	if in.EntriesScanned < 0 || in.FilesScanned < 0 {
		return Inventory{}, fmt.Errorf("jsresolution: negative inventory counters")
	}
	out := Inventory{EntriesScanned: in.EntriesScanned, FilesScanned: in.FilesScanned}
	byPath := make(map[string]PackageMetadata, len(in.Packages))
	for _, pkg := range in.Packages {
		loc, err := NormalizeRepositoryLocation(pkg.Path)
		if err != nil {
			return Inventory{}, fmt.Errorf("normalize package path %q: %w", pkg.Path, err)
		}
		pkg.Path = loc
		if pkg.Name != "" {
			pkg.Name, err = NormalizePackageName(pkg.Name)
			if err != nil {
				return Inventory{}, fmt.Errorf("normalize package at %q: %w", loc, err)
			}
		}
		pkg.Version = strings.TrimSpace(pkg.Version)
		pkg.DeclaredBy, err = normalizeDeclarations(pkg.DeclaredBy)
		if err != nil {
			return Inventory{}, fmt.Errorf("normalize declarations for %q: %w", loc, err)
		}
		if prev, ok := byPath[loc]; ok {
			if !packageMetadataEqual(prev, pkg) {
				return Inventory{}, fmt.Errorf("jsresolution: conflicting package metadata at %q", loc)
			}
			continue
		}
		byPath[loc] = pkg
	}
	out.Packages = make([]PackageMetadata, 0, len(byPath))
	for _, pkg := range byPath {
		out.Packages = append(out.Packages, pkg)
	}
	sort.Slice(out.Packages, func(i, j int) bool {
		if out.Packages[i].Path != out.Packages[j].Path {
			return out.Packages[i].Path < out.Packages[j].Path
		}
		return out.Packages[i].Name < out.Packages[j].Name
	})

	out.Coverage = make([]CoverageIssue, 0, len(in.Coverage))
	for _, issue := range in.Coverage {
		if !issue.Kind.Valid() {
			return Inventory{}, fmt.Errorf("jsresolution: invalid coverage issue kind %q", issue.Kind)
		}
		if issue.Path != "" {
			loc, err := NormalizeRepositoryLocation(issue.Path)
			if err != nil {
				return Inventory{}, fmt.Errorf("normalize coverage path %q: %w", issue.Path, err)
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
	out.Complete = len(out.Coverage) == 0
	return out, nil
}

func normalizeDeclarations(in []MetadataDeclaration) ([]MetadataDeclaration, error) {
	out := make([]MetadataDeclaration, 0, len(in))
	for _, decl := range in {
		loc, err := NormalizeRepositoryLocation(decl.Source)
		if err != nil {
			return nil, err
		}
		decl.Source = loc
		// Pattern is declared metadata, not a filesystem-derived location. Keep
		// its literal whitespace intact; only normalize the declared separator.
		decl.Pattern = strings.ReplaceAll(decl.Pattern, "\\", "/")
		out = append(out, decl)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Pattern < out[j].Pattern
	})
	if len(out) < 2 {
		return out, nil
	}
	result := out[:1]
	for _, value := range out[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result, nil
}

func packageMetadataEqual(a, b PackageMetadata) bool {
	if a.Name != b.Name || a.Version != b.Version || a.Path != b.Path || a.Private != b.Private || a.Workspace != b.Workspace || len(a.DeclaredBy) != len(b.DeclaredBy) {
		return false
	}
	for i := range a.DeclaredBy {
		if a.DeclaredBy[i] != b.DeclaredBy[i] {
			return false
		}
	}
	return true
}

func deduplicateCoverage(in []CoverageIssue) []CoverageIssue {
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
