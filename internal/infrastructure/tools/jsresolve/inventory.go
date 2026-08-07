// Package jsresolve provides offline, deterministic JavaScript and TypeScript
// package-identity metadata processing. It never executes project tooling.
package jsresolve

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	defaultMaxEntries       = 100000
	defaultMaxMetadataFiles = 10000
	defaultMaxMetadataBytes = int64(2 << 20)
)

// InventoryBuilder discovers package.json and workspace metadata beneath one
// repository root using bounded, source-only filesystem reads.
type InventoryBuilder struct {
	maxEntries       int
	maxMetadataFiles int
	maxMetadataBytes int64
}

// NewInventoryBuilder returns a bounded offline metadata inventory builder.
func NewInventoryBuilder() *InventoryBuilder {
	return &InventoryBuilder{
		maxEntries:       defaultMaxEntries,
		maxMetadataFiles: defaultMaxMetadataFiles,
		maxMetadataBytes: defaultMaxMetadataBytes,
	}
}

type packageFile struct {
	file     string
	dir      string
	name     string
	version  string
	private  bool
	patterns []string
}

type workspaceSource struct {
	source   string
	baseDir  string
	patterns []string
}

// Build returns a deterministic inventory of package metadata and first-party
// workspaces. Malformed or unsupported metadata becomes explicit incomplete
// coverage whenever the remaining repository can still be inventoried safely.
func (b *InventoryBuilder) Build(ctx context.Context, root string) (jsresolution.Inventory, error) {
	if ctx == nil {
		return jsresolution.Inventory{}, fmt.Errorf("%w: context is required", shared.ErrValidation)
	}
	if strings.TrimSpace(root) == "" {
		return jsresolution.Inventory{}, fmt.Errorf("%w: repository root is required", shared.ErrValidation)
	}
	if err := ctx.Err(); err != nil {
		return jsresolution.Inventory{}, err
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return jsresolution.Inventory{}, fmt.Errorf("%w: resolve repository root: %v", shared.ErrValidation, err)
	}
	rootInfo, err := os.Lstat(rootAbs)
	if err != nil {
		return jsresolution.Inventory{}, fmt.Errorf("%w: repository root: %v", shared.ErrValidation, err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return jsresolution.Inventory{}, fmt.Errorf("%w: repository root must be a real directory", shared.ErrValidation)
	}

	inventory := jsresolution.Inventory{}
	packages := make(map[string]packageFile)
	var sources []workspaceSource
	var symlinks []string

	walkErr := filepath.WalkDir(rootAbs, func(current string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			rel := repositoryRelative(rootAbs, current)
			inventory.Coverage = append(inventory.Coverage, jsresolution.CoverageIssue{
				Kind: jsresolution.CoverageUnreadableMetadata, Path: rel, Detail: "filesystem entry could not be inspected",
			})
			return nil
		}
		inventory.EntriesScanned++
		if inventory.EntriesScanned > b.maxEntries {
			inventory.Coverage = append(inventory.Coverage, jsresolution.CoverageIssue{
				Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: ".", Detail: fmt.Sprintf("filesystem entry budget exceeded (%d)", b.maxEntries),
			})
			return fs.SkipAll
		}
		if entry.IsDir() {
			if current != rootAbs && skipMetadataDir(entry.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			rel := repositoryRelative(rootAbs, current)
			symlinks = append(symlinks, rel)
			if entry.Name() == "package.json" || entry.Name() == "pnpm-workspace.yaml" {
				inventory.Coverage = append(inventory.Coverage, jsresolution.CoverageIssue{
					Kind: jsresolution.CoverageSymlinkWorkspace, Path: rel, Detail: "workspace metadata is symlinked and was not followed",
				})
			}
			return nil
		}
		if entry.Name() != "package.json" && entry.Name() != "pnpm-workspace.yaml" {
			return nil
		}
		if inventory.FilesScanned >= b.maxMetadataFiles {
			inventory.Coverage = append(inventory.Coverage, jsresolution.CoverageIssue{
				Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: repositoryRelative(rootAbs, current), Detail: fmt.Sprintf("metadata file budget exceeded (%d)", b.maxMetadataFiles),
			})
			return fs.SkipAll
		}
		inventory.FilesScanned++
		content, readErr := readBoundedMetadata(current, b.maxMetadataBytes)
		if readErr != nil {
			kind := jsresolution.CoverageUnreadableMetadata
			if errorsIsMetadataTooLarge(readErr) {
				kind = jsresolution.CoverageMetadataBudgetExceeded
			}
			inventory.Coverage = append(inventory.Coverage, jsresolution.CoverageIssue{
				Kind: kind, Path: repositoryRelative(rootAbs, current), Detail: readErr.Error(),
			})
			return nil
		}
		if entry.Name() == "package.json" {
			pkg, parseErr := parsePackageJSON(repositoryRelative(rootAbs, current), content)
			if parseErr != nil {
				inventory.Coverage = append(inventory.Coverage, jsresolution.CoverageIssue{
					Kind: jsresolution.CoverageMalformedMetadata, Path: repositoryRelative(rootAbs, current), Detail: parseErr.Error(),
				})
				if pkg.file == "" {
					return nil
				}
			}
			if pkg.name != "" {
				normalized, nameErr := jsresolution.NormalizePackageName(pkg.name)
				if nameErr != nil {
					inventory.Coverage = append(inventory.Coverage, jsresolution.CoverageIssue{
						Kind: jsresolution.CoverageMalformedMetadata, Path: pkg.file, Detail: nameErr.Error(),
					})
					pkg.name = ""
				} else {
					pkg.name = normalized
				}
			}
			packages[pkg.dir] = pkg
			if len(pkg.patterns) > 0 {
				sources = append(sources, workspaceSource{source: pkg.file, baseDir: pkg.dir, patterns: pkg.patterns})
			}
			return nil
		}
		patterns, parseErr := parsePNPMWorkspace(content)
		if parseErr != nil {
			inventory.Coverage = append(inventory.Coverage, jsresolution.CoverageIssue{
				Kind: jsresolution.CoverageMalformedMetadata, Path: repositoryRelative(rootAbs, current), Detail: parseErr.Error(),
			})
			return nil
		}
		sources = append(sources, workspaceSource{
			source: repositoryRelative(rootAbs, current),
			baseDir: repositoryRelative(rootAbs, filepath.Dir(current)),
			patterns: patterns,
		})
		return nil
	})
	if walkErr != nil {
		if err := ctx.Err(); err != nil {
			return jsresolution.Inventory{}, err
		}
		return jsresolution.Inventory{}, fmt.Errorf("inventory javascript metadata: %w", walkErr)
	}

	sort.Slice(sources, func(i, j int) bool { return sources[i].source < sources[j].source })
	sort.Strings(symlinks)
	workspaceDecls := make(map[string][]jsresolution.MetadataDeclaration)
	for _, source := range sources {
		compiled, issues := compileWorkspacePatterns(source)
		inventory.Coverage = append(inventory.Coverage, issues...)
		for dir := range packages {
			if decl, ok := selectWorkspaceDeclaration(compiled, dir); ok {
				workspaceDecls[dir] = append(workspaceDecls[dir], decl)
			}
		}
		for _, symlink := range symlinks {
			if decl, ok := selectWorkspaceDeclaration(compiled, symlink); ok {
				inventory.Coverage = append(inventory.Coverage, jsresolution.CoverageIssue{
					Kind: jsresolution.CoverageSymlinkWorkspace, Path: symlink,
					Detail: fmt.Sprintf("workspace pattern %q from %s resolves to a symlink", decl.Pattern, decl.Source),
				})
			}
		}
	}

	packageDirs := make([]string, 0, len(packages))
	for dir := range packages {
		packageDirs = append(packageDirs, dir)
	}
	sort.Strings(packageDirs)
	for _, dir := range packageDirs {
		pkg := packages[dir]
		decls := workspaceDecls[dir]
		isWorkspace := len(decls) > 0
		if isWorkspace && pkg.name == "" {
			inventory.Coverage = append(inventory.Coverage, jsresolution.CoverageIssue{
				Kind: jsresolution.CoverageMalformedMetadata, Path: pkg.file, Detail: "workspace package must declare a valid name",
			})
		}
		inventory.Packages = append(inventory.Packages, jsresolution.PackageMetadata{
			Name: pkg.name, Version: strings.TrimSpace(pkg.version), Path: dir, Private: pkg.private,
			Workspace: isWorkspace, DeclaredBy: decls,
		})
	}

	addWorkspaceConflicts(&inventory)
	return jsresolution.NormalizeInventory(inventory)
}

type compiledPattern struct {
	source  string
	pattern string
	match   string
	negated bool
}

func compileWorkspacePatterns(source workspaceSource) ([]compiledPattern, []jsresolution.CoverageIssue) {
	out := make([]compiledPattern, 0, len(source.patterns))
	var issues []jsresolution.CoverageIssue
	for _, raw := range source.patterns {
		pattern, negated, err := normalizeWorkspacePattern(source.baseDir, raw)
		if err != nil {
			kind := jsresolution.CoverageUnsupportedMetadata
			if strings.Contains(err.Error(), "escapes root") || strings.Contains(err.Error(), "absolute") {
				kind = jsresolution.CoverageWorkspaceRootEscape
			}
			issues = append(issues, jsresolution.CoverageIssue{Kind: kind, Path: source.source, Detail: err.Error()})
			continue
		}
		out = append(out, compiledPattern{source: source.source, pattern: strings.TrimSpace(raw), match: pattern, negated: negated})
	}
	return out, issues
}

func selectWorkspaceDeclaration(patterns []compiledPattern, target string) (jsresolution.MetadataDeclaration, bool) {
	included := false
	var selected compiledPattern
	for _, pattern := range patterns {
		if !matchWorkspacePattern(pattern.match, target) {
			continue
		}
		if pattern.negated {
			included = false
			selected = compiledPattern{}
			continue
		}
		included = true
		selected = pattern
	}
	if !included {
		return jsresolution.MetadataDeclaration{}, false
	}
	return jsresolution.MetadataDeclaration{Source: selected.source, Pattern: selected.pattern}, true
}

func normalizeWorkspacePattern(baseDir, raw string) (string, bool, error) {
	value := strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	if value == "" {
		return "", false, fmt.Errorf("empty workspace pattern")
	}
	negated := strings.HasPrefix(value, "!")
	if negated {
		value = strings.TrimSpace(strings.TrimPrefix(value, "!"))
		if value == "" {
			return "", false, fmt.Errorf("empty negated workspace pattern")
		}
	}
	if strings.HasPrefix(value, "/") || hasWindowsVolumePrefix(value) {
		return "", false, fmt.Errorf("workspace pattern %q is absolute", raw)
	}
	if strings.ContainsAny(value, "{}") {
		return "", false, fmt.Errorf("workspace pattern %q uses unsupported brace expansion", raw)
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "**" {
			continue
		}
		if _, err := path.Match(segment, "probe"); err != nil {
			return "", false, fmt.Errorf("workspace pattern %q has invalid glob syntax", raw)
		}
	}
	base := baseDir
	if base == "." {
		base = ""
	}
	joined := path.Clean(path.Join(base, value))
	if joined == ".." || strings.HasPrefix(joined, "../") {
		return "", false, fmt.Errorf("workspace pattern %q escapes root", raw)
	}
	if joined == "." {
		return ".", negated, nil
	}
	return strings.TrimPrefix(joined, "./"), negated, nil
}

func matchWorkspacePattern(pattern, target string) bool {
	pattern = strings.Trim(strings.TrimSpace(pattern), "/")
	target = strings.Trim(strings.TrimSpace(target), "/")
	if pattern == "" || pattern == "." {
		return target == "" || target == "."
	}
	if target == "." {
		target = ""
	}
	return matchSegments(strings.Split(pattern, "/"), splitPathSegments(target), 0, 0)
}

func splitPathSegments(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, "/")
}

func matchSegments(pattern, target []string, pi, ti int) bool {
	if pi == len(pattern) {
		return ti == len(target)
	}
	if pattern[pi] == "**" {
		for next := ti; next <= len(target); next++ {
			if matchSegments(pattern, target, pi+1, next) {
				return true
			}
		}
		return false
	}
	if ti == len(target) {
		return false
	}
	matched, err := path.Match(pattern[pi], target[ti])
	if err != nil || !matched {
		return false
	}
	return matchSegments(pattern, target, pi+1, ti+1)
}

func parsePackageJSON(rel string, content []byte) (packageFile, error) {
	var raw struct {
		Name       string          `json:"name"`
		Version    string          `json:"version"`
		Private    bool            `json:"private"`
		Workspaces json.RawMessage `json:"workspaces"`
	}
	if err := json.Unmarshal(content, &raw); err != nil {
		return packageFile{}, fmt.Errorf("parse package.json: %w", err)
	}
	patterns, workspaceErr := parseJSONWorkspaces(raw.Workspaces)
	dir := path.Dir(rel)
	pkg := packageFile{file: rel, dir: dir, name: raw.Name, version: raw.Version, private: raw.Private, patterns: patterns}
	if workspaceErr != nil {
		return pkg, workspaceErr
	}
	return pkg, nil
}

func parseJSONWorkspaces(raw json.RawMessage) ([]string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	switch trimmed[0] {
	case '[':
		var patterns []string
		if err := json.Unmarshal(trimmed, &patterns); err != nil {
			return nil, fmt.Errorf("parse package.json workspaces: %w", err)
		}
		return patterns, nil
	case '{':
		var object struct {
			Packages []string `json:"packages"`
		}
		if err := json.Unmarshal(trimmed, &object); err != nil {
			return nil, fmt.Errorf("parse package.json workspaces object: %w", err)
		}
		if object.Packages == nil {
			return nil, fmt.Errorf("package.json workspaces object has no packages list")
		}
		return object.Packages, nil
	default:
		return nil, fmt.Errorf("package.json workspaces must be an array or object")
	}
}

func parsePNPMWorkspace(content []byte) ([]string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	found := false
	baseIndent := -1
	var patterns []string
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " \t\r")
		plain := strings.TrimSpace(stripYAMLComment(line))
		if plain == "" {
			continue
		}
		indent := leadingSpaces(line)
		if !found {
			if plain == "packages:" {
				found = true
				baseIndent = indent
				continue
			}
			if strings.HasPrefix(plain, "packages:") {
				return nil, fmt.Errorf("pnpm-workspace.yaml flow-style packages are unsupported")
			}
			continue
		}
		if indent <= baseIndent {
			break
		}
		item := strings.TrimSpace(stripYAMLComment(line))
		if !strings.HasPrefix(item, "-") {
			return nil, fmt.Errorf("pnpm-workspace.yaml packages must be a scalar list")
		}
		item = strings.TrimSpace(strings.TrimPrefix(item, "-"))
		if item == "" {
			return nil, fmt.Errorf("pnpm-workspace.yaml contains an empty package pattern")
		}
		value, err := unquoteYAMLScalar(item)
		if err != nil {
			return nil, fmt.Errorf("pnpm-workspace.yaml package pattern: %w", err)
		}
		patterns = append(patterns, value)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read pnpm-workspace.yaml: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("pnpm-workspace.yaml has no packages list")
	}
	return patterns, nil
}

func stripYAMLComment(line string) string {
	inSingle, inDouble := false, false
	for i, r := range line {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
				return line[:i]
			}
		}
	}
	return line
}

func unquoteYAMLScalar(value string) (string, error) {
	if strings.HasPrefix(value, "\"") {
		unquoted, err := strconv.Unquote(value)
		if err != nil {
			return "", err
		}
		return unquoted, nil
	}
	if strings.HasPrefix(value, "'") {
		if len(value) < 2 || !strings.HasSuffix(value, "'") {
			return "", fmt.Errorf("unterminated single-quoted scalar")
		}
		return strings.ReplaceAll(value[1:len(value)-1], "''", "'"), nil
	}
	return strings.TrimSpace(value), nil
}

func leadingSpaces(line string) int {
	count := 0
	for _, r := range line {
		if r != ' ' {
			break
		}
		count++
	}
	return count
}

func readBoundedMetadata(file string, max int64) ([]byte, error) {
	info, err := os.Lstat(file)
	if err != nil {
		return nil, fmt.Errorf("inspect metadata: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("metadata is symlinked")
	}
	if info.Size() > max {
		return nil, metadataTooLargeError{size: info.Size(), max: max}
	}
	f, err := os.Open(file) //nolint:gosec // path comes from bounded WalkDir beneath validated root
	if err != nil {
		return nil, fmt.Errorf("open metadata: %w", err)
	}
	defer func() { _ = f.Close() }()
	content, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, fmt.Errorf("read metadata: %w", err)
	}
	if int64(len(content)) > max {
		return nil, metadataTooLargeError{size: int64(len(content)), max: max}
	}
	return content, nil
}

type metadataTooLargeError struct {
	size int64
	max  int64
}

func (e metadataTooLargeError) Error() string {
	return fmt.Sprintf("metadata file is too large (%d bytes > %d)", e.size, e.max)
}

func errorsIsMetadataTooLarge(err error) bool {
	_, ok := err.(metadataTooLargeError)
	return ok
}

func addWorkspaceConflicts(inventory *jsresolution.Inventory) {
	byName := map[string][]string{}
	for _, pkg := range inventory.Packages {
		if pkg.Workspace && pkg.Name != "" {
			byName[pkg.Name] = append(byName[pkg.Name], pkg.Path)
		}
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		paths := byName[name]
		if len(paths) < 2 {
			continue
		}
		sort.Strings(paths)
		inventory.Coverage = append(inventory.Coverage, jsresolution.CoverageIssue{
			Kind: jsresolution.CoverageWorkspaceNameConflict,
			Detail: fmt.Sprintf("workspace package %q is declared at multiple roots: %s", name, strings.Join(paths, ", ")),
		})
	}
}

func repositoryRelative(root, file string) string {
	rel, err := filepath.Rel(root, file)
	if err != nil || rel == "" || rel == "." {
		return "."
	}
	return filepath.ToSlash(rel)
}

func skipMetadataDir(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", "node_modules":
		return true
	default:
		return false
	}
}

func hasWindowsVolumePrefix(value string) bool {
	return len(value) >= 2 && ((value[0] >= 'a' && value[0] <= 'z') || (value[0] >= 'A' && value[0] <= 'Z')) && value[1] == ':'
}
