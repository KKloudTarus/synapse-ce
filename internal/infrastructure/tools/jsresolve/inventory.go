// Package jsresolve provides offline, deterministic JavaScript and TypeScript
// package-identity metadata processing. It never executes project tooling.
package jsresolve

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	defaultMaxEntries            = 100000
	defaultMaxMetadataFiles      = 10000
	defaultMaxMetadataFileBytes  = int64(2 << 20)
	defaultMaxTotalMetadataBytes = int64(64 << 20)
	defaultMaxPatternsPerSource  = 1024
	defaultMaxPatternsTotal      = 8192
	defaultMaxCoverageIssues     = 4096
	defaultMaxWorkspaceMatchWork = 1000000
	defaultMaxWorkspaceSegments  = 256
)

var (
	errWorkspaceRootEscape   = errors.New("workspace pattern escapes repository root")
	errWorkspaceAbsolutePath = errors.New("workspace pattern is absolute")
	errMetadataTooLarge      = errors.New("metadata file exceeds size limit")
	errMetadataTotalBudget   = errors.New("aggregate metadata byte budget exceeded")
	errMetadataChanged       = errors.New("metadata file changed during read")
)

type inventoryLimits struct {
	maxEntries            int
	maxMetadataFiles      int
	maxMetadataFileBytes  int64
	maxTotalMetadataBytes int64
	maxPatternsPerSource  int
	maxPatternsTotal      int
	maxCoverageIssues     int
	maxWorkspaceMatchWork int
	maxWorkspaceSegments  int
}

func defaultInventoryLimits() inventoryLimits {
	return inventoryLimits{
		maxEntries:            defaultMaxEntries,
		maxMetadataFiles:      defaultMaxMetadataFiles,
		maxMetadataFileBytes:  defaultMaxMetadataFileBytes,
		maxTotalMetadataBytes: defaultMaxTotalMetadataBytes,
		maxPatternsPerSource:  defaultMaxPatternsPerSource,
		maxPatternsTotal:      defaultMaxPatternsTotal,
		maxCoverageIssues:     defaultMaxCoverageIssues,
		maxWorkspaceMatchWork: defaultMaxWorkspaceMatchWork,
		maxWorkspaceSegments:  defaultMaxWorkspaceSegments,
	}
}

func (l inventoryLimits) validate() error {
	if l.maxEntries <= 0 || l.maxMetadataFiles <= 0 || l.maxMetadataFileBytes <= 0 ||
		l.maxTotalMetadataBytes <= 0 || l.maxPatternsPerSource <= 0 || l.maxPatternsTotal <= 0 ||
		l.maxCoverageIssues <= 0 || l.maxWorkspaceMatchWork <= 0 || l.maxWorkspaceSegments <= 0 {
		return fmt.Errorf("%w: inventory limits must be positive", shared.ErrValidation)
	}
	return nil
}

type metadataReader func(root *os.Root, rel string, walkInfo fs.FileInfo, maxFileBytes, remainingBytes int64) ([]byte, error)

// InventoryBuilder discovers package.json and workspace metadata beneath one
// repository root using bounded, source-only filesystem reads.
type InventoryBuilder struct {
	limits      inventoryLimits
	openAndRead metadataReader
}

// NewInventoryBuilder returns a bounded offline metadata inventory builder.
func NewInventoryBuilder() *InventoryBuilder {
	return &InventoryBuilder{limits: defaultInventoryLimits(), openAndRead: readBoundedMetadata}
}

func newInventoryBuilderWithLimits(limits inventoryLimits) *InventoryBuilder {
	return &InventoryBuilder{limits: limits, openAndRead: readBoundedMetadata}
}

type packageFile struct {
	file           string
	dir            string
	name           string
	version        string
	private        bool
	patterns       []string
	packageManager string
	dependencies   []jsresolution.DependencySpec
}

type workspaceNegationMode uint8

const (
	workspaceNegationExcludeAlways workspaceNegationMode = iota
	workspaceNegationOrdered
)

type workspaceSource struct {
	source       string
	baseDir      string
	patterns     []string
	negationMode workspaceNegationMode
	includeBase  bool
}

type coverageSink struct {
	inventory *jsresolution.Inventory
	limit     int
	capped    bool
}

func (s *coverageSink) add(issue jsresolution.CoverageIssue) {
	if s.capped {
		return
	}
	if len(s.inventory.Coverage) < s.limit-1 {
		s.inventory.Coverage = append(s.inventory.Coverage, issue)
		return
	}
	budgetIssue := jsresolution.CoverageIssue{
		Kind:   jsresolution.CoverageMetadataBudgetExceeded,
		Path:   ".",
		Detail: fmt.Sprintf("coverage issue budget exceeded (%d)", s.limit),
	}
	if len(s.inventory.Coverage) < s.limit {
		s.inventory.Coverage = append(s.inventory.Coverage, budgetIssue)
	} else {
		s.inventory.Coverage[s.limit-1] = budgetIssue
	}
	s.capped = true
}

func (s *coverageSink) addAll(issues []jsresolution.CoverageIssue) {
	for _, issue := range issues {
		s.add(issue)
		if s.capped {
			return
		}
	}
}

type workBudget struct {
	remaining int
	exceeded  bool
}

func (b *workBudget) consume() bool {
	if b.remaining <= 0 {
		b.exceeded = true
		return false
	}
	b.remaining--
	return true
}

// Build returns a deterministic inventory of package metadata and first-party
// workspaces. Malformed or unsupported metadata becomes explicit incomplete
// coverage whenever the remaining repository can still be inventoried safely.
func (b *InventoryBuilder) Build(ctx context.Context, root string) (jsresolution.Inventory, error) {
	if ctx == nil {
		return jsresolution.Inventory{}, fmt.Errorf("%w: context is required", shared.ErrValidation)
	}
	if b == nil {
		return jsresolution.Inventory{}, fmt.Errorf("%w: inventory builder is required", shared.ErrValidation)
	}
	if err := b.limits.validate(); err != nil {
		return jsresolution.Inventory{}, err
	}
	if strings.TrimSpace(root) == "" {
		return jsresolution.Inventory{}, fmt.Errorf("%w: repository root is required", shared.ErrValidation)
	}
	if err := ctx.Err(); err != nil {
		return jsresolution.Inventory{}, err
	}
	rootAbs, err := filepathAbsClean(root)
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
	rootDir, err := os.OpenRoot(rootAbs)
	if err != nil {
		return jsresolution.Inventory{}, fmt.Errorf("%w: open repository root: %v", shared.ErrValidation, err)
	}
	defer func() { _ = rootDir.Close() }()

	inventory := jsresolution.Inventory{}
	coverage := coverageSink{inventory: &inventory, limit: b.limits.maxCoverageIssues}
	packages := make(map[string]packageFile)
	var sources []workspaceSource
	patternsTotal := 0
	metadataBytes := int64(0)

	walkErr := fs.WalkDir(rootDir.FS(), ".", func(rel string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			if rel == "." {
				return fmt.Errorf("walk repository root: %w", walkErr)
			}
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnreadableMetadata, Path: rel, Detail: "filesystem entry could not be inspected"})
			return nil
		}
		inventory.EntriesScanned++
		if inventory.EntriesScanned > b.limits.maxEntries {
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: ".", Detail: fmt.Sprintf("filesystem entry budget exceeded (%d)", b.limits.maxEntries)})
			return fs.SkipAll
		}
		if entry.IsDir() {
			if rel != "." && skipMetadataDir(entry.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if skipMetadataDir(entry.Name()) {
				return nil
			}
			detail := "symlink entry was skipped because it may hide workspace metadata"
			if isMetadataFile(entry.Name()) {
				detail = "workspace metadata is symlinked and was not followed"
			}
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageSymlinkWorkspace, Path: rel, Detail: detail})
			return nil
		}
		if !isMetadataFile(entry.Name()) {
			return nil
		}
		if inventory.FilesScanned >= b.limits.maxMetadataFiles {
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: rel, Detail: fmt.Sprintf("metadata file budget exceeded (%d)", b.limits.maxMetadataFiles)})
			return fs.SkipAll
		}
		info, infoErr := entry.Info()
		if infoErr != nil || !info.Mode().IsRegular() {
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnreadableMetadata, Path: rel, Detail: "metadata entry is not a stable regular file"})
			return nil
		}
		remaining := b.limits.maxTotalMetadataBytes - metadataBytes
		if remaining <= 0 || info.Size() > remaining {
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: rel, Detail: fmt.Sprintf("aggregate metadata byte budget exceeded (%d)", b.limits.maxTotalMetadataBytes)})
			return fs.SkipAll
		}
		inventory.FilesScanned++
		content, readErr := b.openAndRead(rootDir, rel, info, b.limits.maxMetadataFileBytes, remaining)
		if readErr != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
			kind := jsresolution.CoverageUnreadableMetadata
			if errors.Is(readErr, errMetadataTooLarge) || errors.Is(readErr, errMetadataTotalBudget) {
				kind = jsresolution.CoverageMetadataBudgetExceeded
			}
			coverage.add(jsresolution.CoverageIssue{Kind: kind, Path: rel, Detail: readErr.Error()})
			if errors.Is(readErr, errMetadataTotalBudget) {
				return fs.SkipAll
			}
			return nil
		}
		metadataBytes += int64(len(content))

		if entry.Name() == "package.json" {
			pkg, parseErr := parsePackageJSON(rel, content)
			if parseErr != nil {
				coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMalformedMetadata, Path: rel, Detail: parseErr.Error()})
				if pkg.file == "" {
					return nil
				}
			}
			if pkg.name != "" {
				normalized, nameErr := jsresolution.NormalizePackageName(pkg.name)
				if nameErr != nil {
					coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMalformedMetadata, Path: pkg.file, Detail: nameErr.Error()})
					pkg.name = ""
				} else {
					pkg.name = normalized
				}
			}
			packages[pkg.dir] = pkg
			addWorkspaceSource(&sources, workspaceSource{
				source: pkg.file, baseDir: pkg.dir, patterns: pkg.patterns,
				negationMode: workspaceModeForPackageManager(pkg.packageManager),
			}, &patternsTotal, b.limits, &coverage)
			return nil
		}

		patterns, parseErr := parsePNPMWorkspace(content)
		if parseErr != nil {
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMalformedMetadata, Path: rel, Detail: parseErr.Error()})
			return nil
		}
		addWorkspaceSource(&sources, workspaceSource{
			source: rel, baseDir: path.Dir(rel), patterns: patterns,
			negationMode: workspaceNegationExcludeAlways, includeBase: true,
		}, &patternsTotal, b.limits, &coverage)
		return nil
	})
	if walkErr != nil {
		if err := ctx.Err(); err != nil {
			return jsresolution.Inventory{}, err
		}
		return jsresolution.Inventory{}, fmt.Errorf("inventory javascript metadata: %w", walkErr)
	}

	sort.Slice(sources, func(i, j int) bool { return sources[i].source < sources[j].source })
	packageDirs := make([]string, 0, len(packages))
	for dir := range packages {
		packageDirs = append(packageDirs, dir)
	}
	sort.Strings(packageDirs)

	workspaceDecls := make(map[string][]jsresolution.MetadataDeclaration)
	matchWork := workBudget{remaining: b.limits.maxWorkspaceMatchWork}
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return jsresolution.Inventory{}, err
		}
		if source.includeBase {
			if _, ok := packages[source.baseDir]; ok {
				workspaceDecls[source.baseDir] = append(workspaceDecls[source.baseDir], jsresolution.MetadataDeclaration{Source: source.source, Pattern: "."})
			}
		}
		compiled, issues := compileWorkspacePatterns(source, b.limits.maxWorkspaceSegments)
		coverage.addAll(issues)
		candidates := candidatePackageDirs(compiled, packageDirs, &matchWork)
		for _, dir := range candidates {
			decl, ok, selectErr := selectWorkspaceDeclaration(ctx, compiled, dir, &matchWork, source.negationMode)
			if selectErr != nil {
				if errors.Is(selectErr, context.Canceled) || errors.Is(selectErr, context.DeadlineExceeded) {
					return jsresolution.Inventory{}, selectErr
				}
				return jsresolution.Inventory{}, fmt.Errorf("match workspace declaration: %w", selectErr)
			}
			if matchWork.exceeded {
				break
			}
			if ok {
				workspaceDecls[dir] = append(workspaceDecls[dir], decl)
			}
		}
		if matchWork.exceeded {
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: source.source, Detail: fmt.Sprintf("workspace match work budget exceeded (%d)", b.limits.maxWorkspaceMatchWork)})
			break
		}
	}

	for _, dir := range packageDirs {
		pkg := packages[dir]
		decls := workspaceDecls[dir]
		isWorkspace := len(decls) > 0
		if isWorkspace && pkg.name == "" {
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMalformedMetadata, Path: pkg.file, Detail: "workspace package must declare a valid name"})
		}
		inventory.Packages = append(inventory.Packages, jsresolution.PackageMetadata{
			Name: pkg.name, Version: strings.TrimSpace(pkg.version), Path: dir, Private: pkg.private,
			Workspace: isWorkspace, DeclaredBy: decls, Dependencies: pkg.dependencies,
		})
	}

	addWorkspaceConflicts(&inventory, &coverage)
	return jsresolution.NormalizeInventory(inventory)
}

func filepathAbsClean(root string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", err
	}
	return abs, nil
}

func isMetadataFile(name string) bool {
	return name == "package.json" || name == "pnpm-workspace.yaml"
}

func workspaceModeForPackageManager(raw string) workspaceNegationMode {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "npm" || strings.HasPrefix(value, "npm@") {
		return workspaceNegationOrdered
	}
	return workspaceNegationExcludeAlways
}

func addWorkspaceSource(out *[]workspaceSource, source workspaceSource, total *int, limits inventoryLimits, coverage *coverageSink) {
	if len(source.patterns) == 0 {
		if source.includeBase {
			*out = append(*out, source)
		}
		return
	}
	var patterns []string
	if source.negationMode == workspaceNegationOrdered {
		// Ordered npm semantics can use a later repeated positive pattern to
		// re-include a path. Exact duplicate removal would change that meaning.
		patterns = append([]string(nil), source.patterns...)
	} else {
		patterns = deduplicateStringsStable(source.patterns)
	}
	if len(patterns) > limits.maxPatternsPerSource {
		coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: source.source, Detail: fmt.Sprintf("workspace pattern budget per source exceeded (%d)", limits.maxPatternsPerSource)})
		patterns = patterns[:limits.maxPatternsPerSource]
	}
	remaining := limits.maxPatternsTotal - *total
	if remaining <= 0 {
		coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: source.source, Detail: fmt.Sprintf("total workspace pattern budget exceeded (%d)", limits.maxPatternsTotal)})
		if source.includeBase {
			source.patterns = nil
			*out = append(*out, source)
		}
		return
	}
	if len(patterns) > remaining {
		coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: source.source, Detail: fmt.Sprintf("total workspace pattern budget exceeded (%d)", limits.maxPatternsTotal)})
		patterns = patterns[:remaining]
	}
	*total += len(patterns)
	source.patterns = append([]string(nil), patterns...)
	*out = append(*out, source)
}

func deduplicateStringsStable(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, value := range in {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

type compiledPattern struct {
	source  string
	pattern string
	match   string
	negated bool
}

func compileWorkspacePatterns(source workspaceSource, maxSegments int) ([]compiledPattern, []jsresolution.CoverageIssue) {
	out := make([]compiledPattern, 0, len(source.patterns))
	var issues []jsresolution.CoverageIssue
	for _, raw := range source.patterns {
		pattern, negated, err := normalizeWorkspacePattern(source.baseDir, raw, maxSegments)
		if err != nil {
			kind := jsresolution.CoverageUnsupportedMetadata
			if errors.Is(err, errWorkspaceRootEscape) || errors.Is(err, errWorkspaceAbsolutePath) {
				kind = jsresolution.CoverageWorkspaceRootEscape
			}
			issues = append(issues, jsresolution.CoverageIssue{Kind: kind, Path: source.source, Detail: err.Error()})
			continue
		}
		out = append(out, compiledPattern{source: source.source, pattern: raw, match: pattern, negated: negated})
	}
	if source.negationMode == workspaceNegationExcludeAlways {
		sort.Slice(out, func(i, j int) bool {
			if out[i].negated != out[j].negated {
				return !out[i].negated
			}
			if out[i].match != out[j].match {
				return out[i].match < out[j].match
			}
			return out[i].pattern < out[j].pattern
		})
	}
	return out, issues
}

func normalizeWorkspacePattern(baseDir, raw string, maxSegments int) (string, bool, error) {
	value := raw
	if value == "" {
		return "", false, fmt.Errorf("empty workspace pattern")
	}
	// Detect extglob before interpreting a leading ! as whole-pattern
	// negation. In particular, !(...) is extglob, not an exclusion wrapper.
	if usesUnsupportedExtglob(value) {
		return "", false, fmt.Errorf("workspace pattern %q uses unsupported extended glob syntax", raw)
	}
	negated := strings.HasPrefix(value, "!")
	if negated {
		value = strings.TrimPrefix(value, "!")
		if value == "" {
			return "", false, fmt.Errorf("empty negated workspace pattern")
		}
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, `\\`) || hasWindowsDrivePrefix(value) {
		return "", false, fmt.Errorf("%w: %q", errWorkspaceAbsolutePath, raw)
	}
	value = strings.ReplaceAll(value, "\\", "/")
	if strings.ContainsAny(value, "{}") {
		return "", false, fmt.Errorf("workspace pattern %q uses unsupported brace expansion", raw)
	}
	segments := collapseDoubleStarSegments(strings.Split(value, "/"))
	if len(segments) > maxSegments {
		return "", false, fmt.Errorf("workspace pattern %q exceeds segment budget (%d)", raw, maxSegments)
	}
	for _, segment := range segments {
		if segment == "**" {
			continue
		}
		if _, err := path.Match(segment, "probe"); err != nil {
			return "", false, fmt.Errorf("workspace pattern %q has invalid glob syntax", raw)
		}
	}
	value = strings.Join(segments, "/")
	base := baseDir
	if base == "." {
		base = ""
	}
	joined := path.Clean(path.Join(base, value))
	if joined == ".." || strings.HasPrefix(joined, "../") {
		return "", false, fmt.Errorf("%w: %q", errWorkspaceRootEscape, raw)
	}
	if joined == "." {
		return ".", negated, nil
	}
	return strings.TrimPrefix(joined, "./"), negated, nil
}

func usesUnsupportedExtglob(value string) bool {
	for _, marker := range []string{"@(", "+(", "?(", "*(", "!("} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func collapseDoubleStarSegments(in []string) []string {
	out := make([]string, 0, len(in))
	for _, segment := range in {
		if segment == "**" && len(out) > 0 && out[len(out)-1] == "**" {
			continue
		}
		out = append(out, segment)
	}
	return out
}

func hasWindowsDrivePrefix(value string) bool {
	return len(value) >= 2 && ((value[0] >= 'a' && value[0] <= 'z') || (value[0] >= 'A' && value[0] <= 'Z')) && value[1] == ':'
}

func candidatePackageDirs(patterns []compiledPattern, packageDirs []string, budget *workBudget) []string {
	prefixes := map[string]struct{}{}
	for _, pattern := range patterns {
		if pattern.negated {
			continue
		}
		prefixes[literalPatternPrefix(pattern.match)] = struct{}{}
	}
	if len(prefixes) == 0 {
		return nil
	}
	if _, all := prefixes[""]; all {
		out := make([]string, 0, minInt(len(packageDirs), budget.remaining))
		for _, dir := range packageDirs {
			if !budget.consume() {
				break
			}
			out = append(out, dir)
		}
		return out
	}
	prefixList := make([]string, 0, len(prefixes))
	for prefix := range prefixes {
		prefixList = append(prefixList, prefix)
	}
	sort.Strings(prefixList)
	seen := make(map[string]struct{})
	for _, prefix := range prefixList {
		start := sort.SearchStrings(packageDirs, prefix)
		for i := start; i < len(packageDirs); i++ {
			dir := packageDirs[i]
			if dir != prefix && !strings.HasPrefix(dir, prefix+"/") {
				break
			}
			if !budget.consume() {
				break
			}
			seen[dir] = struct{}{}
		}
		if budget.exceeded {
			break
		}
	}
	out := make([]string, 0, len(seen))
	for dir := range seen {
		out = append(out, dir)
	}
	sort.Strings(out)
	return out
}

func literalPatternPrefix(pattern string) string {
	segments := strings.Split(pattern, "/")
	literal := make([]string, 0, len(segments))
	for _, segment := range segments {
		if segment == "**" || strings.ContainsAny(segment, "*?[") {
			break
		}
		literal = append(literal, segment)
	}
	return strings.Join(literal, "/")
}

func selectWorkspaceDeclaration(ctx context.Context, patterns []compiledPattern, target string, budget *workBudget, mode workspaceNegationMode) (jsresolution.MetadataDeclaration, bool, error) {
	if mode == workspaceNegationOrdered {
		return selectOrderedWorkspaceDeclaration(ctx, patterns, target, budget)
	}
	return selectExcludeAlwaysWorkspaceDeclaration(ctx, patterns, target, budget)
}

func selectExcludeAlwaysWorkspaceDeclaration(ctx context.Context, patterns []compiledPattern, target string, budget *workBudget) (jsresolution.MetadataDeclaration, bool, error) {
	var selected *compiledPattern
	for i := range patterns {
		pattern := &patterns[i]
		if pattern.negated {
			break
		}
		if !budget.consume() {
			return jsresolution.MetadataDeclaration{}, false, nil
		}
		matched, err := matchWorkspacePattern(ctx, pattern.match, target)
		if err != nil {
			return jsresolution.MetadataDeclaration{}, false, err
		}
		if matched {
			selected = pattern
			break
		}
	}
	if selected == nil {
		return jsresolution.MetadataDeclaration{}, false, nil
	}
	for i := range patterns {
		pattern := &patterns[i]
		if !pattern.negated {
			continue
		}
		if !budget.consume() {
			return jsresolution.MetadataDeclaration{}, false, nil
		}
		matched, err := matchWorkspacePattern(ctx, pattern.match, target)
		if err != nil {
			return jsresolution.MetadataDeclaration{}, false, err
		}
		if matched {
			return jsresolution.MetadataDeclaration{}, false, nil
		}
	}
	return jsresolution.MetadataDeclaration{Source: selected.source, Pattern: selected.pattern}, true, nil
}

func selectOrderedWorkspaceDeclaration(ctx context.Context, patterns []compiledPattern, target string, budget *workBudget) (jsresolution.MetadataDeclaration, bool, error) {
	var selected *compiledPattern
	included := false
	for i := range patterns {
		pattern := &patterns[i]
		if !budget.consume() {
			return jsresolution.MetadataDeclaration{}, false, nil
		}
		matched, err := matchWorkspacePattern(ctx, pattern.match, target)
		if err != nil {
			return jsresolution.MetadataDeclaration{}, false, err
		}
		if !matched {
			continue
		}
		if pattern.negated {
			included = false
			selected = nil
			continue
		}
		included = true
		selected = pattern
	}
	if !included || selected == nil {
		return jsresolution.MetadataDeclaration{}, false, nil
	}
	return jsresolution.MetadataDeclaration{Source: selected.source, Pattern: selected.pattern}, true, nil
}

func matchWorkspacePattern(ctx context.Context, pattern, target string) (bool, error) {
	pattern = strings.Trim(pattern, "/")
	target = strings.Trim(target, "/")
	if pattern == "" || pattern == "." {
		return target == "" || target == ".", ctx.Err()
	}
	if target == "." {
		target = ""
	}
	patternSegments := strings.Split(pattern, "/")
	targetSegments := splitPathSegments(target)
	type state struct{ pi, ti int }
	type memoValue struct {
		matched bool
		err     error
	}
	memo := make(map[state]memoValue, (len(patternSegments)+1)*(len(targetSegments)+1))
	var visit func(int, int) (bool, error)
	visit = func(pi, ti int) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		key := state{pi: pi, ti: ti}
		if value, ok := memo[key]; ok {
			return value.matched, value.err
		}
		var matched bool
		var err error
		switch {
		case pi == len(patternSegments):
			matched = ti == len(targetSegments)
		case patternSegments[pi] == "**":
			matched, err = visit(pi+1, ti)
			if err == nil && !matched && ti < len(targetSegments) {
				matched, err = visit(pi, ti+1)
			}
		case ti == len(targetSegments):
			matched = false
		default:
			var segmentMatched bool
			segmentMatched, err = path.Match(patternSegments[pi], targetSegments[ti])
			if err == nil && segmentMatched {
				matched, err = visit(pi+1, ti+1)
			}
		}
		memo[key] = memoValue{matched: matched, err: err}
		return matched, err
	}
	return visit(0, 0)
}

func splitPathSegments(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, "/")
}

func parsePackageJSON(rel string, content []byte) (packageFile, error) {
	var raw struct {
		Name           string            `json:"name"`
		Version        string            `json:"version"`
		Private        bool              `json:"private"`
		Workspaces     json.RawMessage   `json:"workspaces"`
		PackageManager string            `json:"packageManager"`
		Dependencies   map[string]string `json:"dependencies"`
		DevDeps        map[string]string `json:"devDependencies"`
		OptionalDeps   map[string]string `json:"optionalDependencies"`
		PeerDeps       map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(content, &raw); err != nil {
		return packageFile{}, fmt.Errorf("parse package.json: %w", err)
	}
	patterns, workspaceErr := parseJSONWorkspaces(raw.Workspaces)
	dir := path.Dir(rel)
	// Dependency SPECS decide package identity, not just presence: npm lets a dependency be aliased
	// ("lodash": "npm:lodash-es@^4") or fetched from outside the registry, in which case the imported
	// name is not the package name.
	var deps []jsresolution.DependencySpec
	for _, group := range []map[string]string{raw.Dependencies, raw.DevDeps, raw.OptionalDeps, raw.PeerDeps} {
		for name, spec := range group {
			deps = append(deps, jsresolution.DependencySpec{Name: name, Spec: spec})
		}
	}
	pkg := packageFile{
		file: rel, dir: dir, name: raw.Name, version: raw.Version, private: raw.Private,
		patterns: patterns, packageManager: raw.PackageManager, dependencies: deps,
	}
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
	listIndent := -1
	var patterns []string
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " \t\r")
		withoutComment := stripYAMLComment(line)
		plain := strings.TrimSpace(withoutComment)
		if plain == "" {
			continue
		}
		indent, tabIndent := yamlIndent(withoutComment)
		if tabIndent {
			return nil, fmt.Errorf("pnpm-workspace.yaml uses tab indentation")
		}
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

		if listIndent < 0 {
			if indent < baseIndent {
				break
			}
			if strings.HasPrefix(plain, "-") && indent >= baseIndent {
				listIndent = indent
			} else if indent == baseIndent {
				break
			} else {
				return nil, fmt.Errorf("pnpm-workspace.yaml packages must be a scalar list")
			}
		} else {
			if indent < listIndent {
				break
			}
			if indent != listIndent || !strings.HasPrefix(plain, "-") {
				return nil, fmt.Errorf("pnpm-workspace.yaml packages must be a scalar list")
			}
		}

		item := strings.TrimSpace(strings.TrimPrefix(plain, "-"))
		if item == "" {
			return nil, fmt.Errorf("pnpm-workspace.yaml contains an empty package pattern")
		}
		if hasUnsupportedYAMLScalarSyntax(item) {
			return nil, fmt.Errorf("pnpm-workspace.yaml package pattern uses unsupported YAML scalar syntax")
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
		return nil, nil
	}
	if len(patterns) == 0 {
		return nil, fmt.Errorf("pnpm-workspace.yaml packages list is empty or unsupported")
	}
	return patterns, nil
}

func hasUnsupportedYAMLScalarSyntax(item string) bool {
	if item == "" || strings.HasPrefix(item, "'") || strings.HasPrefix(item, "\"") {
		return false
	}
	switch item[0] {
	case '&', '*', '!', '|', '>', '{', '[':
		return true
	default:
		return false
	}
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

func yamlIndent(line string) (int, bool) {
	count := 0
	for _, r := range line {
		switch r {
		case ' ':
			count++
		case '\t':
			return count, true
		default:
			return count, false
		}
	}
	return count, false
}

func readBoundedMetadata(root *os.Root, rel string, walkInfo fs.FileInfo, maxFileBytes, remainingBytes int64) ([]byte, error) {
	if !walkInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q is not a regular file", errMetadataChanged, rel)
	}
	if walkInfo.Size() > maxFileBytes {
		return nil, fmt.Errorf("%w: %q is %d bytes > %d", errMetadataTooLarge, rel, walkInfo.Size(), maxFileBytes)
	}
	if walkInfo.Size() > remainingBytes {
		return nil, fmt.Errorf("%w: %q requires %d bytes with %d remaining", errMetadataTotalBudget, rel, walkInfo.Size(), remainingBytes)
	}
	f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open metadata %q: %w", rel, err)
	}
	defer func() { _ = f.Close() }()
	openedInfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened metadata %q: %w", rel, err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(walkInfo, openedInfo) {
		return nil, fmt.Errorf("%w: %q identity changed before read", errMetadataChanged, rel)
	}
	if openedInfo.Size() > maxFileBytes {
		return nil, fmt.Errorf("%w: %q is %d bytes > %d", errMetadataTooLarge, rel, openedInfo.Size(), maxFileBytes)
	}
	if openedInfo.Size() > remainingBytes {
		return nil, fmt.Errorf("%w: %q requires %d bytes with %d remaining", errMetadataTotalBudget, rel, openedInfo.Size(), remainingBytes)
	}
	limit := minInt64(maxFileBytes, remainingBytes)
	content, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read metadata %q: %w", rel, err)
	}
	if int64(len(content)) > maxFileBytes {
		return nil, fmt.Errorf("%w: %q read exceeded %d bytes", errMetadataTooLarge, rel, maxFileBytes)
	}
	if int64(len(content)) > remainingBytes {
		return nil, fmt.Errorf("%w: %q read exceeded remaining %d bytes", errMetadataTotalBudget, rel, remainingBytes)
	}
	after, err := f.Stat()
	if err != nil || !stableMetadataSnapshot(openedInfo, after, int64(len(content))) {
		return nil, fmt.Errorf("%w: %q changed during read", errMetadataChanged, rel)
	}
	return content, nil
}

func stableMetadataSnapshot(before, after fs.FileInfo, bytesRead int64) bool {
	return before.Mode().IsRegular() && after.Mode().IsRegular() && os.SameFile(before, after) &&
		before.Size() == after.Size() && before.ModTime().Equal(after.ModTime()) && after.Size() == bytesRead
}

func addWorkspaceConflicts(inventory *jsresolution.Inventory, coverage *coverageSink) {
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
		coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageWorkspaceNameConflict, Detail: fmt.Sprintf("workspace package %q is declared at multiple roots: %s", name, strings.Join(paths, ", "))})
	}
}

func skipMetadataDir(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", "node_modules":
		return true
	default:
		return false
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
