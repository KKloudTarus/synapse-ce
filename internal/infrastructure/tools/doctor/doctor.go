// Package doctor provides an offline, read-only preflight report for synapse-cli.
package doctor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ast"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownsbom"
)

const (
	defaultMaxFiles   = 20000
	defaultMaxEntries = 100000
	defaultMaxDepth   = 64
	versionTimeout    = 2 * time.Second
)

// Status is a readiness value for one scan dimension.
type Status string

const (
	StatusFull        Status = "full"
	StatusPartial     Status = "partial"
	StatusUnavailable Status = "unavailable"
)

// Report is the structured doctor output.
type Report struct {
	Target     string               `json:"target"`
	Tools      []ToolProbe          `json:"tools"`
	Inventory  Inventory            `json:"inventory"`
	Dimensions []DimensionReadiness `json:"dimensions"`
}

// ToolProbe describes one optional toolchain dependency.
type ToolProbe struct {
	Name    string `json:"name"`
	Command string `json:"command,omitempty"`
	Found   bool   `json:"found"`
	Path    string `json:"path,omitempty"`
	Version string `json:"version,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Inventory is the bounded target-tree inventory used to explain readiness.
type Inventory struct {
	Markers   []MarkerHit `json:"markers"`
	Languages []Language  `json:"languages"`
	Truncated bool        `json:"truncated"`
}

// MarkerHit is a recognized dependency marker in the target tree.
type MarkerHit struct {
	Path      string `json:"path"`
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Kind      string `json:"kind"`
}

// Language is a lightweight source-language count.
type Language struct {
	Name  string `json:"name"`
	Files int    `json:"files"`
}

// DimensionReadiness explains whether a scan dimension has enough local setup.
type DimensionReadiness struct {
	Dimension string `json:"dimension"`
	Status    Status `json:"status"`
	Reason    string `json:"reason"`
	NextStep  string `json:"next_step,omitempty"`
}

// Options allows tests to inject tool and sidecar discovery.
type Options struct {
	LookPath     func(string) (string, error)
	Version      func(context.Context, string, ...string) (string, error)
	SidecarPath  string
	JavaHomePath string
	MaxFiles     int
	MaxEntries   int
	MaxDepth     int
}

// Probe builds an offline report for target. It never scans, installs tools, or uses the network.
func Probe(ctx context.Context, target string, opts Options) (Report, error) {
	if strings.TrimSpace(target) == "" {
		target = "."
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return Report{}, fmt.Errorf("doctor target: %w", err)
	}
	if fi, err := os.Stat(abs); err != nil {
		return Report{}, fmt.Errorf("doctor target: %w", err)
	} else if !fi.IsDir() {
		return Report{}, fmt.Errorf("doctor target must be a directory: %s", abs)
	}
	normalizeOptions(&opts)
	tools := probeTools(ctx, opts)
	inv, err := inventory(ctx, abs, opts)
	if err != nil {
		return Report{}, err
	}
	return Report{
		Target:     abs,
		Tools:      tools,
		Inventory:  inv,
		Dimensions: readiness(inv, tools),
	}, nil
}

func normalizeOptions(opts *Options) {
	if opts.LookPath == nil {
		opts.LookPath = exec.LookPath
	}
	if opts.Version == nil {
		opts.Version = commandVersion
	}
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = defaultMaxFiles
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = defaultMaxEntries
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = defaultMaxDepth
	}
	if opts.JavaHomePath == "" {
		opts.JavaHomePath = "/usr/libexec/java_home"
	}
}

type toolSpec struct {
	name    string
	command string
	args    []string
}

func probeTools(ctx context.Context, opts Options) []ToolProbe {
	specs := []toolSpec{
		{name: "npm", command: "npm", args: []string{"--version"}},
		{name: "composer", command: "composer", args: []string{"--version"}},
		{name: "bundle", command: "bundle", args: []string{"--version"}},
		{name: "poetry", command: "poetry", args: []string{"--version"}},
		{name: "mvn", command: "mvn", args: []string{"--version"}},
		{name: "gradle", command: "gradle", args: []string{"--version"}},
		{name: "java", command: "java", args: []string{"-version"}},
		{name: "javac", command: "javac", args: []string{"-version"}},
	}
	out := make([]ToolProbe, 0, len(specs)+2)
	for _, spec := range specs {
		out = append(out, probeCommand(ctx, opts, spec))
	}
	out = append(out, probeJDK(ctx, opts, out))
	out = append(out, probeSidecar(opts))
	return out
}

func probeCommand(ctx context.Context, opts Options, spec toolSpec) ToolProbe {
	p := ToolProbe{Name: spec.name, Command: spec.command}
	path, err := opts.LookPath(spec.command)
	if err != nil {
		p.Detail = "not found on PATH"
		return p
	}
	p.Found = true
	p.Path = path
	if len(spec.args) > 0 {
		if v, err := opts.Version(ctx, path, spec.args...); err == nil {
			p.Version = firstLine(v)
		}
	}
	return p
}

func probeJDK(ctx context.Context, opts Options, tools []ToolProbe) ToolProbe {
	p := ToolProbe{Name: "jdk", Command: "java/javac"}
	if javac := toolByName(tools, "javac"); javac.Found {
		p.Found = true
		p.Path = javac.Path
		p.Version = javac.Version
		p.Detail = "javac found on PATH"
		return p
	}
	if java := toolByName(tools, "java"); java.Found {
		p.Found = true
		p.Path = java.Path
		p.Version = java.Version
		p.Detail = "java found on PATH"
		return p
	}
	javaHome := opts.JavaHomePath
	if fi, err := os.Stat(javaHome); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
		if v, err := opts.Version(ctx, javaHome); err == nil && strings.TrimSpace(v) != "" {
			p.Found = true
			p.Path = strings.TrimSpace(v)
			p.Detail = "resolved by /usr/libexec/java_home"
			return p
		}
	}
	p.Detail = "no java, javac, or /usr/libexec/java_home result found"
	return p
}

func probeSidecar(opts Options) ToolProbe {
	candidate := strings.TrimSpace(opts.SidecarPath)
	if candidate == "" {
		candidate = strings.TrimSpace(os.Getenv("SYNAPSE_AST_BIN"))
	}
	if candidate == "" {
		candidate = ast.ResolveSidecar()
	}
	p := ToolProbe{Name: "synapse-ast", Command: candidate}
	if candidate == "" {
		p.Detail = "no sidecar candidate"
		return p
	}
	if strings.ContainsRune(candidate, os.PathSeparator) {
		if fi, err := os.Stat(candidate); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			p.Found = true
			p.Path = candidate
			return p
		}
		p.Detail = "sidecar candidate is not executable"
		return p
	}
	path, err := opts.LookPath(candidate)
	if err != nil {
		p.Detail = "not found on PATH or next to synapse-cli"
		return p
	}
	p.Found = true
	p.Path = path
	return p
}

func commandVersion(ctx context.Context, path string, args ...string) (string, error) {
	vctx, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()
	cmd := exec.CommandContext(vctx, path, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out.String(), nil
}

func firstLine(s string) string {
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func inventory(ctx context.Context, root string, opts Options) (Inventory, error) {
	reg, err := ownsbom.DefaultRegistry()
	if err != nil {
		return Inventory{}, fmt.Errorf("doctor marker registry: %w", err)
	}
	markers := reg.MarkerEcosystems()
	for name, eco := range supplementalMarkers() {
		markers[strings.ToLower(name)] = eco
	}
	hits := make([]MarkerHit, 0)
	seenHits := map[string]bool{}
	langs := map[string]int{}
	files := 0
	entries := 0
	truncated := false
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		entries++
		if entries > opts.MaxEntries {
			truncated = true
			return filepath.SkipAll
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		if path != root && depth(rel) > opts.MaxDepth {
			truncated = true
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		files++
		if files > opts.MaxFiles {
			truncated = true
			return filepath.SkipAll
		}
		name := d.Name()
		lower := strings.ToLower(name)
		if ecosystem, ok := markers[lower]; ok {
			key := rel + "\x00" + lower
			if !seenHits[key] {
				seenHits[key] = true
				hits = append(hits, MarkerHit{
					Path:      filepath.ToSlash(rel),
					Name:      name,
					Ecosystem: ecosystem,
					Kind:      markerKind(lower),
				})
			}
		}
		if lang := languageFor(name); lang != "" {
			langs[lang]++
		}
		return nil
	})
	if err != nil && !errors.Is(err, filepath.SkipAll) {
		return Inventory{}, fmt.Errorf("doctor inventory: %w", err)
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Path == hits[j].Path {
			return hits[i].Name < hits[j].Name
		}
		return hits[i].Path < hits[j].Path
	})
	languages := make([]Language, 0, len(langs))
	for name, count := range langs {
		languages = append(languages, Language{Name: name, Files: count})
	}
	sort.Slice(languages, func(i, j int) bool { return languages[i].Name < languages[j].Name })
	return Inventory{Markers: hits, Languages: languages, Truncated: truncated}, nil
}

func depth(rel string) int {
	rel = filepath.Clean(rel)
	if rel == "." || rel == string(filepath.Separator) {
		return 0
	}
	return strings.Count(rel, string(filepath.Separator)) + 1
}

func supplementalMarkers() map[string]string {
	// These are manifest or companion marker names that indicate readiness gaps but are not direct
	// ownsbom parser dispatch keys. Keep their lockfile counterparts covered by DefaultRegistry.
	return map[string]string{
		"package.json":        "npm",
		"npm-shrinkwrap.json": "npm",
		"composer.json":       "composer",
		"gemfile":             "gem",
		"pyproject.toml":      "poetry",
		"go.sum":              "go",
		"settings.gradle":     "maven",
		"settings.gradle.kts": "maven",
	}
}

func markerKind(name string) string {
	switch name {
	case "package.json", "composer.json", "gemfile", "pyproject.toml", "go.mod", "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "requirements.txt", "requirements-dev.txt", "environment.yml", "environment.yaml", "conanfile.txt":
		return "manifest"
	}
	if strings.Contains(name, "lock") || strings.HasSuffix(name, ".lock") || name == "package.resolved" || name == "manifest.toml" || name == "libs.versions.toml" || name == "go.sum" {
		return "lockfile"
	}
	return "manifest"
}

func skipDir(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", ".idea", ".vscode", ".gradle", "__pycache__", "node_modules", "vendor", "dist", "build", "target", "coverage", ".next":
		return true
	}
	return false
}

func languageFor(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".go":
		return "Go"
	case ".js", ".jsx", ".mjs", ".cjs":
		return "JavaScript"
	case ".ts", ".tsx":
		return "TypeScript"
	case ".py":
		return "Python"
	case ".java", ".kt", ".kts":
		return "JVM"
	case ".rb":
		return "Ruby"
	case ".php":
		return "PHP"
	case ".rs":
		return "Rust"
	case ".cs":
		return ".NET"
	case ".swift":
		return "Swift"
	case ".dart":
		return "Dart"
	case ".ex", ".exs":
		return "Elixir"
	case ".tf":
		return "Terraform"
	case ".yaml", ".yml", ".json", ".toml", ".xml":
		return "Config"
	}
	return ""
}

func readiness(inv Inventory, tools []ToolProbe) []DimensionReadiness {
	return []DimensionReadiness{
		scaReadiness(inv, tools),
		{Dimension: "sast", Status: StatusFull, Reason: "pure-Go source analysis does not require external setup"},
		{Dimension: "secret", Status: StatusFull, Reason: "secret scanning runs in-process without external setup"},
		{Dimension: "misconfig", Status: StatusFull, Reason: "misconfiguration checks run in-process without external setup"},
		codeQualityReadiness(tools),
	}
}

func scaReadiness(inv Inventory, tools []ToolProbe) DimensionReadiness {
	if len(inv.Markers) == 0 {
		return DimensionReadiness{
			Dimension: "sca",
			Status:    StatusUnavailable,
			Reason:    "no supported dependency manifests or lockfiles were found",
			NextStep:  "Add or point doctor at a tree with a supported package manifest or lockfile.",
		}
	}
	if gap := firstSCAGap(inv, tools); gap != nil {
		return *gap
	}
	return DimensionReadiness{
		Dimension: "sca",
		Status:    StatusFull,
		Reason:    "committed lockfiles or directly parsed dependency markers were found",
	}
}

func firstSCAGap(inv Inventory, tools []ToolProbe) *DimensionReadiness {
	has := markerSet(inv.Markers)
	if has["package.json"] && !(has["package-lock.json"] || has["npm-shrinkwrap.json"] || has["yarn.lock"] || has["pnpm-lock.yaml"]) {
		if foundTool(tools, "npm") {
			return &DimensionReadiness{Dimension: "sca", Status: StatusPartial, Reason: "package.json found without a committed npm/yarn/pnpm lockfile; npm is available for transitive resolution", NextStep: "Commit a lockfile for deterministic full coverage."}
		}
		return &DimensionReadiness{Dimension: "sca", Status: StatusPartial, Reason: "package.json found without a committed npm/yarn/pnpm lockfile and npm is not on PATH", NextStep: "Install npm or commit package-lock.json, yarn.lock, or pnpm-lock.yaml."}
	}
	if has["composer.json"] && !has["composer.lock"] {
		return toolGap(tools, "composer", "composer.json found without composer.lock", "Install composer or commit composer.lock.")
	}
	if has["gemfile"] && !has["gemfile.lock"] {
		return toolGap(tools, "bundle", "Gemfile found without Gemfile.lock", "Install bundler or commit Gemfile.lock.")
	}
	if has["pyproject.toml"] && !hasAny(has, pythonLockMarkers()...) {
		return toolGap(tools, "poetry", "pyproject.toml found without a recognized Python lockfile or requirements file", "Install poetry or commit poetry.lock, uv.lock, Pipfile.lock, or requirements.txt.")
	}
	if has["pom.xml"] {
		if !foundTool(tools, "jdk") {
			return &DimensionReadiness{Dimension: "sca", Status: StatusPartial, Reason: "pom.xml found but no JDK was detected for Maven resolution", NextStep: "Install a JDK or rely on committed/resolved dependency data where available."}
		}
		if !foundTool(tools, "mvn") {
			return &DimensionReadiness{Dimension: "sca", Status: StatusPartial, Reason: "pom.xml found but mvn is not on PATH", NextStep: "Install Maven for transitive dependency resolution."}
		}
	}
	if has["build.gradle"] || has["build.gradle.kts"] || has["settings.gradle"] || has["settings.gradle.kts"] {
		if !foundTool(tools, "jdk") {
			return &DimensionReadiness{Dimension: "sca", Status: StatusPartial, Reason: "Gradle build marker found but no JDK was detected", NextStep: "Install a JDK; Gradle dependency resolution needs one."}
		}
		if !foundTool(tools, "gradle") {
			return &DimensionReadiness{Dimension: "sca", Status: StatusPartial, Reason: "Gradle build marker found but gradle is not on PATH", NextStep: "Install a pinned gradle binary for transitive dependency resolution."}
		}
	}
	return nil
}

func hasAny(markers map[string]bool, names ...string) bool {
	for _, name := range names {
		if markers[strings.ToLower(name)] {
			return true
		}
	}
	return false
}

func pythonLockMarkers() []string {
	return []string{
		"poetry.lock",
		"uv.lock",
		"Pipfile.lock",
		"requirements.txt",
		"requirements-dev.txt",
	}
}

func toolGap(tools []ToolProbe, tool, reason, missingStep string) *DimensionReadiness {
	if foundTool(tools, tool) {
		return &DimensionReadiness{Dimension: "sca", Status: StatusPartial, Reason: reason + "; resolver tool is available", NextStep: "Commit the generated lockfile for deterministic full coverage."}
	}
	return &DimensionReadiness{Dimension: "sca", Status: StatusPartial, Reason: reason + " and " + tool + " is not on PATH", NextStep: missingStep}
}

func codeQualityReadiness(tools []ToolProbe) DimensionReadiness {
	if foundTool(tools, "synapse-ast") {
		return DimensionReadiness{
			Dimension: "code-quality",
			Status:    StatusFull,
			Reason:    "synapse-ast sidecar was found for complexity and deeper bug detection",
		}
	}
	return DimensionReadiness{
		Dimension: "code-quality",
		Status:    StatusPartial,
		Reason:    "synapse-ast sidecar was not found; complexity and deeper bug detection will be limited",
		NextStep:  "Ship synapse-ast next to synapse-cli or set SYNAPSE_AST_BIN.",
	}
}

func markerSet(markers []MarkerHit) map[string]bool {
	out := map[string]bool{}
	for _, m := range markers {
		out[strings.ToLower(m.Name)] = true
	}
	return out
}

func foundTool(tools []ToolProbe, name string) bool {
	return toolByName(tools, name).Found
}

func toolByName(tools []ToolProbe, name string) ToolProbe {
	for _, t := range tools {
		if t.Name == name {
			return t
		}
	}
	return ToolProbe{Name: name}
}
