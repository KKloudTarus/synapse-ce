package jvmreach

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/symbolcanon"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
)

// Tier2Analyzer builds a method-level JVM call graph from compiled bytecode. CHA is the default
// dispatch strategy. Points-to narrowing is deliberately opt-in: when enabled it applies a bounded,
// intraprocedural Andersen-style inclusion analysis to straight-line receiver locals, and falls back to
// CHA whenever the receiver may contain an unknown value. Both modes are RAISE-ONLY consumers: this
// analyzer returns only positively reached affected methods and never a negative result.
const tier2SubjectSeparator = "\x1f"

const (
	maxTier2Classes            = 20_000
	maxTier2ArchiveEntries     = 50_000
	maxTier2NestedArchiveDepth = 1
	maxTier2Edges              = 500_000
	tier2AnalysisTimeout       = 15 * time.Second
)

type Tier2Analyzer struct {
	pointsTo bool
}

// NewTier2 returns the owned JVM Tier-2 analyzer. pointsTo=false is the recall-first CHA default.
func NewTier2(pointsTo bool) *Tier2Analyzer { return &Tier2Analyzer{pointsTo: pointsTo} }

type methodGraph struct {
	classes       map[string]*classModel
	edges         map[string][]string
	entrypoints   []string
	coordByMethod map[string]string
	blind         map[string]bool
	classesSeen   int
	methodsBudget int
}

func newMethodGraph() *methodGraph {
	return &methodGraph{
		classes:       map[string]*classModel{},
		edges:         map[string][]string{},
		coordByMethod: map[string]string{},
		blind:         map[string]bool{},
		methodsBudget: maxTier2MethodsTotal,
	}
}

// Analyze implements the reachproof analyzer contract. targetRef must contain compiled classes or jars;
// a source-only/not-built project returns a successful no-result analysis (the raise-only coordinator mints
// nothing). Only methods from archives carrying Maven pom.properties are eligible affected-symbol targets;
// unattributed Gradle/plain jars may contribute intermediate graph edges but can never raise a finding.
func (a *Tier2Analyzer) Analyze(ctx context.Context, targetRef string, subjects []string) (*reachability.Analysis, error) {
	if ctx == nil {
		return nil, fmt.Errorf("jvm tier-2: context is required")
	}
	if strings.TrimSpace(targetRef) == "" {
		return nil, fmt.Errorf("jvm tier-2: target directory is required")
	}
	// Tier-2 parses and graphs untrusted bytecode in-process. The deadline covers both phases,
	// including CHA dispatch construction, and a timeout fails closed to no JVM coverage.
	ctx, cancel := context.WithTimeout(ctx, tier2AnalysisTimeout)
	defer cancel()
	g := newMethodGraph()
	if err := scanTier2Workspace(ctx, targetRef, g, a.pointsTo); err != nil {
		return nil, err
	}
	if len(g.entrypoints) == 0 {
		return &reachability.Analysis{}, nil
	}
	if err := g.buildEdges(ctx, a.pointsTo); err != nil {
		return nil, err
	}
	reached, prev, err := reachableMethods(ctx, g.edges, g.entrypoints)
	if err != nil {
		return nil, err
	}
	results := make([]reachability.Result, 0, len(subjects))
	seen := map[string]bool{}
	for subjectIdx, raw := range subjects {
		if subjectIdx&0x3ff == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if strings.TrimSpace(raw) == "" || seen[raw] {
			continue
		}
		seen[raw] = true
		purl, symbol, ok := splitTier2Subject(raw)
		if !ok {
			continue
		}
		expectedCoord := coordKeyOf(sbom.Component{PURL: purl})
		if expectedCoord == "" {
			continue
		}
		want := canonicalJVMSymbol(symbol)
		if len(want.Segments) < 2 {
			continue
		}
		best := ""
		bestLen := int(^uint(0) >> 1)
		methodIdx := 0
		for method, coord := range g.coordByMethod {
			if methodIdx&0x3ff == 0 {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
			methodIdx++
			if coord != expectedCoord || !reached[method] {
				continue
			}
			if !symbolcanon.TailMatch(want, canonicalMethodKey(method), 2) {
				continue
			}
			path := methodPath(prev, method)
			if len(path) > 0 && len(path) < bestLen {
				best, bestLen = method, len(path)
			}
		}
		if best == "" {
			continue
		}
		path := methodPath(prev, best)
		if coord := g.coordByMethod[best]; coord != "" && len(path) > 0 {
			path[len(path)-1] = path[len(path)-1] + " [maven " + coord + "]"
		}
		results = append(results, reachability.Result{Symbol: raw, Reachable: true, Path: path})
	}
	entries := append([]string(nil), g.entrypoints...)
	sort.Strings(entries)
	return &reachability.Analysis{Results: results, Entrypoints: entries}, nil
}

func splitTier2Subject(raw string) (purl, symbol string, ok bool) {
	parts := strings.SplitN(raw, tier2SubjectSeparator, 2)
	if len(parts) != 2 {
		return "", "", false
	}
	purl = strings.TrimSpace(parts[0])
	symbol = strings.TrimSpace(parts[1])
	if !strings.HasPrefix(purl, "pkg:maven/") || symbol == "" {
		return "", "", false
	}
	return purl, symbol, true
}

func canonicalJVMSymbol(raw string) symbolcanon.Symbol {
	raw = strings.TrimSpace(raw)
	if i := strings.IndexByte(raw, '('); i >= 0 {
		raw = raw[:i]
	}
	raw = strings.ReplaceAll(raw, "$", ".")
	return symbolcanon.Canonicalize(symbolcanon.Generic, raw)
}

func canonicalMethodKey(key string) symbolcanon.Symbol {
	owner, name, _, ok := splitMethodKey(key)
	if !ok {
		return symbolcanon.Symbol{}
	}
	return canonicalJVMSymbol(strings.ReplaceAll(owner, "/", ".") + "." + name)
}

func scanTier2Workspace(ctx context.Context, root string, g *methodGraph, pointsTo bool) error {
	info, err := fs.Stat(osDirFS(root), ".")
	if err != nil || !info.IsDir() {
		if err == nil {
			err = fmt.Errorf("not a directory")
		}
		return fmt.Errorf("jvm tier-2 scan %q: %w", root, err)
	}
	archives := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		lower := strings.ToLower(d.Name())
		switch {
		case strings.HasSuffix(lower, ".class") && isAppClassPath(path):
			return addTier2Class(ctx, g, readFile(path), "", true, pointsTo)
		case isArchive(lower):
			if archives >= maxArchives {
				return filepath.SkipAll
			}
			archives++
			return ingestTier2Archive(ctx, path, g, pointsTo)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("jvm tier-2 walk %q: %w", root, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func osDirFS(root string) fs.FS { return os.DirFS(root) }

func ingestTier2Archive(ctx context.Context, path string, g *methodGraph, pointsTo bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil
	}
	defer func() { _ = zr.Close() }()
	return ingestTier2Zip(ctx, &zr.Reader, g, maxTier2NestedArchiveDepth, pointsTo)
}

func ingestTier2Zip(ctx context.Context, zr *zip.Reader, g *methodGraph, depth int, pointsTo bool) error {
	coord := coordOfArchive(zr)
	for i, f := range zr.File {
		if i >= maxTier2ArchiveEntries || g.classesSeen >= maxTier2Classes {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		name := f.Name
		switch {
		case strings.HasSuffix(name, ".class"):
			app := strings.HasPrefix(name, "BOOT-INF/classes/") || strings.HasPrefix(name, "WEB-INF/classes/")
			classCoord := coord
			if app {
				classCoord = ""
			}
			if err := addTier2Class(ctx, g, readZipEntry(f, maxClassBytes), classCoord, app, pointsTo); err != nil {
				return err
			}
		case depth > 0 && isArchive(strings.ToLower(name)) &&
			(strings.HasPrefix(name, "BOOT-INF/lib/") || strings.HasPrefix(name, "WEB-INF/lib/")):
			if data := readZipEntry(f, maxNestedJARSize); len(data) > 0 {
				if nested, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err == nil {
					if err := ingestTier2Zip(ctx, nested, g, depth-1, pointsTo); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func addTier2Class(ctx context.Context, g *methodGraph, data []byte, coord string, app, pointsTo bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(data) == 0 || g.classesSeen >= maxTier2Classes || g.methodsBudget == 0 {
		return nil
	}
	g.classesSeen++
	m, err := parseTier2Class(ctx, data, coord, app, pointsTo, &g.methodsBudget)
	if err != nil || m == nil || m.name == "" {
		if err := ctx.Err(); err != nil {
			return err
		}
		return nil
	}
	if _, exists := g.classes[m.name]; exists {
		return nil
	}
	g.classes[m.name] = m
	for _, method := range m.methods {
		key := fullMethodKey(method.owner, method.name, method.desc)
		if app {
			g.entrypoints = append(g.entrypoints, key)
		}
		if coord != "" {
			g.coordByMethod[key] = coord
		}
		if method.access&accNative != 0 {
			g.blind["jni"] = true
		}
		for _, call := range method.calls {
			markBlindCall(g.blind, call)
		}
	}
	return nil
}

func markBlindCall(blind map[string]bool, c callSite) {
	owner := c.owner
	if owner == "java/lang/reflect/Proxy" {
		blind["proxy"] = true
	}
	if strings.HasPrefix(owner, "java/lang/reflect/") || owner == "java/lang/Class" || strings.HasPrefix(owner, "java/lang/invoke/") {
		blind["reflection"] = true
	}
	if owner == "java/util/ServiceLoader" {
		blind["service_loader"] = true
	}
	if strings.HasPrefix(owner, "javax/naming/") || strings.HasPrefix(owner, "jakarta/naming/") {
		blind["jndi"] = true
	}
	if strings.Contains(owner, "ClassLoader") || (owner == "java/lang/Class" && c.name == "forName") {
		blind["classloader"] = true
	}
	if owner == "java/lang/System" && (c.name == "load" || c.name == "loadLibrary") {
		blind["jni"] = true
	}
	if strings.HasPrefix(owner, "org/springframework/") || strings.HasPrefix(owner, "jakarta/inject/") || strings.HasPrefix(owner, "javax/inject/") {
		blind["di"] = true
	}
	if c.opcode == 0xba {
		blind["invokedynamic"] = true
	}
}

func (g *methodGraph) buildEdges(ctx context.Context, pointsTo bool) error {
	edgeCount := 0
	methodCount := 0
	for _, cls := range g.classes {
		for _, method := range cls.methods {
			if methodCount&0x3f == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			methodCount++
			from := fullMethodKey(method.owner, method.name, method.desc)
			seen := map[string]bool{}
			for callIdx, call := range method.calls {
				if callIdx&0x3f == 0 {
					if err := ctx.Err(); err != nil {
						return err
					}
				}
				targets, err := g.resolveCall(ctx, call, pointsTo)
				if err != nil {
					return err
				}
				for _, target := range targets {
					if target != "" && !seen[target] {
						if edgeCount >= maxTier2Edges {
							return fmt.Errorf("jvm tier-2: call-graph edge limit exceeded")
						}
						seen[target] = true
						g.edges[from] = append(g.edges[from], target)
						edgeCount++
					}
				}
			}
			sort.Strings(g.edges[from])
		}
	}
	return nil
}

func (g *methodGraph) resolveCall(ctx context.Context, c callSite, pointsTo bool) ([]string, error) {
	if c.opcode == 0xb8 || c.opcode == 0xb7 {
		if key := g.lookupDeclared(c.owner, c.name, c.desc); key != "" {
			return []string{key}, nil
		}
		return nil, nil
	}
	if c.opcode != 0xb6 && c.opcode != 0xb9 {
		return nil, nil
	}
	if pointsTo && !c.receiverUnknown && len(c.receiverTypes) > 0 {
		var narrowed []string
		for i, typ := range c.receiverTypes {
			if i&0x3f == 0 {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
			isSubtype, err := g.isSubtype(ctx, typ, c.owner, map[string]bool{})
			if err != nil {
				return nil, err
			}
			if !isSubtype {
				continue
			}
			key, err := g.virtualDispatch(ctx, typ, c.name, c.desc)
			if err != nil {
				return nil, err
			}
			if key != "" {
				narrowed = append(narrowed, key)
			}
		}
		if len(narrowed) > 0 {
			return uniqueSorted(narrowed), nil
		}
	}
	var out []string
	classIdx := 0
	for name := range g.classes {
		if classIdx&0x3f == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		classIdx++
		isSubtype, err := g.isSubtype(ctx, name, c.owner, map[string]bool{})
		if err != nil {
			return nil, err
		}
		if !isSubtype {
			continue
		}
		key, err := g.virtualDispatch(ctx, name, c.name, c.desc)
		if err != nil {
			return nil, err
		}
		if key != "" {
			out = append(out, key)
		}
	}
	if key := g.lookupDeclared(c.owner, c.name, c.desc); key != "" {
		out = append(out, key)
	}
	return uniqueSorted(out), nil
}

func (g *methodGraph) lookupDeclared(owner, name, desc string) string {
	cls := g.classes[owner]
	if cls == nil {
		return ""
	}
	if _, ok := cls.methods[methodSig(name, desc)]; ok {
		return fullMethodKey(owner, name, desc)
	}
	return ""
}

func (g *methodGraph) virtualDispatch(ctx context.Context, typ, name, desc string) (string, error) {
	seen := map[string]bool{}
	for depth := 0; typ != "" && !seen[typ]; depth++ {
		if depth&0x3f == 0 {
			if err := ctx.Err(); err != nil {
				return "", err
			}
		}
		seen[typ] = true
		cls := g.classes[typ]
		if cls == nil {
			return "", nil
		}
		if _, ok := cls.methods[methodSig(name, desc)]; ok {
			return fullMethodKey(typ, name, desc), nil
		}
		typ = cls.super
	}
	return "", nil
}

func (g *methodGraph) isSubtype(ctx context.Context, typ, want string, seen map[string]bool) (bool, error) {
	queue := []string{typ}
	for visited := 0; len(queue) > 0; visited++ {
		if visited&0x3f == 0 {
			if err := ctx.Err(); err != nil {
				return false, err
			}
		}
		cur := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if cur == want {
			return true, nil
		}
		if cur == "" || seen[cur] {
			continue
		}
		seen[cur] = true
		cls := g.classes[cur]
		if cls == nil {
			continue
		}
		queue = append(queue, cls.super)
		queue = append(queue, cls.interfaces...)
	}
	return false, nil
}

func reachableMethods(ctx context.Context, edges map[string][]string, roots []string) (map[string]bool, map[string]string, error) {
	reached := map[string]bool{}
	prev := map[string]string{}
	queue := make([]string, 0, len(roots))
	for _, root := range roots {
		if root == "" || reached[root] {
			continue
		}
		reached[root] = true
		queue = append(queue, root)
	}
	for visited := 0; len(queue) > 0; visited++ {
		if visited&0x3ff == 0 {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
		}
		cur := queue[0]
		queue = queue[1:]
		for edgeIdx, next := range edges[cur] {
			if edgeIdx&0x3ff == 0 {
				if err := ctx.Err(); err != nil {
					return nil, nil, err
				}
			}
			if reached[next] {
				continue
			}
			reached[next] = true
			prev[next] = cur
			queue = append(queue, next)
		}
	}
	return reached, prev, nil
}

func methodPath(prev map[string]string, target string) []string {
	if target == "" {
		return nil
	}
	path := []string{target}
	for cur := target; prev[cur] != ""; {
		cur = prev[cur]
		path = append(path, cur)
		if len(path) >= 128 {
			break
		}
	}
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
	for i := range path {
		path[i] = displayMethod(path[i])
	}
	return path
}

func fullMethodKey(owner, name, desc string) string { return owner + "\x00" + name + "\x00" + desc }

func splitMethodKey(key string) (owner, name, desc string, ok bool) {
	parts := strings.SplitN(key, "\x00", 3)
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

func displayMethod(key string) string {
	owner, name, _, ok := splitMethodKey(key)
	if !ok {
		return key
	}
	return strings.ReplaceAll(owner, "/", ".") + "." + name
}

func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
