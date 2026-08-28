package pyreach

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/pythonprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
)

const (
	maxPythonWitnessNodes = 128
	maxPythonWitnessBytes = 256
)

type semanticFactsProvider interface {
	PythonFacts(ctx context.Context, root string) (pythonprogram.Document, bool, error)
}

// Tier2Analyzer resolves Python semantic facts once per pass and answers affected-symbol reachability.
// Partial evidence may prove a positive path; only a complete extraction/resolution may prove a negative.
type Tier2Analyzer struct {
	provider  semanticFactsProvider
	cached    *pythonTier2Evidence
	cachedDir string
	cachedErr error
}

func NewTier2Analyzer(provider semanticFactsProvider) (*Tier2Analyzer, error) {
	if provider == nil {
		return nil, fmt.Errorf("%w: python tier-2 analyzer needs a semantic facts provider", shared.ErrValidation)
	}
	return &Tier2Analyzer{provider: provider}, nil
}

func (a *Tier2Analyzer) Analyze(ctx context.Context, dir string, subjects []string) (*reachability.Analysis, error) {
	if ctx == nil || strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("%w: python tier-2 analysis needs a context and target directory", shared.ErrValidation)
	}
	if len(subjects) == 0 {
		return &reachability.Analysis{}, nil
	}
	evidence, err := a.evidenceFor(ctx, dir)
	if err != nil {
		return nil, err
	}
	results := make([]reachability.Result, 0, len(subjects))
	seen := map[string]bool{}
	for _, subject := range subjects {
		if seen[subject] {
			continue
		}
		seen[subject] = true
		placement := evidence.place(subject)
		result := reachability.Result{Symbol: subject}
		if target, path, witness := firstPythonReachable(evidence.resolution, placement.targets); target != "" {
			result.Reachable = true
			if witness {
				result.Path = path
			} else {
				result.Path = []string{"python:reachable:witness-budget-exceeded"}
			}
		} else if len(placement.targets) == 0 || !placement.complete || !evidence.resolution.Complete {
			// The recorder filters this case before calling Analyze. If a different caller bypasses that
			// contract, fail toward reachable so absence of evidence can never suppress a finding.
			result.Reachable = true
			result.Path = []string{"python:coverage:unknown", subject}
		}
		results = append(results, result)
	}
	return &reachability.Analysis{Results: results, Entrypoints: append([]string(nil), evidence.resolution.Graph.Entrypoints...)}, nil
}

type pythonTier2Evidence struct {
	resolution pythonprogram.Resolution
	nodes      []pythonNode
}

type pythonNode struct {
	id        string
	module    string
	qualified string
	dotted    string
}

type symbolPlacement struct {
	targets  []string
	complete bool
}

func (a *Tier2Analyzer) evidenceFor(ctx context.Context, dir string) (pythonTier2Evidence, error) {
	if a.cached != nil && a.cachedDir == dir {
		return *a.cached, a.cachedErr
	}
	document, available, err := a.provider.PythonFacts(ctx, dir)
	if err != nil {
		err = fmt.Errorf("python tier-2 semantic extraction (no coverage): %w", err)
		a.cached, a.cachedDir, a.cachedErr = &pythonTier2Evidence{}, dir, err
		return *a.cached, err
	}
	if !available {
		err = fmt.Errorf("%w: python tier-2 semantic sidecar is unavailable", shared.ErrNotFound)
		a.cached, a.cachedDir, a.cachedErr = &pythonTier2Evidence{}, dir, err
		return *a.cached, err
	}
	resolution, err := pythonprogram.Resolve(document)
	if err != nil {
		err = fmt.Errorf("python tier-2 semantic resolution (no coverage): %w", err)
		a.cached, a.cachedDir, a.cachedErr = &pythonTier2Evidence{}, dir, err
		return *a.cached, err
	}
	evidence := pythonTier2Evidence{resolution: resolution, nodes: indexPythonNodes(resolution)}
	a.cached, a.cachedDir, a.cachedErr = &evidence, dir, nil
	return evidence, nil
}

func (a *Tier2Analyzer) answerableSubjects(ctx context.Context, dir string, subjects []pythonReachabilitySubject) ([]pythonReachabilitySubject, error) {
	evidence, err := a.evidenceFor(ctx, dir)
	if err != nil {
		return nil, err
	}
	out := make([]pythonReachabilitySubject, 0, len(subjects))
	for _, subject := range subjects {
		var positive []string
		allPlaceable := len(subject.Symbols) > 0
		for _, raw := range subject.Symbols {
			placement := evidence.place(raw)
			target, _, witness := firstPythonReachable(evidence.resolution, placement.targets)
			if target != "" && witness {
				positive = append(positive, raw)
				continue
			}
			if target != "" {
				allPlaceable = false
				continue
			}
			if len(placement.targets) == 0 || !placement.complete {
				allPlaceable = false
			}
		}
		switch {
		case len(positive) > 0:
			// One reached affected symbol proves the finding reachable even if another advisory symbol is
			// unplaceable. Pass only positive subjects so the sealed path is real evidence.
			out = append(out, pythonReachabilitySubject{FindingID: subject.FindingID, Symbols: sortedUniqueStrings(positive)})
		case evidence.resolution.Complete && allPlaceable:
			out = append(out, pythonReachabilitySubject{FindingID: subject.FindingID, Symbols: append([]string(nil), subject.Symbols...)})
		}
	}
	return out, nil
}

func (e pythonTier2Evidence) place(subject string) symbolPlacement {
	purl, raw, ok := ParseSymbolSubject(subject)
	if !ok {
		return symbolPlacement{}
	}
	component, _, _ := parsePyPURL(purl)
	imports := ImportCandidates(component)
	allowedRoots := map[string]bool{}
	for _, candidate := range imports {
		allowedRoots[strings.ToLower(candidate)] = true
	}
	if module, _, canonical := splitCanonicalPythonID(raw); canonical {
		root := strings.Split(module, ".")[0]
		if !allowedRoots[strings.ToLower(root)] {
			return symbolPlacement{}
		}
		return symbolPlacement{targets: []string{raw}, complete: true}
	}

	normalized := strings.Replace(raw, ":", ".", 1)
	parts := strings.Split(normalized, ".")
	targets := map[string]bool{}
	for _, node := range e.nodes {
		root := strings.Split(node.module, ".")[0]
		if !allowedRoots[strings.ToLower(root)] {
			continue
		}
		if node.dotted == normalized || node.qualified == normalized || strings.HasSuffix(node.dotted, "."+normalized) {
			targets[node.id] = true
		}
	}
	complete := false
	if len(parts) >= 2 && allowedRoots[strings.ToLower(parts[0])] {
		complete = true
		for split := 1; split < len(parts); split++ {
			targets["python:"+strings.Join(parts[:split], ".")+":"+strings.Join(parts[split:], ".")] = true
		}
	}
	if len(parts) >= 2 && normalizeDistribution(parts[0]) == normalizeDistribution(component) {
		complete = true
		rest := parts[1:]
		for _, candidate := range imports {
			combined := append([]string{candidate}, rest...)
			for split := 1; split < len(combined); split++ {
				targets["python:"+strings.Join(combined[:split], ".")+":"+strings.Join(combined[split:], ".")] = true
			}
		}
	}
	out := make([]string, 0, len(targets))
	for target := range targets {
		out = append(out, target)
	}
	sort.Strings(out)
	return symbolPlacement{targets: out, complete: complete}
}

func indexPythonNodes(resolution pythonprogram.Resolution) []pythonNode {
	set := map[string]bool{}
	for _, entry := range resolution.Graph.Entrypoints {
		set[entry] = true
	}
	for _, edge := range resolution.Graph.Edges {
		set[edge.Caller] = true
		for _, callee := range edge.Callees {
			set[callee] = true
		}
	}
	for id := range resolution.Graph.Positions {
		set[id] = true
	}
	var nodes []pythonNode
	for id := range set {
		module, qualified, ok := splitCanonicalPythonID(id)
		if !ok || !validPythonDotted(module) || !validPythonDotted(qualified) {
			continue
		}
		nodes = append(nodes, pythonNode{id: id, module: module, qualified: qualified, dotted: module + "." + qualified})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].id < nodes[j].id })
	return nodes
}

func firstPythonReachable(resolution pythonprogram.Resolution, targets []string) (string, []string, bool) {
	longTarget := ""
	for _, target := range targets {
		if path := resolution.Graph.PathTo(target); len(path) > 0 {
			valid := len(path) <= maxPythonWitnessNodes
			for _, node := range path {
				valid = valid && len(node) <= maxPythonWitnessBytes
			}
			if valid {
				return target, path, true
			}
			if longTarget == "" {
				longTarget = target
			}
		}
	}
	return longTarget, nil, false
}

func sortedUniqueStrings(values []string) []string {
	sort.Strings(values)
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}
