package projectuc

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

const (
	maxProjectDependencyNodes = 50_000
	maxProjectDependencyEdges = 250_000
)

// DependencyGraph is the latest immutable Project SBOM projected for interactive reads.
// It deliberately omits raw SBOM/source material and carries only bounded, stored facts.
type DependencyGraph struct {
	AnalysisID string                 `json:"analysis_id"`
	Roots      []string               `json:"roots"`
	Nodes      []DependencyGraphNode  `json:"nodes"`
	Edges      []DependencyGraphEdge  `json:"edges"`
	Summary    DependencyGraphSummary `json:"summary"`
}

type DependencyGraphNode struct {
	ID                 string                         `json:"id"`
	Name               string                         `json:"name"`
	Version            string                         `json:"version"`
	PURL               string                         `json:"purl,omitempty"`
	Scope              string                         `json:"scope"`
	Reachability       string                         `json:"reachability,omitempty"`
	Direct             bool                           `json:"direct"`
	Depth              int                            `json:"depth"`
	Licenses           []DependencyGraphLicense       `json:"licenses"`
	LicenseRisk        bool                           `json:"license_risk"`
	LicenseVerdict     string                         `json:"license_verdict"`
	Vulnerabilities    []DependencyGraphVulnerability `json:"vulnerabilities"`
	VulnerabilityCount int                            `json:"vulnerability_count"`
	WorstSeverity      string                         `json:"worst_severity,omitempty"`
}

type DependencyGraphLicense struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

type DependencyGraphVulnerability struct {
	ID           string `json:"id"`
	Source       string `json:"source"`
	Severity     string `json:"severity"`
	FixedVersion string `json:"fixed_version,omitempty"`
}

type DependencyGraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type DependencyGraphSummary struct {
	Components  int `json:"components"`
	Direct      int `json:"direct"`
	Transitive  int `json:"transitive"`
	Vulnerable  int `json:"vulnerable"`
	LicenseRisk int `json:"license_risk"`
	Edges       int `json:"edges"`
}

// ProjectDependencyGraph returns the latest analysis's dependency graph without exposing the
// entire cached scan result. Tenant ownership is resolved before the immutable result is read.
func (s *Service) ProjectDependencyGraph(ctx context.Context, tenantID shared.ID, key string) (DependencyGraph, error) {
	latest, scan, err := s.latestDependencyScan(ctx, tenantID, key)
	if err != nil {
		return DependencyGraph{}, err
	}
	return buildProjectDependencyGraph(latest.Analysis.ID, scan)
}

// ExportProjectDependencySubtree renders the selected component and every dependency below it as
// CycloneDX. An empty root exports the complete latest Project SBOM.
func (s *Service) ExportProjectDependencySubtree(ctx context.Context, tenantID shared.ID, key, root string) ([]byte, string, error) {
	latest, scan, err := s.latestDependencyScan(ctx, tenantID, key)
	if err != nil {
		return nil, "", err
	}
	if scan.SBOM == nil {
		return nil, "", shared.ErrNotFound
	}
	filtered, err := dependencySubtree(scan.SBOM, strings.TrimSpace(root))
	if err != nil {
		return nil, "", err
	}
	data, err := scauc.MarshalCycloneDX(filtered, scan.Target, latest.Analysis.CreatedAt)
	if err != nil {
		return nil, "", fmt.Errorf("render project dependency subtree: %w", err)
	}
	name := safeDependencyExportName(key)
	if root != "" {
		name += "-subtree"
	}
	return data, name + ".cdx.json", nil
}

func (s *Service) latestDependencyScan(ctx context.Context, tenantID shared.ID, key string) (LatestAnalysis, scauc.ScanResult, error) {
	latest, err := s.LatestAnalysis(ctx, tenantID, key)
	if err != nil {
		return LatestAnalysis{}, scauc.ScanResult{}, err
	}
	var scan scauc.ScanResult
	if err := json.Unmarshal(latest.Result, &scan); err != nil {
		return LatestAnalysis{}, scauc.ScanResult{}, fmt.Errorf("decode project dependency graph: %w", err)
	}
	if scan.SBOM == nil {
		return LatestAnalysis{}, scauc.ScanResult{}, shared.ErrNotFound
	}
	return latest, scan, nil
}

func buildProjectDependencyGraph(analysisID string, scan scauc.ScanResult) (DependencyGraph, error) {
	if scan.SBOM == nil {
		return DependencyGraph{}, shared.ErrNotFound
	}
	if len(scan.SBOM.Components) > maxProjectDependencyNodes {
		return DependencyGraph{}, fmt.Errorf("%w: dependency graph has %d components; maximum is %d", shared.ErrValidation, len(scan.SBOM.Components), maxProjectDependencyNodes)
	}

	type componentRef struct {
		component sbom.Component
		id        string
	}
	components := make([]componentRef, 0, len(scan.SBOM.Components))
	byID := make(map[string]sbom.Component, len(scan.SBOM.Components))
	byName := make(map[string][]string)
	byNameVersion := make(map[string][]string)
	for _, component := range scan.SBOM.Components {
		id := sbom.ComponentID(component.Name, component.Version, component.PURL)
		if id == "" {
			continue
		}
		if _, duplicate := byID[id]; duplicate {
			continue
		}
		byID[id] = component
		components = append(components, componentRef{component: component, id: id})
		byName[component.Name] = append(byName[component.Name], id)
		byNameVersion[component.Name+"\x00"+component.Version] = append(byNameVersion[component.Name+"\x00"+component.Version], id)
	}
	sort.Slice(components, func(i, j int) bool { return components[i].id < components[j].id })

	edgeSeen := make(map[string]bool)
	children := make(map[string][]string)
	parents := make(map[string][]string)
	edges := make([]DependencyGraphEdge, 0)
	for _, dependency := range scan.SBOM.Dependencies {
		if _, exists := byID[dependency.Ref]; !exists {
			continue
		}
		for _, target := range dependency.DependsOn {
			if _, exists := byID[target]; !exists || target == dependency.Ref {
				continue
			}
			key := dependency.Ref + "\x00" + target
			if edgeSeen[key] {
				continue
			}
			if len(edges) >= maxProjectDependencyEdges {
				return DependencyGraph{}, fmt.Errorf("%w: dependency graph exceeds %d edges", shared.ErrValidation, maxProjectDependencyEdges)
			}
			edgeSeen[key] = true
			edges = append(edges, DependencyGraphEdge{From: dependency.Ref, To: target})
			children[dependency.Ref] = append(children[dependency.Ref], target)
			parents[target] = append(parents[target], dependency.Ref)
		}
	}
	for id := range byID {
		sort.Strings(children[id])
		sort.Strings(parents[id])
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		return edges[i].To < edges[j].To
	})

	roots := make([]string, 0)
	for id := range byID {
		if len(parents[id]) == 0 {
			roots = append(roots, id)
		}
	}
	sort.Strings(roots)
	depth := dependencyDepths(roots, children)

	vulnsByID := make(map[string][]DependencyGraphVulnerability)
	for _, item := range scan.Vulnerabilities {
		ids := componentIDsForVulnerability(item, byID, byNameVersion)
		severity := item.Severity
		if !severity.Valid() {
			severity = shared.SeverityUnknown
		}
		for _, id := range ids {
			vulnsByID[id] = append(vulnsByID[id], DependencyGraphVulnerability{
				ID: item.ID, Source: item.Source, Severity: string(severity), FixedVersion: item.FixedVersion,
			})
		}
	}
	for id := range vulnsByID {
		sort.Slice(vulnsByID[id], func(i, j int) bool {
			left, right := vulnsByID[id][i], vulnsByID[id][j]
			if left.ID != right.ID {
				return left.ID < right.ID
			}
			if left.Source != right.Source {
				return left.Source < right.Source
			}
			if left.Severity != right.Severity {
				return left.Severity < right.Severity
			}
			return left.FixedVersion < right.FixedVersion
		})
	}

	licenseVerdict := make(map[string]string)
	for _, finding := range scan.Licenses {
		for _, token := range finding.Components {
			for _, id := range resolveLicenseComponentIDs(token, byID, byName, byNameVersion) {
				if licenseVerdictRank(string(finding.Verdict)) > licenseVerdictRank(licenseVerdict[id]) {
					licenseVerdict[id] = string(finding.Verdict)
				}
			}
		}
	}

	graph := DependencyGraph{AnalysisID: analysisID, Roots: roots, Edges: edges}
	for _, ref := range components {
		licenses := make([]DependencyGraphLicense, 0, len(ref.component.Licenses))
		riskyCategory := false
		for _, license := range ref.component.Licenses {
			category := license.Category
			if category == "" {
				category = sbom.LicenseUnknown
			}
			licenses = append(licenses, DependencyGraphLicense{ID: license.SPDXID, Name: license.Name, Category: string(category)})
			riskyCategory = riskyCategory || category == sbom.LicenseCopyleft || category == sbom.LicenseProprietary || category == sbom.LicenseUnknown
		}
		sort.Slice(licenses, func(i, j int) bool {
			if licenses[i].ID != licenses[j].ID {
				return licenses[i].ID < licenses[j].ID
			}
			if licenses[i].Name != licenses[j].Name {
				return licenses[i].Name < licenses[j].Name
			}
			return licenses[i].Category < licenses[j].Category
		})
		itemDepth, reachable := depth[ref.id]
		if !reachable {
			itemDepth = -1 // a cycle with no root: visible, but never mislabelled direct.
		}
		vulns := vulnsByID[ref.id]
		verdict := licenseVerdict[ref.id]
		licenseRisk := verdict == string(ports.LicenseWarn) || verdict == string(ports.LicenseDeny) || verdict == "" && riskyCategory
		node := DependencyGraphNode{
			ID: ref.id, Name: ref.component.Name, Version: ref.component.Version, PURL: ref.component.PURL,
			Scope: ref.component.Scope, Reachability: ref.component.Reachability,
			Direct: itemDepth == 0, Depth: itemDepth, Licenses: licenses,
			LicenseRisk: licenseRisk, LicenseVerdict: verdict, Vulnerabilities: vulns,
			VulnerabilityCount: len(vulns), WorstSeverity: worstDependencySeverity(vulns),
		}
		graph.Nodes = append(graph.Nodes, node)
		graph.Summary.Components++
		if node.Direct {
			graph.Summary.Direct++
		} else {
			graph.Summary.Transitive++
		}
		if node.VulnerabilityCount > 0 {
			graph.Summary.Vulnerable++
		}
		if node.LicenseRisk {
			graph.Summary.LicenseRisk++
		}
	}
	graph.Summary.Edges = len(edges)
	return graph, nil
}

func dependencyDepths(roots []string, children map[string][]string) map[string]int {
	depth := make(map[string]int, len(children))
	queue := append([]string(nil), roots...)
	for _, root := range roots {
		depth[root] = 0
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, child := range children[current] {
			next := depth[current] + 1
			known, exists := depth[child]
			if exists && known <= next {
				continue
			}
			depth[child] = next
			queue = append(queue, child)
		}
	}
	return depth
}

func componentIDsForVulnerability(item vulnerability.Vulnerability, byID map[string]sbom.Component, byNameVersion map[string][]string) []string {
	if item.PackagePURL != "" {
		if _, ok := byID[item.PackagePURL]; ok {
			return []string{item.PackagePURL}
		}
	}
	return append([]string(nil), byNameVersion[item.Component+"\x00"+item.Version]...)
}

func resolveLicenseComponentIDs(token string, byID map[string]sbom.Component, byName, byNameVersion map[string][]string) []string {
	if _, ok := byID[token]; ok {
		return []string{token}
	}
	if ids := byName[token]; len(ids) > 0 {
		return append([]string(nil), ids...)
	}
	if at := strings.LastIndex(token, "@"); at > 0 {
		return append([]string(nil), byNameVersion[token[:at]+"\x00"+token[at+1:]]...)
	}
	return nil
}

func licenseVerdictRank(verdict string) int {
	switch verdict {
	case string(ports.LicenseDeny):
		return 3
	case string(ports.LicenseWarn):
		return 2
	case string(ports.LicenseAllow):
		return 1
	default:
		return 0
	}
}

func worstDependencySeverity(items []DependencyGraphVulnerability) string {
	worst, rank := "", -1
	for _, item := range items {
		severity := shared.Severity(item.Severity)
		if current := shared.SeverityRank(severity); current > rank {
			worst, rank = item.Severity, current
		}
	}
	return worst
}

func dependencySubtree(doc *sbom.SBOM, root string) (*sbom.SBOM, error) {
	if doc == nil {
		return nil, shared.ErrNotFound
	}
	if root == "" {
		clone := *doc
		clone.Components = append([]sbom.Component(nil), doc.Components...)
		clone.Dependencies = cloneDependencies(doc.Dependencies)
		clone.Raw = nil
		return &clone, nil
	}
	valid := make(map[string]bool, len(doc.Components))
	for _, component := range doc.Components {
		valid[sbom.ComponentID(component.Name, component.Version, component.PURL)] = true
	}
	if !valid[root] {
		return nil, shared.ErrNotFound
	}
	children := make(map[string][]string)
	for _, dependency := range doc.Dependencies {
		if !valid[dependency.Ref] {
			continue
		}
		for _, child := range dependency.DependsOn {
			if valid[child] {
				children[dependency.Ref] = append(children[dependency.Ref], child)
			}
		}
	}
	selected := map[string]bool{root: true}
	queue := []string{root}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, child := range children[current] {
			if selected[child] {
				continue
			}
			selected[child] = true
			queue = append(queue, child)
		}
	}
	filtered := *doc
	filtered.Raw = nil
	filtered.Components = nil
	for _, component := range doc.Components {
		if selected[sbom.ComponentID(component.Name, component.Version, component.PURL)] {
			filtered.Components = append(filtered.Components, component)
		}
	}
	filtered.Dependencies = nil
	for _, dependency := range doc.Dependencies {
		if !selected[dependency.Ref] {
			continue
		}
		next := sbom.Dependency{Ref: dependency.Ref}
		for _, child := range dependency.DependsOn {
			if selected[child] {
				next.DependsOn = append(next.DependsOn, child)
			}
		}
		filtered.Dependencies = append(filtered.Dependencies, next)
	}
	return &filtered, nil
}

func cloneDependencies(in []sbom.Dependency) []sbom.Dependency {
	out := make([]sbom.Dependency, len(in))
	for i, dependency := range in {
		out[i] = sbom.Dependency{Ref: dependency.Ref, DependsOn: append([]string(nil), dependency.DependsOn...)}
	}
	return out
}

func safeDependencyExportName(key string) string {
	key = strings.TrimSpace(key)
	var out strings.Builder
	for _, r := range key {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			out.WriteRune(r)
		}
	}
	if out.Len() == 0 {
		return "project-dependencies"
	}
	return out.String() + "-dependencies"
}
