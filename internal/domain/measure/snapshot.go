package measure

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type NodeKind string

const (
	NodeProject   NodeKind = "project"
	NodeDirectory NodeKind = "directory"
	NodeFile      NodeKind = "file"
)

type Availability string

const (
	AvailabilityAvailable   Availability = "available"
	AvailabilityUnavailable Availability = "unavailable"
)

type CountMetric struct {
	Availability Availability `json:"availability"`
	Value        *int         `json:"value"`
	Reason       string       `json:"reason,omitempty"`
}

type DecimalMetric struct {
	Availability Availability `json:"availability"`
	Value        *float64     `json:"value"`
	Reason       string       `json:"reason,omitempty"`
}

type Counters struct {
	Files        int `json:"files"`
	Functions    int `json:"functions"`
	CodeLines    int `json:"code_lines"`
	CommentLines int `json:"comment_lines"`
	BlankLines   int `json:"blank_lines"`

	Cyclomatic int `json:"cyclomatic"`
	Cognitive  int `json:"cognitive"`

	CoveredLines      int `json:"covered_lines"`
	CoverableLines    int `json:"coverable_lines"`
	DuplicatedLines   int `json:"duplicated_lines"`
	DuplicationBlocks int `json:"duplication_blocks"`

	IssuesByType     map[string]int `json:"issues_by_type"`
	IssuesBySeverity map[string]int `json:"issues_by_severity"`

	RemediationEffortMinutes int `json:"remediation_effort_minutes"`
}

type Node struct {
	Path     string   `json:"path"`
	Name     string   `json:"name"`
	Kind     NodeKind `json:"kind"`
	Parent   string   `json:"parent,omitempty"`
	Language string   `json:"language,omitempty"`

	Counters Counters `json:"counters"`

	FunctionsKnown       bool `json:"functions_known"`
	ComplexityAvailable  bool `json:"complexity_available"`
	CoverageAvailable    bool `json:"coverage_available"`
	DuplicationAvailable bool `json:"duplication_available"`
	TechDebtAvailable    bool `json:"tech_debt_available"`
	IssueTypeAvailable   bool `json:"issue_type_available"`
	AttributionAvailable bool `json:"attribution_available"`
}

func (n Node) CommentDensity() DecimalMetric {
	total := n.Counters.CodeLines + n.Counters.CommentLines
	if total == 0 {
		return DecimalMetric{Availability: AvailabilityUnavailable}
	}
	val := float64(n.Counters.CommentLines) / float64(total) * 100.0
	return DecimalMetric{Availability: AvailabilityAvailable, Value: &val}
}

func (n Node) Coverage() DecimalMetric {
	if !n.CoverageAvailable {
		return DecimalMetric{Availability: AvailabilityUnavailable}
	}
	if n.Counters.CoverableLines == 0 {
		return DecimalMetric{Availability: AvailabilityUnavailable}
	}
	val := float64(n.Counters.CoveredLines) / float64(n.Counters.CoverableLines) * 100.0
	return DecimalMetric{Availability: AvailabilityAvailable, Value: &val}
}

func (n Node) DuplicationDensity() DecimalMetric {
	if !n.DuplicationAvailable {
		return DecimalMetric{Availability: AvailabilityUnavailable}
	}
	if n.Counters.CodeLines == 0 {
		val := 0.0
		return DecimalMetric{Availability: AvailabilityAvailable, Value: &val}
	}
	val := float64(n.Counters.DuplicatedLines) / float64(n.Counters.CodeLines) * 100.0
	return DecimalMetric{Availability: AvailabilityAvailable, Value: &val}
}

type Snapshot struct {
	Nodes []Node `json:"nodes"`

	NewCodeCoverage DecimalMetric `json:"new_code_coverage"`
}

type IssueInput struct {
	Path     string
	RuleKey  rule.Key
	Severity shared.Severity
}

type RuleResolver interface {
	Get(key rule.Key) (rule.Rule, error)
}

type BuildSnapshotInput struct {
	Inventory   Inventory
	Complexity  *ComplexityReport
	Coverage    *CoverageReport
	Duplication *DuplicationReport
	Issues      []IssueInput
	RuleCatalog RuleResolver
}

// CanonicalPath normalizes a file path and strictly rejects traversal and absolute paths.
func CanonicalPath(p string) (string, error) {
	p = strings.ReplaceAll(p, "\\", "/")
	if p == "" {
		return "", nil
	}
	if p == "." {
		return "", errors.New("canonical path: dot paths are not allowed")
	}
	if strings.HasPrefix(p, "/") {
		return "", errors.New("canonical path: unix absolute paths are not allowed")
	}
	// Reject Windows drive letters/UNC
	if len(p) >= 2 && p[1] == ':' {
		return "", errors.New("canonical path: windows drive absolute paths are not allowed")
	}
	if strings.Contains(p, "//") {
		return "", errors.New("canonical path: repeated separators are not allowed")
	}

	parts := strings.Split(p, "/")
	var clean []string
	for _, part := range parts {
		if part == "" {
			return "", errors.New("canonical path: empty segments are not allowed")
		}
		if part == "." {
			return "", errors.New("canonical path: dot segments are not allowed")
		}
		if part == ".." {
			return "", errors.New("canonical path: directory traversal is not allowed")
		}
		clean = append(clean, part)
	}
	return strings.Join(clean, "/"), nil
}

// BuildSnapshot creates an immutable measure snapshot from engine outputs.
func BuildSnapshot(in BuildSnapshotInput) (Snapshot, error) {
	if in.RuleCatalog == nil {
		return Snapshot{}, errors.New("measure snapshot: nil rule catalog")
	}

	nodesByPath := make(map[string]*Node)

	getNode := func(p string) *Node {
		if n, ok := nodesByPath[p]; ok {
			return n
		}

		name := path.Base(p)
		parent := ""
		kind := NodeDirectory
		if p == "" {
			name = ""
			kind = NodeProject
		} else {
			dir := path.Dir(p)
			if dir == "." {
				parent = ""
			} else {
				parent = dir
			}
		}

		n := &Node{
			Path:   p,
			Name:   name,
			Kind:   kind,
			Parent: parent,
			Counters: Counters{
				IssuesByType:     make(map[string]int),
				IssuesBySeverity: make(map[string]int),
			},
			FunctionsKnown:       true,
			ComplexityAvailable:  true,
			CoverageAvailable:    in.Coverage != nil,
			DuplicationAvailable: in.Duplication != nil,
			TechDebtAvailable:    true,
			IssueTypeAvailable:   true,
			AttributionAvailable: true,
		}
		nodesByPath[p] = n
		return n
	}

	getNode("") // Always create root node unconditionally

	seenFilePaths := make(map[string]bool)

	markAttributionUnavailable := func() {
		for _, node := range nodesByPath {
			node.AttributionAvailable = false
		}
	}

	// 1. Files from Inventory
	for _, f := range in.Inventory.Files {
		p, err := CanonicalPath(f.Path)
		if err != nil {
			return Snapshot{}, err
		}
		if p == "" {
			return Snapshot{}, errors.New("measure snapshot: inventory file path cannot be root")
		}
		if seenFilePaths[p] {
			return Snapshot{}, errors.New("measure snapshot: duplicate canonical file path in inventory: " + p)
		}
		seenFilePaths[p] = true

		n := getNode(p)
		n.Kind = NodeFile
		n.Language = f.Language
		n.Counters.Files = 1
		n.Counters.CodeLines = f.CodeLines
		n.Counters.CommentLines = f.CommentLines
		n.Counters.BlankLines = f.BlankLines
		n.Counters.Functions = f.Functions
		n.FunctionsKnown = f.FunctionsKnown
	}

	// Make sure parents exist
	ensureParents := func(p string) {
		if p == "" {
			return
		}
		dir := path.Dir(p)
		if dir == "." {
			dir = ""
		}
		for dir != "" && dir != "." {
			getNode(dir)
			nextDir := path.Dir(dir)
			if nextDir == "." {
				nextDir = ""
			}
			dir = nextDir
		}
		getNode("") // root
	}

	for p := range nodesByPath {
		ensureParents(p)
	}

	// 2. Complexity
	if in.Complexity != nil {
		for _, cx := range in.Complexity.Functions {
			p, err := CanonicalPath(cx.File)
			if err != nil {
				return Snapshot{}, fmt.Errorf("measure snapshot: complexity path %q: %w", cx.File, err)
			}
			n := nodesByPath[p]
			if n != nil && n.Kind == NodeFile {
				n.Counters.Cyclomatic += cx.Cyclomatic
				n.Counters.Cognitive += cx.Cognitive
			}
		}
	} else {
		for _, n := range nodesByPath {
			n.ComplexityAvailable = false
		}
	}

	// 3. Coverage
	if in.Coverage != nil {
		for _, fc := range in.Coverage.Files {
			p, err := CanonicalPath(fc.File)
			if err != nil {
				return Snapshot{}, fmt.Errorf("measure snapshot: coverage path %q: %w", fc.File, err)
			}
			n := nodesByPath[p]
			if n != nil && n.Kind == NodeFile {
				n.Counters.CoverableLines = fc.TotalLines
				n.Counters.CoveredLines = fc.CoveredLines
			}
		}
		// Files in inventory without coverage data have 0 coverable lines.
	}

	// 4. Duplication
	blockOccurrencesByNode := make(map[string]map[int]bool) // Node path -> Block Index -> true
	if in.Duplication != nil {
		globalFileLines := make(map[string]map[int]bool)
		for bi, block := range in.Duplication.Blocks {
			for _, occ := range block.Occurrences {
				if occ.StartLine < 1 || occ.EndLine < occ.StartLine {
					continue
				}
				p, err := CanonicalPath(occ.File)
				if err != nil {
					return Snapshot{}, fmt.Errorf("measure snapshot: duplication path %q: %w", occ.File, err)
				}
				n := nodesByPath[p]
				if n == nil || n.Kind != NodeFile {
					continue
				}
				if globalFileLines[p] == nil {
					globalFileLines[p] = make(map[int]bool)
				}
				for line := occ.StartLine; line <= occ.EndLine; line++ {
					globalFileLines[p][line] = true
				}

				if blockOccurrencesByNode[p] == nil {
					blockOccurrencesByNode[p] = make(map[int]bool)
				}
				blockOccurrencesByNode[p][bi] = true
			}
		}

		for p, lines := range globalFileLines {
			n := nodesByPath[p]
			dupLines := len(lines)
			// Clamp to code lines
			if dupLines > n.Counters.CodeLines {
				dupLines = n.Counters.CodeLines
			}
			n.Counters.DuplicatedLines += dupLines
		}

		for p, blocks := range blockOccurrencesByNode {
			n := nodesByPath[p]
			n.Counters.DuplicationBlocks = len(blocks)
		}
	}

	// 5. Issues
	for _, issue := range in.Issues {
		if strings.TrimSpace(issue.Path) == "" {
			n := getNode("")
			n.Counters.IssuesBySeverity[string(issue.Severity)]++
			markAttributionUnavailable()

			r, err := in.RuleCatalog.Get(issue.RuleKey)
			if err != nil {
				if !errors.Is(err, shared.ErrNotFound) {
					return Snapshot{}, fmt.Errorf("measure snapshot: resolve rule %q: %w", issue.RuleKey, err)
				}
				n.TechDebtAvailable = false
				n.IssueTypeAvailable = false
				continue
			}
			if !r.Type.Valid() {
				return Snapshot{}, fmt.Errorf("measure snapshot: invalid rule type %q for rule %q", r.Type, issue.RuleKey)
			}
			n.Counters.IssuesByType[string(r.Type)]++
			if r.Type != rule.TypeSecurityHotspot {
				n.Counters.RemediationEffortMinutes += r.RemediationEffort
			}
			continue
		}

		p, err := CanonicalPath(issue.Path)
		n := nodesByPath[p]
		if err != nil || n == nil {
			n = getNode("") // Add to root if path is missing, invalid, or unmatched
			markAttributionUnavailable()
		}

		if string(issue.Severity) != "" {
			n.Counters.IssuesBySeverity[string(issue.Severity)]++
		}

		r, err := in.RuleCatalog.Get(issue.RuleKey)
		if err != nil {
			if !errors.Is(err, shared.ErrNotFound) {
				return Snapshot{}, fmt.Errorf("measure snapshot: resolve rule %q: %w", issue.RuleKey, err)
			}
			n.TechDebtAvailable = false
			n.IssueTypeAvailable = false
			continue
		}

		if !r.Type.Valid() {
			return Snapshot{}, fmt.Errorf("measure snapshot: invalid rule type %q for rule %q", r.Type, issue.RuleKey)
		}

		n.Counters.IssuesByType[string(r.Type)]++

		if r.Type != rule.TypeSecurityHotspot {
			n.Counters.RemediationEffortMinutes += r.RemediationEffort
		}
	}

	// Rollup function (post-order traversal)
	// Sort paths so children come before parents
	var paths []string
	for p := range nodesByPath {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool {
		return len(paths[i]) > len(paths[j]) // Longer paths first (children before parents)
	})

	for _, p := range paths {
		if p == "" {
			continue // Root has no parent to roll up to
		}
		n := nodesByPath[p]
		parent := nodesByPath[n.Parent]
		parent.Counters.Files += n.Counters.Files
		parent.Counters.CodeLines += n.Counters.CodeLines
		parent.Counters.CommentLines += n.Counters.CommentLines
		parent.Counters.BlankLines += n.Counters.BlankLines
		parent.Counters.Functions += n.Counters.Functions

		parent.Counters.Cyclomatic += n.Counters.Cyclomatic
		parent.Counters.Cognitive += n.Counters.Cognitive

		parent.Counters.CoverableLines += n.Counters.CoverableLines
		parent.Counters.CoveredLines += n.Counters.CoveredLines

		parent.Counters.DuplicatedLines += n.Counters.DuplicatedLines

		for k, v := range n.Counters.IssuesByType {
			parent.Counters.IssuesByType[k] += v
		}
		for k, v := range n.Counters.IssuesBySeverity {
			parent.Counters.IssuesBySeverity[k] += v
		}

		parent.Counters.RemediationEffortMinutes += n.Counters.RemediationEffortMinutes

		parent.FunctionsKnown = parent.FunctionsKnown && n.FunctionsKnown
		parent.ComplexityAvailable = parent.ComplexityAvailable && n.ComplexityAvailable
		parent.CoverageAvailable = parent.CoverageAvailable && n.CoverageAvailable
		parent.DuplicationAvailable = parent.DuplicationAvailable && n.DuplicationAvailable
		parent.TechDebtAvailable = parent.TechDebtAvailable && n.TechDebtAvailable
		parent.IssueTypeAvailable = parent.IssueTypeAvailable && n.IssueTypeAvailable
		parent.AttributionAvailable = parent.AttributionAvailable && n.AttributionAvailable
	}

	// Deduplicate blocks for directories
	if in.Duplication != nil {
		// Re-sort from children to parents
		for _, p := range paths {
			if p == "" {
				continue
			}
			n := nodesByPath[p]
			if blockOccurrencesByNode[n.Parent] == nil {
				blockOccurrencesByNode[n.Parent] = make(map[int]bool)
			}
			for bi := range blockOccurrencesByNode[p] {
				blockOccurrencesByNode[n.Parent][bi] = true
			}
		}
		for p, blocks := range blockOccurrencesByNode {
			n := nodesByPath[p]
			n.Counters.DuplicationBlocks = len(blocks)
		}
	}

	// Final sort for nodes by canonical path
	sort.Slice(paths, func(i, j int) bool {
		return paths[i] < paths[j]
	})

	var nodes []Node
	for _, p := range paths {
		nodes = append(nodes, *nodesByPath[p])
	}

	return Snapshot{
		Nodes: nodes,
		NewCodeCoverage: DecimalMetric{
			Availability: AvailabilityUnavailable,
			Reason:       "changed_line_coverage_not_available",
		},
	}, nil
}
