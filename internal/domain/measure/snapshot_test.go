package measure

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type mockResolver struct {
	m   map[rule.Key]rule.Rule
	err error
}

func (r *mockResolver) Get(k rule.Key) (rule.Rule, error) {
	if r.err != nil {
		return rule.Rule{}, r.err
	}
	if rule, ok := r.m[k]; ok {
		return rule, nil
	}
	return rule.Rule{}, shared.ErrNotFound
}

func TestBuildSnapshot(t *testing.T) {
	// Setup dummy rule catalog
	catalog := &mockResolver{m: map[rule.Key]rule.Rule{
		"bug-rule": {
			Key:               "bug-rule",
			Type:              rule.TypeBug,
			RemediationEffort: 5,
		},
		"vuln-rule": {
			Key:               "vuln-rule",
			Type:              rule.TypeVulnerability,
			RemediationEffort: 10,
		},
		"hotspot-rule": {
			Key:               "hotspot-rule",
			Type:              rule.TypeSecurityHotspot,
			RemediationEffort: 15, // Hotspots should NOT add to effort
		},
	}}

	// 10. nil catalog behavior
	_, err := BuildSnapshot(BuildSnapshotInput{
		Inventory:   NewInventory(nil),
		RuleCatalog: nil,
	})
	if err == nil {
		t.Fatal("expected error for nil rule catalog")
	}

	input := BuildSnapshotInput{
		RuleCatalog: catalog,
		Inventory: NewInventory(nil,
			FileInventory{Path: "src/a.go", Language: "Go", CodeLines: 100, CommentLines: 20, Functions: 5, FunctionsKnown: true},
			FileInventory{Path: "src/b.go", Language: "Go", CodeLines: 50, CommentLines: 0, Functions: 2, FunctionsKnown: true},
			FileInventory{Path: "data/c.txt", Language: "Text", CodeLines: 10, CommentLines: 5, Functions: 0, FunctionsKnown: false},
		),
		Complexity: &ComplexityReport{
			Functions: []FunctionComplexity{
				{File: "src/a.go", Cyclomatic: 10, Cognitive: 8},
				{File: "src/b.go", Cyclomatic: 5, Cognitive: 2},
			},
		},
		Coverage: &CoverageReport{
			Files: []FileCoverage{
				{File: "src/a.go", TotalLines: 80, CoveredLines: 40},
				// src/b.go has no coverage data (0 coverable lines)
			},
		},
		Duplication: &DuplicationReport{
			Blocks: []DuplicationBlock{
				{
					Occurrences: []CodeRange{
						{File: "src/a.go", StartLine: 1, EndLine: 10},
						{File: "src/b.go", StartLine: 5, EndLine: 14}, // same block
					},
				},
				{
					Occurrences: []CodeRange{
						{File: "src/a.go", StartLine: 5, EndLine: 15},  // overlaps with first block
						{File: "src/a.go", StartLine: 50, EndLine: 60}, // different place
					},
				},
			},
		},
		Issues: []IssueInput{
			{Path: "src/a.go", RuleKey: "bug-rule", Severity: shared.SeverityHigh},
			{Path: "src/b.go", RuleKey: "vuln-rule", Severity: shared.SeverityCritical},
			{Path: "src/a.go", RuleKey: "hotspot-rule", Severity: shared.SeverityMedium},
			{Path: "src/a.go", RuleKey: "unknown-rule", Severity: shared.SeverityLow}, // 8. unknown rule
		},
	}

	snap, err := BuildSnapshot(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Helper to find node by path
	getNode := func(p string) *Node {
		for i := range snap.Nodes {
			if snap.Nodes[i].Path == p {
				return &snap.Nodes[i]
			}
		}
		return nil
	}

	// 4. deterministic node order
	var paths []string
	for _, n := range snap.Nodes {
		paths = append(paths, n.Path)
	}
	expectedPaths := []string{"", "data", "data/c.txt", "src", "src/a.go", "src/b.go"}
	if !reflect.DeepEqual(paths, expectedPaths) {
		t.Fatalf("expected paths %v, got %v", expectedPaths, paths)
	}

	// 1. root -> directory -> file hierarchy rollups
	root := getNode("")
	src := getNode("src")
	a := getNode("src/a.go")

	if root.Kind != NodeProject || src.Kind != NodeDirectory || a.Kind != NodeFile {
		t.Fatalf("wrong node kinds")
	}

	// 5. additive counter rollups
	if root.Counters.CodeLines != 160 { // 100 + 50 + 10
		t.Fatalf("root codelines = %d", root.Counters.CodeLines)
	}
	if root.Counters.Files != 3 {
		t.Fatalf("root files = %d", root.Counters.Files)
	}

	// 18. complexity aggregation
	if root.Counters.Cyclomatic != 15 {
		t.Fatalf("root cyclomatic = %d", root.Counters.Cyclomatic)
	}

	// 12. hotspot not double-counted & 13. remediation effort
	// src/a.go has 1 bug (effort 5), 1 hotspot (effort 15, ignored), 1 unknown (effort ignored)
	if a.Counters.RemediationEffortMinutes != 5 {
		t.Fatalf("a.go effort = %d", a.Counters.RemediationEffortMinutes)
	}
	if src.Counters.RemediationEffortMinutes != 15 { // a.go (5) + b.go (10)
		t.Fatalf("src effort = %d", src.Counters.RemediationEffortMinutes)
	}
	if a.Counters.IssuesByType[string(rule.TypeSecurityHotspot)] != 1 {
		t.Fatalf("expected 1 hotspot in a.go")
	}
	if a.Counters.IssuesByType[string(rule.TypeBug)] != 1 {
		t.Fatalf("expected 1 bug in a.go")
	}

	// 8. unknown rule key behavior
	if a.TechDebtAvailable {
		t.Fatalf("a.go should have unavailable tech debt due to unknown rule")
	}
	if a.Counters.IssuesBySeverity[string(shared.SeverityLow)] != 1 {
		t.Fatalf("unknown rule severity should still be counted")
	}
	if src.TechDebtAvailable {
		t.Fatalf("src tech debt should propagate unavailable")
	}

	// 14. overlap-safe duplicated line counting
	// a.go: block1 (1-10), block2 (5-15, 50-60) -> lines 1-15 (15 lines), 50-60 (11 lines) = 26 lines
	if a.Counters.DuplicatedLines != 26 {
		t.Fatalf("a.go duplicated lines = %d", a.Counters.DuplicatedLines)
	}
	// b.go: block1 (5-14) = 10 lines
	if root.Counters.DuplicatedLines != 36 {
		t.Fatalf("root duplicated lines = %d", root.Counters.DuplicatedLines)
	}

	// 15. distinct duplication-block rollup
	if a.Counters.DuplicationBlocks != 2 {
		t.Fatalf("a.go blocks = %d", a.Counters.DuplicationBlocks)
	}
	if getNode("src/b.go").Counters.DuplicationBlocks != 1 {
		t.Fatalf("b.go blocks = %d", getNode("src/b.go").Counters.DuplicationBlocks)
	}
	// block1 is shared by a.go and b.go, so src directory should only count it once -> total 2 distinct blocks
	if src.Counters.DuplicationBlocks != 2 {
		t.Fatalf("src blocks = %d", src.Counters.DuplicationBlocks)
	}

	// 17. new-code coverage unavailable
	if snap.NewCodeCoverage.Availability != AvailabilityUnavailable {
		t.Fatalf("new code coverage should be unavailable")
	}

	// 6. percentage derivation
	// Comment density of a.go = 20 / 120 = 16.666%
	if *a.CommentDensity().Value < 16.6 || *a.CommentDensity().Value > 16.7 {
		t.Fatalf("a.go comment density = %f", *a.CommentDensity().Value)
	}
	// Comment density of b.go = 0 / 50 = 0%
	if *getNode("src/b.go").CommentDensity().Value != 0 {
		t.Fatalf("b.go comment density = %f", *getNode("src/b.go").CommentDensity().Value)
	}

	// 7. no percentage averaging (root density should be 25 / 185 = 13.5%, NOT average of children)
	if *root.CommentDensity().Value < 13.5 || *root.CommentDensity().Value > 13.6 {
		t.Fatalf("root comment density = %f", *root.CommentDensity().Value)
	}

	// 16. coverage present and absent
	if *a.Coverage().Value != 50.0 {
		t.Fatalf("a.go coverage = %f", *a.Coverage().Value)
	}
	if getNode("src/b.go").Coverage().Availability != AvailabilityUnavailable {
		t.Fatalf("b.go coverage should be unavailable due to zero coverable lines")
	}

	// 19. legacy analysis decode & 20. memory clone isolation
	b, _ := json.Marshal(snap)
	var snap2 Snapshot
	json.Unmarshal(b, &snap2)

	if snap2.Nodes[0].Counters.Files != snap.Nodes[0].Counters.Files {
		t.Fatalf("json roundtrip failed")
	}
}

func TestSnapshotNormalization(t *testing.T) {
	tests := []struct {
		name    string
		paths   []string
		wantErr string
	}{
		{
			name:    "valid paths",
			paths:   []string{"src/win.go", "dir/double.go", "dot.go"},
			wantErr: "",
		},
		{
			name:    "unix absolute",
			paths:   []string{"/abs.go"},
			wantErr: "unix absolute",
		},
		{
			name:    "windows absolute",
			paths:   []string{"C:\\abs.go"},
			wantErr: "windows drive absolute",
		},
		{
			name:    "directory traversal",
			paths:   []string{"dir/../up.go"},
			wantErr: "directory traversal",
		},
		{
			name:    "repeated separators",
			paths:   []string{"dir//double.go"},
			wantErr: "repeated separators",
		},
		{
			name:    "duplicate canonical path",
			paths:   []string{"src/win.go", "src\\win.go"},
			wantErr: "duplicate canonical file path",
		},
		{
			name:    "root as file",
			paths:   []string{""},
			wantErr: "inventory file path cannot be root",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := make([]FileInventory, len(tt.paths))
			for i, p := range tt.paths {
				files[i] = FileInventory{Path: p, Language: "Go", CodeLines: 10}
			}
			input := BuildSnapshotInput{
				RuleCatalog: &mockResolver{},
				Inventory:   NewInventory(nil, files...),
			}

			_, err := BuildSnapshot(input)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestSnapshotCatalogFailure(t *testing.T) {
	input := BuildSnapshotInput{
		RuleCatalog: &mockResolver{err: errors.New("infra failure")},
		Inventory:   NewInventory(nil, FileInventory{Path: "src/a.go", Language: "Go", CodeLines: 10}),
		Issues:      []IssueInput{{Path: "src/a.go", RuleKey: "bug", Severity: shared.SeverityHigh}},
	}
	_, err := BuildSnapshot(input)
	if err == nil || !strings.Contains(err.Error(), "infra failure") {
		t.Fatalf("expected infra failure error, got %v", err)
	}
}

func TestSnapshotHotspotsIncluded(t *testing.T) {
	input := BuildSnapshotInput{
		RuleCatalog: &mockResolver{m: map[rule.Key]rule.Rule{
			"hotspot-rule": {Key: "hotspot-rule", Type: rule.TypeSecurityHotspot, RemediationEffort: 15},
		}},
		Inventory: NewInventory(nil),
		Issues: []IssueInput{
			{Path: "", RuleKey: "hotspot-rule", Severity: shared.SeverityHigh}, // hotspot with empty path
		},
	}
	snap, err := BuildSnapshot(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	root := snap.Nodes[0]
	if root.Counters.IssuesByType[string(rule.TypeSecurityHotspot)] != 1 {
		t.Fatalf("expected 1 security hotspot, got %d", root.Counters.IssuesByType[string(rule.TypeSecurityHotspot)])
	}
	if root.Counters.RemediationEffortMinutes != 0 {
		t.Fatalf("hotspots must not add to remediation effort, got %d", root.Counters.RemediationEffortMinutes)
	}
	if root.AttributionAvailable {
		t.Fatalf("empty path must trigger attribution unavailable")
	}
}

func TestSnapshotInvalidRuleType(t *testing.T) {
	input := BuildSnapshotInput{
		RuleCatalog: &mockResolver{m: map[rule.Key]rule.Rule{
			"bad-rule": {Key: "bad-rule", Type: rule.Type("invalid_type"), RemediationEffort: 10},
		}},
		Inventory: NewInventory(nil),
		Issues: []IssueInput{
			{Path: "", RuleKey: "bad-rule", Severity: shared.SeverityHigh},
		},
	}
	_, err := BuildSnapshot(input)
	if err == nil || !strings.Contains(err.Error(), "invalid rule type") {
		t.Fatalf("expected invalid rule type error, got %v", err)
	}
}

func TestSnapshotAttributionUnavailable(t *testing.T) {
	input := BuildSnapshotInput{
		RuleCatalog: &mockResolver{m: map[rule.Key]rule.Rule{
			"rule1": {Key: "rule1", Type: rule.TypeCodeSmell, RemediationEffort: 5},
			"rule2": {Key: "rule2", Type: rule.TypeVulnerability, RemediationEffort: 10},
		}},
		Inventory: NewInventory(nil,
			FileInventory{Path: "src/a.go", Language: "Go", CodeLines: 10},
			FileInventory{Path: "src/b.go", Language: "Go", CodeLines: 20},
		),
		Issues: []IssueInput{
			{Path: "", RuleKey: "rule1", Severity: shared.SeverityHigh},         // No path
			{Path: "src/c.go", RuleKey: "rule2", Severity: shared.SeverityHigh}, // Missing file
		},
	}
	snap, err := BuildSnapshot(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, n := range snap.Nodes {
		if n.AttributionAvailable {
			t.Fatalf("node %q expected AttributionAvailable=false", n.Path)
		}
	}

	root := snap.Nodes[0]
	if root.Counters.IssuesByType[string(rule.TypeCodeSmell)] != 1 {
		t.Fatalf("expected 1 code smell at root, got %d", root.Counters.IssuesByType[string(rule.TypeCodeSmell)])
	}
	if root.Counters.IssuesByType[string(rule.TypeVulnerability)] != 1 {
		t.Fatalf("expected 1 vulnerability at root, got %d", root.Counters.IssuesByType[string(rule.TypeVulnerability)])
	}
	if root.Counters.RemediationEffortMinutes != 15 {
		t.Fatalf("expected 15 minutes of remediation effort, got %d", root.Counters.RemediationEffortMinutes)
	}
}
