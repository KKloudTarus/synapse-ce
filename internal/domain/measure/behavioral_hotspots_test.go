package measure

import (
	"strings"
	"testing"
)

func TestBehavioralHotspotsReport_RankingAndTieBreaking(t *testing.T) {
	// Fixture:
	// A: complexity 10, 8 commits => 80
	// B: complexity 30, 1 commit  => 30
	// C: complexity 10, 3 commits => 30 (tie with B on score: B has 1 commit, C has 3 commits -> C before B)
	// D: complexity 30, 1 commit  => 30 (tie with B on score & commits & complexity: path "d.go" vs "b.go" -> b.go before d.go)
	// E: complexity 10, 0 commits => 0 (measured in window with 0 touches)
	inv := Inventory{
		Files: []FileInventory{
			{Path: "a.go", Language: "Go"},
			{Path: "b.go", Language: "Go"},
			{Path: "c.go", Language: "Go"},
			{Path: "d.go", Language: "Go"},
			{Path: "e.go", Language: "Go"},
		},
	}

	comp := &ComplexityReport{
		Functions: []FunctionComplexity{
			{File: "a.go", Cyclomatic: 10},
			{File: "b.go", Cyclomatic: 30},
			{File: "c.go", Cyclomatic: 10},
			{File: "d.go", Cyclomatic: 30},
			{File: "e.go", Cyclomatic: 10},
		},
		Files: []ComplexityFileCoverage{
			{File: "a.go", Language: "Go", Supported: true, Parsed: true},
			{File: "b.go", Language: "Go", Supported: true, Parsed: true},
			{File: "c.go", Language: "Go", Supported: true, Parsed: true},
			{File: "d.go", Language: "Go", Supported: true, Parsed: true},
			{File: "e.go", Language: "Go", Supported: true, Parsed: true},
		},
	}

	// 8 commits touching a.go; 3 commits touching c.go; 1 commit touching b.go and d.go
	commits := make([]BehavioralCommitEvidence, 8)
	c1Hash := strings.Repeat("1", 40)
	for i := 0; i < 8; i++ {
		cID := strings.Repeat(string(rune('1'+i)), 40)
		nextID := ""
		if i+1 < 8 {
			nextID = strings.Repeat(string(rune('1'+i+1)), 40)
		}
		var paths []string
		paths = append(paths, "a.go")
		if i < 3 {
			paths = append(paths, "c.go")
		}
		if i == 0 {
			paths = append(paths, "b.go", "d.go")
		}
		commits[i] = BehavioralCommitEvidence{
			CommitID:      cID,
			FirstParentID: nextID,
			TouchedPaths:  paths,
		}
	}

	rep, err := BuildBehavioralHotspots(BuildBehavioralHotspotsInput{
		Inventory:        inv,
		Complexity:       comp,
		Commits:          commits,
		HeadCommit:       c1Hash,
		RequestedCommits: 8,
		EvaluatedCommits: 8,
		ReachedRoot:      true,
		HistoryAvailable: true,
	})
	if err != nil {
		t.Fatalf("BuildBehavioralHotspots: %v", err)
	}

	if rep.Availability != BehavioralComplete {
		t.Fatalf("expected complete, got %v (%s)", rep.Availability, rep.Reason)
	}
	if len(rep.Files) != 5 {
		t.Fatalf("expected 5 files, got %d", len(rep.Files))
	}

	// Order check:
	// 1. a.go (score 80)
	// 2. c.go (score 30, changes 3)
	// 3. b.go (score 30, changes 1, cyc 30, path b.go)
	// 4. d.go (score 30, changes 1, cyc 30, path d.go)
	// 5. e.go (score 0, changes 0)
	expected := []string{"a.go", "c.go", "b.go", "d.go", "e.go"}
	for i, exp := range expected {
		if rep.Files[i].Path != exp {
			t.Errorf("file[%d] got %s, want %s", i, rep.Files[i].Path, exp)
		}
	}

	// Verify metrics for directory / project
	projMetrics := rep.MetricsForPath("", NodeProject)
	if projMetrics.Score.Availability != AvailabilityAvailable || *projMetrics.Score.Value != 80 {
		t.Fatalf("project max score want 80, got %v", projMetrics.Score)
	}
	if projMetrics.ChangeCount.Availability != AvailabilityAvailable || *projMetrics.ChangeCount.Value != 5 {
		t.Fatalf("project measured count want 5, got %v", projMetrics.ChangeCount)
	}

	// Verify ranked descendant files
	items, total, shown, omitted := rep.RankedFiles("", 2)
	if total != 5 || shown != 2 || omitted != 3 || len(items) != 2 {
		t.Fatalf("RankedFiles paging mismatch: total=%d shown=%d omitted=%d len=%d", total, shown, omitted, len(items))
	}
	if items[0].Path != "a.go" || items[1].Path != "c.go" {
		t.Fatalf("RankedFiles items: got %s, %s", items[0].Path, items[1].Path)
	}
}

func TestBehavioralHotspotsReport_PartialAndUnavailable(t *testing.T) {
	inv := Inventory{
		Files: []FileInventory{
			{Path: "pkg/a.go", Language: "Go"},
			{Path: "pkg/unsupported.xyz", Language: "XYZ"},
		},
	}

	comp := &ComplexityReport{
		Functions: []FunctionComplexity{
			{File: "pkg/a.go", Cyclomatic: 5},
		},
		Files: []ComplexityFileCoverage{
			{File: "pkg/a.go", Language: "Go", Supported: true, Parsed: true},
			{File: "pkg/unsupported.xyz", Language: "XYZ", Supported: false, Parsed: false},
		},
	}

	head := strings.Repeat("a", 40)
	commits := []BehavioralCommitEvidence{
		{CommitID: head, TouchedPaths: []string{"pkg/a.go"}},
	}

	rep, err := BuildBehavioralHotspots(BuildBehavioralHotspotsInput{
		Inventory:        inv,
		Complexity:       comp,
		Commits:          commits,
		HeadCommit:       head,
		RequestedCommits: 1,
		EvaluatedCommits: 1,
		ReachedRoot:      true,
		HistoryAvailable: true,
	})
	if err != nil {
		t.Fatalf("BuildBehavioralHotspots: %v", err)
	}

	if rep.Availability != BehavioralPartial {
		t.Fatalf("want partial availability, got %s", rep.Availability)
	}
	if len(rep.Files) != 1 || rep.Files[0].Path != "pkg/a.go" {
		t.Fatalf("expected 1 measured file pkg/a.go, got %+v", rep.Files)
	}
	if len(rep.Gaps) != 1 || rep.Gaps[0].Path != "pkg/unsupported.xyz" {
		t.Fatalf("expected gap for unsupported.xyz, got %+v", rep.Gaps)
	}

	// Legacy complexity report without Files coverage
	compLegacy := &ComplexityReport{
		Functions: []FunctionComplexity{
			{File: "pkg/a.go", Cyclomatic: 5},
		},
	}
	repLegacy, err := BuildBehavioralHotspots(BuildBehavioralHotspotsInput{
		Inventory:        inv,
		Complexity:       compLegacy,
		Commits:          commits,
		HeadCommit:       head,
		RequestedCommits: 1,
		EvaluatedCommits: 1,
		ReachedRoot:      true,
		HistoryAvailable: true,
	})
	if err != nil {
		t.Fatalf("BuildBehavioralHotspots: %v", err)
	}
	if repLegacy.Availability != BehavioralUnavailable {
		t.Fatalf("legacy comp without coverage must be unavailable, got %s", repLegacy.Availability)
	}
}

func TestBehavioralHotspotsReport_Validation(t *testing.T) {
	// Score overflow test
	bad := BehavioralHotspotsReport{
		Version:          BehavioralHotspotsSchemaVersion,
		Availability:     BehavioralComplete,
		HeadCommit:       strings.Repeat("f", 40),
		RequestedCommits: 1,
		EvaluatedCommits: 1,
		Files: []BehavioralFile{
			{Path: "overflow.go", Cyclomatic: 1_000_000, ChangeCount: 3000, Score: 300}, // score mismatch
		},
		TotalMeasured: 1,
	}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected validation error for score mismatch")
	}

	// Duplicate path test
	dup := BehavioralHotspotsReport{
		Version:          BehavioralHotspotsSchemaVersion,
		Availability:     BehavioralComplete,
		HeadCommit:       strings.Repeat("f", 40),
		RequestedCommits: 1,
		EvaluatedCommits: 1,
		Files: []BehavioralFile{
			{Path: "a.go", Cyclomatic: 10, ChangeCount: 1, Score: 10},
			{Path: "a.go", Cyclomatic: 10, ChangeCount: 1, Score: 10},
		},
		TotalMeasured: 2,
	}
	if err := dup.Validate(); err == nil {
		t.Fatal("expected validation error for duplicate path")
	}
}

func TestBehavioralHotspotsReport_RejectsMalformedComplexityEvidence(t *testing.T) {
	inv := Inventory{
		Files: []FileInventory{
			{Path: "a.go", Language: "Go"},
		},
	}
	comp := &ComplexityReport{
		Version: ComplexitySchemaVersion,
		Files: []ComplexityFileCoverage{
			{File: "a.go", Language: "Go", Supported: true, Parsed: true},
			{File: "../escape.go", Language: "Go", Supported: true, Parsed: true},
		},
		Functions: []FunctionComplexity{
			{File: "a.go", Cyclomatic: 5},
		},
	}
	head := strings.Repeat("a", 40)
	_, err := BuildBehavioralHotspots(BuildBehavioralHotspotsInput{
		Inventory:        inv,
		Complexity:       comp,
		Commits:          []BehavioralCommitEvidence{{CommitID: head, TouchedPaths: []string{"a.go"}}},
		HeadCommit:       head,
		RequestedCommits: 1,
		EvaluatedCommits: 1,
		ReachedRoot:      true,
		HistoryAvailable: true,
	})
	if err == nil {
		t.Fatal("expected error on malformed complexity evidence, got nil")
	}
}
