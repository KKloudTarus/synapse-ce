package measure

import (
	"errors"
	"fmt"
	"math"
	"path"
)

// Validate enforces snapshot constraints to fail-closed on corrupt states.
func (s Snapshot) Validate() error {
	nodesByPath := make(map[string]*Node, len(s.Nodes))
	var root *Node

	for i := range s.Nodes {
		n := &s.Nodes[i]

		// Unique canonical paths
		if _, exists := nodesByPath[n.Path]; exists {
			return errors.New("measure snapshot: duplicate canonical path: " + n.Path)
		}

		// Canonical check
		if n.Path != "" {
			canonical, err := CanonicalPath(n.Path)
			if err != nil || canonical != n.Path {
				return fmt.Errorf("measure snapshot: path is not canonical: %q", n.Path)
			}
			if n.Parent != "" {
				parentCanonical, err := CanonicalPath(n.Parent)
				if err != nil || parentCanonical != n.Parent {
					return fmt.Errorf("measure snapshot: parent is not canonical: %q", n.Parent)
				}
			}
		}

		nodesByPath[n.Path] = n

		if n.Path == "" {
			if root != nil {
				return errors.New("measure snapshot: multiple roots found")
			}
			root = n
		}
	}

	if root == nil {
		return errors.New("measure snapshot: exactly one root node is required, got 0")
	}

	if root.Kind != NodeProject || root.Parent != "" {
		return errors.New("measure snapshot: root must be project kind with empty parent")
	}

	for i := range s.Nodes {
		n := &s.Nodes[i]

		if n.Path != "" && n.Kind == NodeProject {
			return fmt.Errorf("measure snapshot: non-root project node found: %q", n.Path)
		}

		if n.Path != "" {
			if _, exists := nodesByPath[n.Parent]; !exists {
				return fmt.Errorf("measure snapshot: missing parent %q for node %q", n.Parent, n.Path)
			}
			if n.Path == n.Parent {
				return fmt.Errorf("measure snapshot: self-referential node %q", n.Path)
			}

			// Parent must be canonical immediate directory
			expectedParent := path.Dir(n.Path)
			if expectedParent == "." {
				expectedParent = ""
			}
			if n.Parent != expectedParent {
				return fmt.Errorf("measure snapshot: parent %q is not immediate directory of %q", n.Parent, n.Path)
			}
		}

		if n.Kind != NodeProject && n.Kind != NodeDirectory && n.Kind != NodeFile {
			return fmt.Errorf("measure snapshot: invalid kind %q for node %q", n.Kind, n.Path)
		}

		if n.Counters.Files < 0 || n.Counters.Functions < 0 || n.Counters.CodeLines < 0 || n.Counters.CommentLines < 0 || n.Counters.BlankLines < 0 ||
			n.Counters.Cyclomatic < 0 || n.Counters.Cognitive < 0 || n.Counters.CoveredLines < 0 || n.Counters.CoverableLines < 0 ||
			n.Counters.DuplicatedLines < 0 || n.Counters.DuplicationBlocks < 0 || n.Counters.RemediationEffortMinutes < 0 {
			return fmt.Errorf("measure snapshot: negative counter found in node %q", n.Path)
		}

		if n.Counters.CoveredLines > n.Counters.CoverableLines {
			return fmt.Errorf("measure snapshot: covered lines > coverable lines in node %q", n.Path)
		}

		if n.Counters.DuplicatedLines > n.Counters.CodeLines {
			return fmt.Errorf("measure snapshot: duplicated lines > ncloc in node %q", n.Path)
		}

		for k, v := range n.Counters.IssuesByType {
			if k != "code_smell" && k != "bug" && k != "vulnerability" && k != "security_hotspot" {
				return fmt.Errorf("measure snapshot: unsupported issue key %q in node %q", k, n.Path)
			}
			if v < 0 {
				return fmt.Errorf("measure snapshot: negative issue counter for type %q in node %q", k, n.Path)
			}
		}
		for k, v := range n.Counters.IssuesBySeverity {
			if k != "info" && k != "low" && k != "medium" && k != "high" && k != "critical" {
				return fmt.Errorf("measure snapshot: unsupported severity key %q in node %q", k, n.Path)
			}
			if v < 0 {
				return fmt.Errorf("measure snapshot: negative issue counter for severity %q in node %q", k, n.Path)
			}
		}

		cd := n.CommentDensity()
		if cd.Availability == AvailabilityAvailable {
			if cd.Value == nil {
				return fmt.Errorf("measure snapshot: available comment density has null value in node %q", n.Path)
			}
			if math.IsNaN(*cd.Value) || math.IsInf(*cd.Value, 0) || *cd.Value < 0 || *cd.Value > 100.0 {
				return fmt.Errorf("measure snapshot: comment density out of bounds in node %q", n.Path)
			}
		} else if cd.Value != nil {
			return fmt.Errorf("measure snapshot: unavailable comment density has non-null value in node %q", n.Path)
		}

		cov := n.Coverage()
		if cov.Availability == AvailabilityAvailable {
			if cov.Value == nil {
				return fmt.Errorf("measure snapshot: available coverage has null value in node %q", n.Path)
			}
			if math.IsNaN(*cov.Value) || math.IsInf(*cov.Value, 0) || *cov.Value < 0 || *cov.Value > 100.0 {
				return fmt.Errorf("measure snapshot: coverage out of bounds in node %q", n.Path)
			}
		} else if cov.Value != nil {
			return fmt.Errorf("measure snapshot: unavailable coverage has non-null value in node %q", n.Path)
		}

		dup := n.DuplicationDensity()
		if dup.Availability == AvailabilityAvailable {
			if dup.Value == nil {
				return fmt.Errorf("measure snapshot: available duplication density has null value in node %q", n.Path)
			}
			if math.IsNaN(*dup.Value) || math.IsInf(*dup.Value, 0) || *dup.Value < 0 || *dup.Value > 100.0 {
				return fmt.Errorf("measure snapshot: duplication density out of bounds in node %q", n.Path)
			}
		} else if dup.Value != nil {
			return fmt.Errorf("measure snapshot: unavailable duplication density has non-null value in node %q", n.Path)
		}
	}

	// Cycle detection and File children check
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if n.Kind == NodeFile {
			for j := range s.Nodes {
				if s.Nodes[j].Parent == n.Path && s.Nodes[j].Path != n.Path {
					return fmt.Errorf("measure snapshot: file %q cannot have children", n.Path)
				}
			}
		}
		// Cycle check
		visited := make(map[string]bool)
		curr := n.Path
		for curr != "" {
			if visited[curr] {
				return fmt.Errorf("measure snapshot: cycle detected involving %q", curr)
			}
			visited[curr] = true
			parent := nodesByPath[curr].Parent
			curr = parent
		}
	}

	// validAvailability is the closed set of supported Availability values.
	// An empty string is the zero-value default and is treated as AvailabilityUnavailable.
	validAvailability := map[Availability]bool{
		AvailabilityAvailable:   true,
		AvailabilityUnavailable: true,
		"":                      true, // zero-value treated as unavailable
	}

	if !validAvailability[s.NewCodeCoverage.Availability] {
		return fmt.Errorf("measure snapshot: invalid new_code_coverage availability %q", s.NewCodeCoverage.Availability)
	}
	if s.NewCodeCoverage.Availability == AvailabilityAvailable {
		if s.NewCodeCoverage.Value == nil {
			return errors.New("measure snapshot: available new code coverage has null value")
		}
		if math.IsNaN(*s.NewCodeCoverage.Value) || math.IsInf(*s.NewCodeCoverage.Value, 0) || *s.NewCodeCoverage.Value < 0 || *s.NewCodeCoverage.Value > 100.0 {
			return errors.New("measure snapshot: new code coverage out of bounds")
		}
	} else if s.NewCodeCoverage.Value != nil {
		return errors.New("measure snapshot: unavailable new code coverage has non-null value")
	}

	return nil
}
