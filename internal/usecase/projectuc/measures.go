package projectuc

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rating"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var validDomains = map[string]bool{
	"size":        true,
	"complexity":  true,
	"coverage":    true,
	"duplication": true,
	"issues":      true,
	"debt":        true,
	"ratings":     true,
}

// GetMeasures retrieves the measure node and its direct children for a specific path.
func (s *Service) GetMeasures(ctx context.Context, tenantID, projectKey, path string, domains []string, limit int, cursorStr string) (ProjectMeasureResponse, error) {
	if s.cursorSecret == nil {
		return ProjectMeasureResponse{}, fmt.Errorf("measure cursor signing key is not configured")
	}
	if limit < 1 || limit > 200 {
		return ProjectMeasureResponse{}, fmt.Errorf("%w: limit must be between 1 and 200", shared.ErrValidation)
	}

	p, err := s.repo.GetByKey(ctx, shared.ID(tenantID), strings.TrimSpace(projectKey))
	if err != nil {
		return ProjectMeasureResponse{}, err // handles ErrNotFound
	}

	// Normalize domains
	domainMap := make(map[string]bool)
	var normalizedDomains []string
	if len(domains) == 0 {
		// All domains
		for d := range validDomains {
			domainMap[d] = true
		}
		// Canonical order
		normalizedDomains = []string{"size", "complexity", "coverage", "duplication", "issues", "debt", "ratings"}
	} else {
		for _, d := range domains {
			if !validDomains[d] {
				return ProjectMeasureResponse{}, fmt.Errorf("%w: invalid domain %q", shared.ErrValidation, d)
			}
			domainMap[d] = true
		}
		// Deterministic canonical order
		for _, d := range []string{"size", "complexity", "coverage", "duplication", "issues", "debt", "ratings"} {
			if domainMap[d] {
				normalizedDomains = append(normalizedDomains, d)
			}
		}
	}

	canonicalPath, err := measure.CanonicalPath(path)
	if err != nil || canonicalPath != path {
		return ProjectMeasureResponse{}, fmt.Errorf("%w: invalid canonical path", shared.ErrValidation)
	}

	var analysis *projectanalysis.Analysis

	cursor, err := DecodeMeasureCursor(cursorStr, s.cursorSecret)
	if err != nil {
		return ProjectMeasureResponse{}, fmt.Errorf("%w: %v", shared.ErrValidation, err)
	}

	if cursor != nil {
		if cursor.Path != path {
			// Do not disclose analysis existence by returning shared.ErrNotFound or similar early.
			return ProjectMeasureResponse{}, fmt.Errorf("%w: cursor mismatch", shared.ErrValidation)
		}
		a, err := s.analyses.Get(ctx, p.TenantID, p.ID, shared.ID(cursor.AnalysisID))
		if err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				return ProjectMeasureResponse{}, fmt.Errorf("%w: cursor analysis not found", shared.ErrValidation)
			}
			return ProjectMeasureResponse{}, err
		}
		analysis = &a
	} else {
		analyses, _, err := s.analyses.List(ctx, p.TenantID, p.ID, 1, time.Time{}, "")
		if err != nil {
			return ProjectMeasureResponse{}, err
		}
		if len(analyses) == 0 {
			// No-analysis semantics
			return ProjectMeasureResponse{
				State: "not_analyzed",
				Project: ProjectNodeInfo{
					Key:  p.Key,
					Name: p.Name,
				},
				Analysis:        nil,
				Path:            path,
				IncludedDomains: normalizedDomains,
				Node:            nil,
				Children: ChildCollection{
					Items:      []MeasureNode{},
					NextCursor: nil,
				},
			}, nil
		}
		analysis = &analyses[0]
	}

	if err := analysis.Snapshot.Validate(); err != nil {
		return ProjectMeasureResponse{}, err // Fail closed on corrupt snapshot
	}

	validateGrade := func(g rating.Grade) error {
		if g == "" || g == "A" || g == "B" || g == "C" || g == "D" || g == "E" {
			return nil
		}
		return fmt.Errorf("corrupt rating: %q", g)
	}
	if err := validateGrade(analysis.Rating.Security); err != nil {
		return ProjectMeasureResponse{}, err
	}
	if err := validateGrade(analysis.Rating.Reliability); err != nil {
		return ProjectMeasureResponse{}, err
	}
	if err := validateGrade(analysis.Rating.Maintainability); err != nil {
		return ProjectMeasureResponse{}, err
	}

	var targetNode *measure.Node
	var allChildren []measure.Node

	for i := range analysis.Snapshot.Nodes {
		n := &analysis.Snapshot.Nodes[i]
		if n.Path == path {
			targetNode = n
		} else if n.Parent == path && n.Path != path {
			allChildren = append(allChildren, *n)
		}
	}

	if targetNode == nil {
		if cursor != nil {
			return ProjectMeasureResponse{}, fmt.Errorf("%w: cursor mismatch", shared.ErrValidation)
		}
		return ProjectMeasureResponse{}, shared.ErrNotFound
	}

	// Sort function
	childLess := func(a, b *measure.Node) bool {
		aRank := 2
		if a.Kind == measure.NodeDirectory {
			aRank = 1
		}
		bRank := 2
		if b.Kind == measure.NodeDirectory {
			bRank = 1
		}
		if aRank != bRank {
			return aRank < bRank
		}
		return a.Path < b.Path
	}

	sort.Slice(allChildren, func(i, j int) bool {
		return childLess(&allChildren[i], &allChildren[j])
	})

	var paginatedChildren []MeasureNode
	var lastChildPath string
	var lastChildRank int
	count := 0

	// Check if cursor continuation key corresponds to a direct child
	if cursor != nil && cursor.LastChildPath != "" {
		foundCursor := false
		for _, child := range allChildren {
			childRank := 2
			if child.Kind == measure.NodeDirectory {
				childRank = 1
			}
			if childRank == cursor.LastKindRank && child.Path == cursor.LastChildPath {
				foundCursor = true
				break
			}
		}
		if !foundCursor {
			return ProjectMeasureResponse{}, fmt.Errorf("%w: cursor mismatch", shared.ErrValidation)
		}
	}

	for _, child := range allChildren {
		childRank := 2
		if child.Kind == measure.NodeDirectory {
			childRank = 1
		}

		if cursor != nil && cursor.LastChildPath != "" {
			// Skip if this child is <= cursor
			if childRank < cursor.LastKindRank || (childRank == cursor.LastKindRank && child.Path <= cursor.LastChildPath) {
				continue
			}
		}

		if count >= limit {
			break
		}
		paginatedChildren = append(paginatedChildren, *mapDomainMeasures(&child, domainMap, analysis))
		lastChildPath = child.Path
		lastChildRank = childRank
		count++
	}

	if paginatedChildren == nil {
		paginatedChildren = []MeasureNode{}
	}

	var nextCursorStr *string
	if count == limit {
		// Check if there are more
		hasMore := false
		for _, child := range allChildren {
			childRank := 2
			if child.Kind == measure.NodeDirectory {
				childRank = 1
			}
			if childRank > lastChildRank || (childRank == lastChildRank && child.Path > lastChildPath) {
				hasMore = true
				break
			}
		}
		if hasMore {
			nextCursor := MeasureCursor{
				Version:       1,
				AnalysisID:    string(analysis.ID),
				Path:          path,
				LastKindRank:  lastChildRank,
				LastChildPath: lastChildPath,
			}
			enc := nextCursor.Encode(s.cursorSecret)
			nextCursorStr = &enc
		}
	}

	analysisMeta := &AnalysisMetadata{
		ID:           string(analysis.ID),
		CreatedAt:    analysis.CreatedAt,
		SourceRef:    analysis.SourceRef,
		SourceCommit: analysis.SourceCommit,
	}

	return ProjectMeasureResponse{
		State: "analyzed",
		Project: ProjectNodeInfo{
			Key:  p.Key,
			Name: p.Name,
		},
		Analysis:        analysisMeta,
		Path:            path,
		IncludedDomains: normalizedDomains,
		Node:            mapDomainMeasures(targetNode, domainMap, analysis),
		Children: ChildCollection{
			Items:      paginatedChildren,
			NextCursor: nextCursorStr,
		},
	}, nil
}

func toPtr(s string) *string { return &s }

func toAvailability(available bool, reason string) (MeasureAvailabilityState, *string) {
	if available {
		return AvailabilityAvailable, nil
	}
	return AvailabilityUnavailable, &reason
}

func toCount(val int, avail MeasureAvailabilityState, reason *string) MeasureCountMetric {
	if avail == AvailabilityAvailable {
		return MeasureCountMetric{Availability: avail, Value: &val, Reason: nil}
	}
	return MeasureCountMetric{Availability: avail, Value: nil, Reason: reason}
}

func toDecimal(m measure.DecimalMetric) MeasureDecimalMetric {
	if m.Availability == measure.AvailabilityAvailable {
		return MeasureDecimalMetric{Availability: AvailabilityAvailable, Value: m.Value, Reason: nil}
	}

	avail := AvailabilityUnavailable

	var reason *string
	if m.Reason != "" {
		reason = &m.Reason
	} else if avail == AvailabilityUnavailable {
		r := "legacy_analysis"
		reason = &r
	}
	return MeasureDecimalMetric{Availability: avail, Value: nil, Reason: reason}
}

func mapDomainMeasures(n *measure.Node, domains map[string]bool, analysis *projectanalysis.Analysis) *MeasureNode {
	snap := analysis.Snapshot
	mn := &MeasureNode{
		Path:     n.Path,
		Name:     n.Name,
		Kind:     n.Kind,
		Language: n.Language,
	}

	if domains["size"] {
		fnAvail, fnReason := toAvailability(n.FunctionsKnown, "function_count_not_available")
		cdDec := toDecimal(n.CommentDensity())
		if cdDec.Availability == AvailabilityUnavailable && (n.Counters.CodeLines+n.Counters.CommentLines) == 0 {
			r := "no_commentable_lines"
			cdDec.Reason = &r
		}

		mn.Size = &SizeMeasures{
			Files:          toCount(n.Counters.Files, AvailabilityAvailable, nil),
			NCLOC:          toCount(n.Counters.CodeLines, AvailabilityAvailable, nil),
			CommentLines:   toCount(n.Counters.CommentLines, AvailabilityAvailable, nil),
			BlankLines:     toCount(n.Counters.BlankLines, AvailabilityAvailable, nil),
			Functions:      toCount(n.Counters.Functions, fnAvail, fnReason),
			CommentDensity: cdDec,
		}
	}
	if domains["complexity"] {
		cxAvail, cxReason := toAvailability(n.ComplexityAvailable, "complexity_not_available")
		mn.Complexity = &ComplexityMeasures{
			Cyclomatic: toCount(n.Counters.Cyclomatic, cxAvail, cxReason),
			Cognitive:  toCount(n.Counters.Cognitive, cxAvail, cxReason),
		}
	}
	if domains["coverage"] {
		newCodeCov := MeasureDecimalMetric{Availability: AvailabilityNotApplicable, Reason: nil}
		if n.Kind == measure.NodeProject {
			if snap.NewCodeCoverage.Availability == measure.AvailabilityAvailable {
				newCodeCov = MeasureDecimalMetric{Availability: AvailabilityAvailable, Value: snap.NewCodeCoverage.Value, Reason: nil}
			} else {
				reason := "changed_line_coverage_not_available"
				newCodeCov = MeasureDecimalMetric{Availability: AvailabilityUnavailable, Value: nil, Reason: &reason}
			}
		}

		// Distinguish coverage analyzer absence vs zero executable lines
		covReasonStr := "coverage_not_supplied"
		if analysis.Coverage != nil && n.Counters.CoverableLines == 0 {
			covReasonStr = "no_executable_lines"
		}
		cvAvail, cvReason := toAvailability(n.CoverageAvailable, covReasonStr)
		coverageDec := toDecimal(n.Coverage())
		if n.CoverageAvailable && n.Counters.CoverableLines == 0 {
			coverageDec.Availability = AvailabilityUnavailable
			r := "no_executable_lines"
			coverageDec.Reason = &r
		} else if coverageDec.Availability == AvailabilityUnavailable {
			coverageDec.Reason = cvReason
		}

		mn.Coverage = &CoverageMeasures{
			CoveredLines:    toCount(n.Counters.CoveredLines, cvAvail, cvReason),
			CoverableLines:  toCount(n.Counters.CoverableLines, cvAvail, cvReason),
			Coverage:        coverageDec,
			NewCodeCoverage: newCodeCov,
		}
	}
	if domains["duplication"] {
		dpAvail, dpReason := toAvailability(n.DuplicationAvailable, "duplication_not_available")
		dupDec := toDecimal(n.DuplicationDensity())
		if dupDec.Availability == AvailabilityUnavailable {
			dupDec.Reason = dpReason
		}
		mn.Duplication = &DuplicationMeasures{
			DuplicatedLines:    toCount(n.Counters.DuplicatedLines, dpAvail, dpReason),
			DuplicationBlocks:  toCount(n.Counters.DuplicationBlocks, dpAvail, dpReason),
			DuplicationDensity: dupDec,
		}
	}
	if domains["issues"] {
		mn.Issues = &IssueMeasures{
			ByType:     map[string]MeasureCountMetric{},
			BySeverity: map[string]MeasureCountMetric{},
		}

		typeAvail, typeReason := toAvailability(n.IssueTypeAvailable, "issue_type_incomplete")
		sevAvail, sevReason := toAvailability(true, "") // Severity is always available at root

		if n.Kind != measure.NodeProject {
			typeAvail, typeReason = toAvailability(n.IssueTypeAvailable && n.AttributionAvailable, "issue_attribution_incomplete")
			if !n.AttributionAvailable {
				typeAvail, typeReason = toAvailability(false, "issue_attribution_incomplete")
			}
			sevAvail, sevReason = toAvailability(n.AttributionAvailable, "issue_attribution_incomplete")
		}

		for _, k := range []string{"code_smell", "bug", "vulnerability", "security_hotspot"} {
			mn.Issues.ByType[k] = toCount(n.Counters.IssuesByType[k], typeAvail, typeReason)
		}
		for _, k := range []string{"info", "low", "medium", "high", "critical"} {
			mn.Issues.BySeverity[k] = toCount(n.Counters.IssuesBySeverity[k], sevAvail, sevReason)
		}
	}
	if domains["debt"] {
		avail, reason := toAvailability(n.TechDebtAvailable, "technical_debt_incomplete")
		if n.Kind != measure.NodeProject && !n.AttributionAvailable {
			avail, reason = toAvailability(false, "issue_attribution_incomplete")
		}
		mn.Debt = &DebtMeasures{
			RemediationEffortMinutes: toCount(n.Counters.RemediationEffortMinutes, avail, reason),
		}
	}
	if domains["ratings"] {
		if n.Kind == measure.NodeProject {
			mn.Ratings = &RatingsMeasures{
				Security:        MeasureGradeMetric{Availability: AvailabilityAvailable, Grade: toPtr(string(analysis.Rating.Security)), Reason: nil},
				Reliability:     MeasureGradeMetric{Availability: AvailabilityAvailable, Grade: toPtr(string(analysis.Rating.Reliability)), Reason: nil},
				Maintainability: MeasureGradeMetric{Availability: AvailabilityAvailable, Grade: toPtr(string(analysis.Rating.Maintainability)), Reason: nil},
			}
			if analysis.Rating.Security == "" {
				mn.Ratings.Security = MeasureGradeMetric{Availability: AvailabilityUnavailable, Reason: toPtr("rating_not_available")}
			}
			if analysis.Rating.Reliability == "" {
				mn.Ratings.Reliability = MeasureGradeMetric{Availability: AvailabilityUnavailable, Reason: toPtr("rating_not_available")}
			}
			if analysis.Rating.Maintainability == "" {
				mn.Ratings.Maintainability = MeasureGradeMetric{Availability: AvailabilityUnavailable, Reason: toPtr("rating_not_available")}
			}
		} else {
			mn.Ratings = &RatingsMeasures{
				Security:        MeasureGradeMetric{Availability: AvailabilityNotApplicable, Reason: nil},
				Reliability:     MeasureGradeMetric{Availability: AvailabilityNotApplicable, Reason: nil},
				Maintainability: MeasureGradeMetric{Availability: AvailabilityNotApplicable, Reason: nil},
			}
		}
	}
	return mn
}
