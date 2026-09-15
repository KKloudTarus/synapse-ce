package measure

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
)

const (
	BehavioralHotspotsSchemaVersion = 1
	maxBehavioralCommits             = 2048
	maxBehavioralFiles               = 50_000
	maxBehavioralTouches             = 250_000
)

// BehavioralAvailability distinguishes complete, partial, and unavailable reports.
type BehavioralAvailability string

const (
	BehavioralComplete    BehavioralAvailability = "complete"
	BehavioralPartial     BehavioralAvailability = "partial"
	BehavioralUnavailable BehavioralAvailability = "unavailable"
)

// BehavioralFile represents one ranked source file.
type BehavioralFile struct {
	Path        string `json:"path"`
	Language    string `json:"language,omitempty"`
	Cyclomatic  int    `json:"cyclomatic"`
	ChangeCount int    `json:"change_count"`
	Score       int    `json:"score"`
}

// BehavioralCommitEvidence captures one evaluated first-parent commit and its touched files.
type BehavioralCommitEvidence struct {
	CommitID      string   `json:"commit_id"`
	FirstParentID string   `json:"first_parent_id,omitempty"`
	TouchedPaths  []string `json:"touched_paths,omitempty"`
}

// BehavioralGap documents why a file or scope could not be measured.
type BehavioralGap struct {
	Path   string `json:"path,omitempty"`
	Reason string `json:"reason"`
}

// BehavioralHotspotsReport is the immutable domain evidence for behavioral hotspots.
type BehavioralHotspotsReport struct {
	Version          int                        `json:"version"`
	Availability     BehavioralAvailability     `json:"availability"`
	Reason           string                     `json:"reason,omitempty"`
	HeadCommit       string                     `json:"head_commit,omitempty"`
	RequestedCommits int                        `json:"requested_commits"`
	EvaluatedCommits int                        `json:"evaluated_commits"`
	ReachedRoot      bool                       `json:"reached_root"`
	Commits          []BehavioralCommitEvidence `json:"commits,omitempty"`
	Files            []BehavioralFile           `json:"files,omitempty"`
	TotalEligible    int                        `json:"total_eligible"`
	TotalMeasured    int                        `json:"total_measured"`
	Gaps             []BehavioralGap            `json:"gaps,omitempty"`
}

// BehavioralMetrics provides measure tree node metrics.
type BehavioralMetrics struct {
	CyclomaticSum CountMetric `json:"cyclomatic_sum"`
	ChangeCount   CountMetric `json:"change_count"`
	Score         CountMetric `json:"score"`
}

// BuildBehavioralHotspotsInput is the input to BuildBehavioralHotspots.
type BuildBehavioralHotspotsInput struct {
	Inventory        Inventory
	Complexity       *ComplexityReport
	Commits          []BehavioralCommitEvidence
	HeadCommit       string
	RequestedCommits int
	EvaluatedCommits int
	ReachedRoot      bool
	HistoryAvailable bool
	HistoryReason    string
}

// BuildBehavioralHotspots constructs and validates a deterministic BehavioralHotspotsReport.
func BuildBehavioralHotspots(in BuildBehavioralHotspotsInput) (BehavioralHotspotsReport, error) {
	rep := BehavioralHotspotsReport{
		Version:          BehavioralHotspotsSchemaVersion,
		HeadCommit:       strings.TrimSpace(in.HeadCommit),
		RequestedCommits: in.RequestedCommits,
		EvaluatedCommits: in.EvaluatedCommits,
		ReachedRoot:      in.ReachedRoot,
		Commits:          make([]BehavioralCommitEvidence, 0, len(in.Commits)),
		Files:            []BehavioralFile{},
		Gaps:             []BehavioralGap{},
	}
	if in.RequestedCommits < 0 || in.RequestedCommits > maxBehavioralCommits || in.EvaluatedCommits < 0 || in.EvaluatedCommits > in.RequestedCommits {
		return BehavioralHotspotsReport{}, errors.New("behavioral hotspots: invalid commit window counts")
	}
	if len(in.Inventory.Files) > maxBehavioralFiles {
		rep.Availability = BehavioralUnavailable
		rep.Reason = "file_budget_exceeded"
		if err := rep.Validate(); err != nil {
			return BehavioralHotspotsReport{}, err
		}
		return rep, nil
	}

	// 1. If history is unavailable, fail closed to unavailable report
	if !in.HistoryAvailable {
		rep.Availability = BehavioralUnavailable
		rep.Reason = in.HistoryReason
		if rep.Reason == "" {
			rep.Reason = "history_unavailable"
		}
		if err := rep.Validate(); err != nil {
			return BehavioralHotspotsReport{}, err
		}
		return rep, nil
	}

	// Sanitize and copy commit evidence
	if in.EvaluatedCommits != len(in.Commits) {
		return BehavioralHotspotsReport{}, errors.New("behavioral hotspots: evaluated commits mismatch")
	}
	seenCommits := make(map[string]bool, len(in.Commits))
	commitTouchCount := make(map[string]int) // path -> distinct commits touching it
	totalTouches := 0
	for _, c := range in.Commits {
		cID := strings.TrimSpace(c.CommitID)
		if !isValidCommitHash(cID) {
			return BehavioralHotspotsReport{}, fmt.Errorf("behavioral hotspots: invalid commit id %q", c.CommitID)
		}
		if seenCommits[cID] {
			return BehavioralHotspotsReport{}, fmt.Errorf("behavioral hotspots: duplicate commit id %q", cID)
		}
		seenCommits[cID] = true

		pID := strings.TrimSpace(c.FirstParentID)
		seenPathsInCommit := make(map[string]bool, len(c.TouchedPaths))
		var touched []string
		for _, rawPath := range c.TouchedPaths {
			canon, err := CanonicalPath(rawPath)
			if err != nil || canon == "" || canon != rawPath {
				return BehavioralHotspotsReport{}, fmt.Errorf("behavioral hotspots: invalid touched path %q", rawPath)
			}
			if seenPathsInCommit[canon] {
				return BehavioralHotspotsReport{}, fmt.Errorf("behavioral hotspots: duplicate touched path %q", canon)
			}
			seenPathsInCommit[canon] = true
			touched = append(touched, canon)
			commitTouchCount[canon]++
			totalTouches++
			if totalTouches > maxBehavioralTouches {
				return BehavioralHotspotsReport{}, errors.New("behavioral hotspots: touch budget exceeded")
			}
		}
		sort.Strings(touched)
		rep.Commits = append(rep.Commits, BehavioralCommitEvidence{
			CommitID:      cID,
			FirstParentID: pID,
			TouchedPaths:  touched,
		})
	}

	// 2. Iterate eligible files from Inventory
	// An eligible file is a tracked regular source file in inventory.
	var gaps []BehavioralGap
	var files []BehavioralFile

	seenInventory := make(map[string]bool, len(in.Inventory.Files))
	for _, f := range in.Inventory.Files {
		canon, err := CanonicalPath(f.Path)
		if err != nil || canon == "" || canon != f.Path {
			return BehavioralHotspotsReport{}, fmt.Errorf("behavioral hotspots: invalid inventory path %q", f.Path)
		}
		if seenInventory[canon] {
			return BehavioralHotspotsReport{}, fmt.Errorf("behavioral hotspots: duplicate inventory path %q", canon)
		}
		seenInventory[canon] = true
		rep.TotalEligible++

		// Check complexity
		if in.Complexity == nil {
			gaps = append(gaps, BehavioralGap{
				Path:   canon,
				Reason: "complexity_not_available",
			})
			continue
		}

		cycSum, measured := in.Complexity.FileCyclomatic(canon)
		if !measured {
			gaps = append(gaps, BehavioralGap{
				Path:   canon,
				Reason: "complexity_not_measured",
			})
			continue
		}

		changes := commitTouchCount[canon]
		// Integer overflow safe calculation
		if int64(cycSum)*int64(changes) > math.MaxInt32 {
			return BehavioralHotspotsReport{}, fmt.Errorf("behavioral score overflow for %q: %d * %d", canon, cycSum, changes)
		}
		score := cycSum * changes

		files = append(files, BehavioralFile{
			Path:        canon,
			Language:    f.Language,
			Cyclomatic:  cycSum,
			ChangeCount: changes,
			Score:       score,
		})
	}

	// Sort files deterministically:
	// score DESC, then change_count DESC, then cyclomatic DESC, then path ASC (byte-wise)
	sort.Slice(files, func(i, j int) bool {
		if files[i].Score != files[j].Score {
			return files[i].Score > files[j].Score
		}
		if files[i].ChangeCount != files[j].ChangeCount {
			return files[i].ChangeCount > files[j].ChangeCount
		}
		if files[i].Cyclomatic != files[j].Cyclomatic {
			return files[i].Cyclomatic > files[j].Cyclomatic
		}
		return files[i].Path < files[j].Path
	})

	// Sort gaps deterministically:
	sort.Slice(gaps, func(i, j int) bool {
		if gaps[i].Path != gaps[j].Path {
			return gaps[i].Path < gaps[j].Path
		}
		return gaps[i].Reason < gaps[j].Reason
	})

	rep.Files = files
	rep.Gaps = gaps
	rep.TotalMeasured = len(files)

	if rep.TotalEligible == 0 || rep.TotalMeasured == 0 {
		rep.Availability = BehavioralUnavailable
		rep.Reason = "no_supported_files_measured"
	} else if len(gaps) == 0 {
		rep.Availability = BehavioralComplete
	} else {
		rep.Availability = BehavioralPartial
		rep.Reason = fmt.Sprintf("%d_of_%d_files_unmeasured", len(gaps), rep.TotalEligible)
	}

	if err := rep.Validate(); err != nil {
		return BehavioralHotspotsReport{}, err
	}
	return rep, nil
}

// Validate ensures all invariants, bounds and ordering hold.
func (r BehavioralHotspotsReport) Validate() error {
	if r.Version != BehavioralHotspotsSchemaVersion {
		return fmt.Errorf("behavioral hotspots: unsupported version %d", r.Version)
	}
	if len(r.Commits) > maxBehavioralCommits || len(r.Files) > maxBehavioralFiles || len(r.Gaps) > maxBehavioralFiles {
		return errors.New("behavioral hotspots: evidence limit exceeded")
	}
	if r.RequestedCommits < 0 || r.RequestedCommits > maxBehavioralCommits || r.EvaluatedCommits < 0 || r.EvaluatedCommits > r.RequestedCommits {
		return errors.New("behavioral hotspots: invalid commit window counts")
	}

	switch r.Availability {
	case BehavioralComplete, BehavioralPartial:
		if !isValidCommitHash(r.HeadCommit) {
			return fmt.Errorf("behavioral hotspots: invalid head commit %q", r.HeadCommit)
		}
		if r.EvaluatedCommits == 0 {
			return errors.New("behavioral hotspots: evaluated commits must be positive when available")
		}
		if r.TotalMeasured != len(r.Files) {
			return errors.New("behavioral hotspots: total measured mismatch")
		}
		if len(r.Commits) == 0 || r.Commits[0].CommitID != r.HeadCommit {
			return errors.New("behavioral hotspots: head commit does not match evidence")
		}
		if r.Availability == BehavioralComplete && (len(r.Gaps) != 0 || r.TotalEligible != len(r.Files) || r.Reason != "") {
			return errors.New("behavioral hotspots: inconsistent complete coverage")
		}
		if r.Availability == BehavioralPartial && (len(r.Gaps) == 0 || r.TotalEligible != len(r.Files)+len(r.Gaps) || strings.TrimSpace(r.Reason) == "") {
			return errors.New("behavioral hotspots: inconsistent partial coverage")
		}
	case BehavioralUnavailable:
		// Reason must not be empty
		if strings.TrimSpace(r.Reason) == "" {
			return errors.New("behavioral hotspots: unavailable report requires a reason")
		}
		if len(r.Files) != 0 || r.TotalMeasured != 0 {
			return errors.New("behavioral hotspots: unavailable report cannot contain ranked files")
		}
	default:
		return fmt.Errorf("behavioral hotspots: unknown availability %q", r.Availability)
	}

	// Validate commit chain
	if r.Availability != BehavioralUnavailable && r.EvaluatedCommits != len(r.Commits) {
		return errors.New("behavioral hotspots: evaluated commits mismatch")
	}
	seenCommits := make(map[string]bool, len(r.Commits))
	touchCounts := make(map[string]int)
	totalTouches := 0
	for i, c := range r.Commits {
		if !isValidCommitHash(c.CommitID) {
			return fmt.Errorf("behavioral hotspots: invalid commit id %q", c.CommitID)
		}
		if seenCommits[c.CommitID] {
			return fmt.Errorf("behavioral hotspots: duplicate commit id %q", c.CommitID)
		}
		seenCommits[c.CommitID] = true
		if c.FirstParentID != "" && !isValidCommitHash(c.FirstParentID) {
			return fmt.Errorf("behavioral hotspots: invalid first parent id %q", c.FirstParentID)
		}
		if i+1 < len(r.Commits) && c.FirstParentID != r.Commits[i+1].CommitID {
			return fmt.Errorf("behavioral hotspots: broken first-parent chain between %s and %s", c.CommitID, r.Commits[i+1].CommitID)
		}

		lastPath := ""
		for j, p := range c.TouchedPaths {
			canon, err := CanonicalPath(p)
			if err != nil || canon != p {
				return fmt.Errorf("behavioral hotspots: invalid touched path %q", p)
			}
			if j > 0 && p <= lastPath {
				return errors.New("behavioral hotspots: touched paths are duplicate or unsorted")
			}
			lastPath = p
			touchCounts[p]++
			totalTouches++
			if totalTouches > maxBehavioralTouches {
				return errors.New("behavioral hotspots: touch budget exceeded")
			}
		}
	}
	if r.Availability != BehavioralUnavailable {
		last := r.Commits[len(r.Commits)-1]
		if r.ReachedRoot != (last.FirstParentID == "") {
			return errors.New("behavioral hotspots: root boundary mismatch")
		}
	}

	// Validate files
	seenFiles := make(map[string]bool, len(r.Files))
	for i, f := range r.Files {
		canon, err := CanonicalPath(f.Path)
		if err != nil || canon != f.Path || canon == "" {
			return fmt.Errorf("behavioral hotspots: invalid file path %q", f.Path)
		}
		if seenFiles[f.Path] {
			return fmt.Errorf("behavioral hotspots: duplicate file path %q", f.Path)
		}
		seenFiles[f.Path] = true
		if f.Cyclomatic < 0 || f.ChangeCount < 0 {
			return fmt.Errorf("behavioral hotspots: negative metrics for %q", f.Path)
		}
		if int64(f.Cyclomatic)*int64(f.ChangeCount) > math.MaxInt32 {
			return fmt.Errorf("behavioral hotspots: score overflow for %q", f.Path)
		}
		if f.Score != f.Cyclomatic*f.ChangeCount {
			return fmt.Errorf("behavioral hotspots: score mismatch for %q: got %d, want %d", f.Path, f.Score, f.Cyclomatic*f.ChangeCount)
		}
		if f.ChangeCount != touchCounts[f.Path] {
			return fmt.Errorf("behavioral hotspots: change count mismatch for %q", f.Path)
		}

		// Ordering check
		if i > 0 {
			prev := r.Files[i-1]
			if prev.Score < f.Score {
				return errors.New("behavioral hotspots: files not sorted by score DESC")
			}
			if prev.Score == f.Score {
				if prev.ChangeCount < f.ChangeCount {
					return errors.New("behavioral hotspots: files not sorted by change_count DESC")
				}
				if prev.ChangeCount == f.ChangeCount {
					if prev.Cyclomatic < f.Cyclomatic {
						return errors.New("behavioral hotspots: files not sorted by cyclomatic DESC")
					}
					if prev.Cyclomatic == f.Cyclomatic && prev.Path >= f.Path {
						return errors.New("behavioral hotspots: files not sorted by path ASC")
					}
				}
			}
		}
	}

	// Validate gaps
	lastGapKey := ""
	for i, g := range r.Gaps {
		if g.Path != "" {
			canon, err := CanonicalPath(g.Path)
			if err != nil || canon != g.Path {
				return fmt.Errorf("behavioral hotspots: invalid gap path %q", g.Path)
			}
		}
		if strings.TrimSpace(g.Reason) == "" {
			return errors.New("behavioral hotspots: gap reason cannot be empty")
		}
		if seenFiles[g.Path] {
			return fmt.Errorf("behavioral hotspots: measured file also appears as gap %q", g.Path)
		}
		gapKey := g.Path + "\x00" + g.Reason
		if i > 0 && gapKey <= lastGapKey {
			return errors.New("behavioral hotspots: gaps are duplicate or unsorted")
		}
		lastGapKey = gapKey
	}

	return nil
}

// MetricsForPath computes the behavioral metrics for a specific file or subtree.
func (r BehavioralHotspotsReport) MetricsForPath(path string, kind NodeKind) BehavioralMetrics {
	if r.Availability == BehavioralUnavailable {
		reason := r.Reason
		if reason == "" {
			reason = "behavioral_hotspots_unavailable"
		}
		return BehavioralMetrics{
			CyclomaticSum: unavailableCount(reason),
			ChangeCount:   unavailableCount(reason),
			Score:         unavailableCount(reason),
		}
	}

	if kind == NodeFile {
		for _, f := range r.Files {
			if f.Path == path {
				cyc := f.Cyclomatic
				changes := f.ChangeCount
				score := f.Score
				return BehavioralMetrics{
					CyclomaticSum: availableCount(cyc),
					ChangeCount:   availableCount(changes),
					Score:         availableCount(score),
				}
			}
		}
		// Check if file is in gaps
		for _, g := range r.Gaps {
			if g.Path == path {
				return BehavioralMetrics{
					CyclomaticSum: unavailableCount(g.Reason),
					ChangeCount:   unavailableCount(g.Reason),
					Score:         unavailableCount(g.Reason),
				}
			}
		}
		return BehavioralMetrics{
			CyclomaticSum: unavailableCount("file_not_in_scope"),
			ChangeCount:   unavailableCount("file_not_in_scope"),
			Score:         unavailableCount("file_not_in_scope"),
		}
	}

	// For Project or Directory nodes:
	// Directory/root only provides summary: max score, measured files count.
	// Does not sum file scores into "project risk".
	maxScore := 0
	hasMeasured := false
	measuredCount := 0

	prefix := ""
	if path != "" {
		prefix = path + "/"
	}

	for _, f := range r.Files {
		inScope := false
		if path == "" || strings.HasPrefix(f.Path, prefix) {
			inScope = true
		}
		if inScope {
			measuredCount++
			if !hasMeasured || f.Score > maxScore {
				maxScore = f.Score
				hasMeasured = true
			}
		}
	}

	if !hasMeasured {
		return BehavioralMetrics{
			CyclomaticSum: unavailableCount("directory_summary_uses_max_score"),
			ChangeCount:   availableCount(0),
			Score:         unavailableCount("no_measured_descendant_files"),
		}
	}

	return BehavioralMetrics{
		CyclomaticSum: unavailableCount("directory_summary_uses_max_score"),
		ChangeCount:   availableCount(measuredCount),
		Score:         availableCount(maxScore),
	}
}

// RankedFiles filters descendant files under path (all files if path=="") and returns up to limit rows.
func (r BehavioralHotspotsReport) RankedFiles(path string, limit int) (items []BehavioralFile, totalMeasured, shown, omitted int) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}

	prefix := ""
	if path != "" {
		prefix = path + "/"
	}

	var filtered []BehavioralFile
	for _, f := range r.Files {
		if path == "" || f.Path == path || strings.HasPrefix(f.Path, prefix) {
			filtered = append(filtered, f)
		}
	}

	totalMeasured = len(filtered)
	shown = totalMeasured
	if shown > limit {
		shown = limit
	}
	omitted = totalMeasured - shown
	items = filtered[:shown]
	return items, totalMeasured, shown, omitted
}

func isValidCommitHash(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
