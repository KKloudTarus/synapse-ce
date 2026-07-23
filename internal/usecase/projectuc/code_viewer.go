package projectuc

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const maxCodeLines = 1000

type CodeFileFilter struct {
	IncludeGenerated bool
	Changed          *bool
	HasFindings      *bool
	Prefix           string
	Status           string
}

type CodeRevision struct {
	Ref            string `json:"ref,omitempty"`
	Commit         string `json:"commit,omitempty"`
	ArtifactDigest string `json:"artifact_digest,omitempty"`
}

type CodeFile struct {
	Path             string                            `json:"path"`
	OldPath          string                            `json:"old_path,omitempty"`
	Status           string                            `json:"status"`
	Language         string                            `json:"language,omitempty"`
	Lines            int                               `json:"lines"`
	FindingCount     int                               `json:"finding_count"`
	ChangedLineCount int                               `json:"changed_line_count"`
	Binary           bool                              `json:"binary"`
	Generated        bool                              `json:"generated"`
	SourceAvailable  bool                              `json:"source_available"`
	SourceReason     projectanalysis.UnavailableReason `json:"source_reason,omitempty"`
}

// CodeLineOverlay is sparse: a nil coverage value means unknown/not executable.
type CodeLineOverlay struct {
	Line       int   `json:"line"`
	Covered    *bool `json:"covered,omitempty"`
	Changed    bool  `json:"changed,omitempty"`
	Duplicated bool  `json:"duplicated,omitempty"`
}

type CodeLine struct {
	Number     int     `json:"number"`
	Content    string  `json:"content"`
	Change     string  `json:"change"`
	Duplicated bool    `json:"duplicated"`
	Coverage   *string `json:"coverage"`
}

// CodeFinding is the display-safe immutable finding marker for a source response.
// DetectionStatus is immutable; CurrentStatus is optional mutable triage state.
type CodeFinding struct {
	ID              string                 `json:"id"`
	Kind            string                 `json:"kind"`
	RuleKey         string                 `json:"rule_key,omitempty"`
	RuleName        string                 `json:"rule_name,omitempty"`
	Type            string                 `json:"type,omitempty"`
	Severity        shared.Severity        `json:"severity"`
	DetectionStatus finding.Status         `json:"detection_status"`
	CurrentStatus   string                 `json:"current_status,omitempty"`
	Message         string                 `json:"message,omitempty"`
	Location        finding.SourceLocation `json:"location"`
	New             bool                   `json:"new"`
}

type CodeFileView struct {
	AnalysisID            string        `json:"analysis_id"`
	Base                  *CodeRevision `json:"base,omitempty"`
	Head                  CodeRevision  `json:"head"`
	File                  CodeFile      `json:"file"`
	FromLine              int           `json:"from_line"`
	ToLine                int           `json:"to_line"`
	TotalLines            int           `json:"total_lines"`
	Lines                 []CodeLine    `json:"lines"`
	Findings              []CodeFinding `json:"findings"`
	LineCoverageAvailable bool          `json:"-"`
}

type CodeDiffView struct {
	AnalysisID       string                     `json:"analysis_id"`
	Base             *CodeRevision              `json:"base,omitempty"`
	Head             CodeRevision               `json:"head"`
	Path             string                     `json:"path"`
	View             string                     `json:"view"`
	ContextTruncated bool                       `json:"context_truncated"`
	Change           projectanalysis.FileChange `json:"change"`
	BaseFile         projectanalysis.SourceFile `json:"base_file,omitempty"`
	SourceFile       projectanalysis.SourceFile `json:"source_file,omitempty"`
}

// ListCodeFiles returns the immutable snapshot inventory enriched with retained-source state.
func (s *Service) ListCodeFiles(ctx context.Context, tenantID shared.ID, key, analysisID string) ([]CodeFile, projectanalysis.SourceCapabilities, error) {
	return s.ListCodeFilesWithFilter(ctx, tenantID, key, analysisID, CodeFileFilter{})
}

// ListCodeFilesWithFilter derives the inventory only from persisted analysis metadata.
func (s *Service) ListCodeFilesWithFilter(ctx context.Context, tenantID shared.ID, key, analysisID string, filter CodeFileFilter) ([]CodeFile, projectanalysis.SourceCapabilities, error) {
	analysis, err := s.GetAnalysis(ctx, tenantID, key, analysisID)
	if err != nil {
		return nil, projectanalysis.SourceCapabilities{}, err
	}
	if filter.Prefix != "" {
		canonical, err := measure.CanonicalPath(filter.Prefix)
		if err != nil || canonical != filter.Prefix {
			return nil, analysis.Capabilities, fmt.Errorf("%w: source prefix is invalid", shared.ErrValidation)
		}
	}
	files := codeFiles(analysis)
	out := files[:0]
	for _, file := range files {
		if file.Generated && !filter.IncludeGenerated {
			continue
		}
		if filter.Changed != nil && (*filter.Changed != (file.Status != "unchanged")) {
			continue
		}
		if filter.HasFindings != nil && (*filter.HasFindings != (file.FindingCount > 0)) {
			continue
		}
		if filter.Prefix != "" && file.Path != filter.Prefix && !strings.HasPrefix(file.Path, filter.Prefix+"/") {
			continue
		}
		if filter.Status != "" && file.Status != string(filter.Status) {
			continue
		}
		out = append(out, file)
	}
	return out, analysis.Capabilities, nil
}

// ReadCodeFile resolves exact analysis ownership before reading one bounded source window.
func (s *Service) ReadCodeFile(ctx context.Context, tenantID shared.ID, key, analysisID, path string, fromLine, toLine int) (CodeFileView, projectanalysis.SourceCapabilities, error) {
	analysis, err := s.GetAnalysis(ctx, tenantID, key, analysisID)
	if err != nil {
		return CodeFileView{}, projectanalysis.SourceCapabilities{}, err
	}
	canonical, err := measure.CanonicalPath(path)
	if err != nil || canonical == "" || canonical != path {
		return CodeFileView{}, analysis.Capabilities, fmt.Errorf("%w: source path is invalid", shared.ErrValidation)
	}
	if !analysis.Capabilities.Source.Available || s.sourceArtifacts == nil {
		return CodeFileView{}, analysis.Capabilities, projectanalysis.ErrSourceNotRetained
	}
	file, found := codeFileByPath(analysis, canonical)
	if !found {
		return CodeFileView{}, analysis.Capabilities, shared.ErrNotFound
	}
	baseSide := file.Status == projectanalysis.FileStatusDeleted.String()
	if !file.SourceAvailable {
		if file.SourceReason == projectanalysis.UnavailableLimitExceeded || (!baseSide && analysis.SourceManifest.Truncated) || (baseSide && analysis.Comparison.BaseManifest.Truncated) {
			return CodeFileView{}, analysis.Capabilities, projectanalysis.ErrSourceLimit
		}
		if file.SourceReason == projectanalysis.UnavailableBinary || file.SourceReason == projectanalysis.UnavailableNonUTF8 {
			return CodeFileView{}, analysis.Capabilities, projectanalysis.ErrSourceUnsupported
		}
		return CodeFileView{}, analysis.Capabilities, projectanalysis.ErrSourceNotRetained
	}
	var source projectanalysis.SourceFile
	var data []byte
	if baseSide {
		data, source, err = s.sourceArtifacts.LoadBase(ctx, tenantID, shared.ID(analysis.ProjectID), analysis.ID, canonical)
	} else {
		data, source, err = s.sourceArtifacts.Load(ctx, tenantID, shared.ID(analysis.ProjectID), analysis.ID, canonical)
	}
	if err != nil {
		return CodeFileView{}, analysis.Capabilities, err
	}
	lines := splitCodeLines(string(data))
	if fromLine < 1 {
		fromLine = 1
	}
	if toLine == 0 {
		toLine = fromLine + maxCodeLines - 1
	}
	if toLine < fromLine || toLine-fromLine+1 > maxCodeLines {
		return CodeFileView{}, analysis.Capabilities, fmt.Errorf("%w: source line range must contain 1 to %d lines", shared.ErrValidation, maxCodeLines)
	}
	if toLine > len(lines) {
		toLine = len(lines)
	}
	if fromLine > len(lines) {
		toLine = fromLine - 1
	}
	annotations := annotationsForRange(analysis.Annotations, canonical, fromLine, toLine)
	statuses := s.currentFindingStatuses(ctx, tenantID, shared.ID(analysis.ProjectID), annotations)
	overlays := overlaysForRange(analysis, canonical, fromLine, toLine)
	return CodeFileView{
		AnalysisID: analysis.ID, Base: codeBaseRevision(analysis), Head: codeHeadRevision(analysis), File: withSource(file, source),
		FromLine: fromLine, ToLine: toLine, TotalLines: len(lines), Lines: codeLines(lines, overlays, fromLine, toLine),
		Findings: codeFindings(annotations, lines, statuses), LineCoverageAvailable: analysis.Coverage != nil && analysis.Coverage.Lines[canonical] != nil,
	}, analysis.Capabilities, nil
}

// ReadCodeDiff serves scan-time persisted hunk data. Git is never called from this read path.
func (s *Service) ReadCodeDiff(ctx context.Context, tenantID shared.ID, key, analysisID, path, view string, contextLines int) (CodeDiffView, projectanalysis.SourceCapabilities, error) {
	analysis, err := s.GetAnalysis(ctx, tenantID, key, analysisID)
	if err != nil {
		return CodeDiffView{}, projectanalysis.SourceCapabilities{}, err
	}
	canonical, err := measure.CanonicalPath(path)
	if err != nil || canonical == "" || canonical != path {
		return CodeDiffView{}, analysis.Capabilities, fmt.Errorf("%w: source path is invalid", shared.ErrValidation)
	}
	if view != "unified" && view != "split" {
		return CodeDiffView{}, analysis.Capabilities, fmt.Errorf("%w: diff view must be unified or split", shared.ErrValidation)
	}
	if contextLines < 0 || contextLines > 100 {
		return CodeDiffView{}, analysis.Capabilities, fmt.Errorf("%w: diff context must be between 0 and 100", shared.ErrValidation)
	}
	capability := analysis.Capabilities.UnifiedDiff
	if view == "split" {
		capability = analysis.Capabilities.SplitDiff
	}
	if !capability.Available || !analysis.Comparison.Available {
		return CodeDiffView{}, analysis.Capabilities, projectanalysis.ErrSourceNotRetained
	}
	for _, change := range analysis.FileChanges {
		if change.NewPath != canonical && change.OldPath != canonical {
			continue
		}
		if change.Binary {
			return CodeDiffView{}, analysis.Capabilities, projectanalysis.ErrSourceUnsupported
		}
		trimmed, truncated := trimFileChange(change, contextLines)
		out := CodeDiffView{AnalysisID: analysis.ID, Base: codeBaseRevision(analysis), Head: codeHeadRevision(analysis), Path: canonical, View: view, ContextTruncated: truncated, Change: trimmed}
		if change.OldPath != "" && manifestOmittedByLimit(analysis.Comparison.BaseManifest, change.OldPath) {
			return CodeDiffView{}, analysis.Capabilities, projectanalysis.ErrSourceLimit
		}
		if change.NewPath != "" && manifestOmittedByLimit(analysis.SourceManifest, change.NewPath) {
			return CodeDiffView{}, analysis.Capabilities, projectanalysis.ErrSourceLimit
		}
		if change.OldPath != "" && s.sourceArtifacts != nil {
			_, out.BaseFile, err = s.sourceArtifacts.LoadBase(ctx, tenantID, shared.ID(analysis.ProjectID), analysis.ID, change.OldPath)
			if err != nil {
				return CodeDiffView{}, analysis.Capabilities, err
			}
		}
		if change.NewPath != "" && s.sourceArtifacts != nil {
			_, out.SourceFile, err = s.sourceArtifacts.Load(ctx, tenantID, shared.ID(analysis.ProjectID), analysis.ID, change.NewPath)
			if err != nil {
				return CodeDiffView{}, analysis.Capabilities, err
			}
		}
		return out, analysis.Capabilities, nil
	}
	return CodeDiffView{}, analysis.Capabilities, shared.ErrNotFound
}

func trimFileChange(change projectanalysis.FileChange, contextLines int) (projectanalysis.FileChange, bool) {
	out := change
	truncated := false
	out.Hunks = make([]projectanalysis.DiffHunk, 0, len(change.Hunks))
	for _, hunk := range change.Hunks {
		keep := make([]bool, len(hunk.Rows))
		for i, row := range hunk.Rows {
			if row.Kind == projectanalysis.DiffRowContext {
				continue
			}
			from, to := max(0, i-contextLines), min(len(hunk.Rows)-1, i+contextLines)
			for j := from; j <= to; j++ {
				keep[j] = true
			}
		}
		for start := 0; start < len(hunk.Rows); {
			for start < len(hunk.Rows) && !keep[start] {
				truncated = true
				start++
			}
			end := start
			for end < len(hunk.Rows) && keep[end] {
				end++
			}
			if start == end {
				continue
			}
			rows := append([]projectanalysis.DiffRow(nil), hunk.Rows[start:end]...)
			trimmed := projectanalysis.DiffHunk{OldStart: hunk.OldStart, NewStart: hunk.NewStart, Rows: rows}
			for _, row := range hunk.Rows[:start] {
				if row.Kind != projectanalysis.DiffRowAdded {
					trimmed.OldStart++
				}
				if row.Kind != projectanalysis.DiffRowRemoved {
					trimmed.NewStart++
				}
			}
			for _, row := range rows {
				if row.Kind != projectanalysis.DiffRowAdded {
					trimmed.OldLines++
				}
				if row.Kind != projectanalysis.DiffRowRemoved {
					trimmed.NewLines++
				}
			}
			out.Hunks = append(out.Hunks, trimmed)
			start = end
		}
	}
	return out, truncated
}

func codeFiles(analysis projectanalysis.Analysis) []CodeFile {
	sources := map[string]projectanalysis.SourceFile{}
	for _, file := range analysis.SourceManifest.Files {
		sources[file.Path] = file
	}
	bases := map[string]projectanalysis.SourceFile{}
	for _, file := range analysis.Comparison.BaseManifest.Files {
		bases[file.Path] = file
	}
	changes := map[string]projectanalysis.FileChange{}
	for _, change := range analysis.FileChanges {
		if change.NewPath != "" {
			changes[change.NewPath] = change
		}
		if change.OldPath != "" {
			changes[change.OldPath] = change
		}
	}
	annotations := map[string]int{}
	for _, annotation := range analysis.Annotations {
		annotations[annotation.Location.File]++
	}
	languages := map[string]string{}
	paths := map[string]struct{}{}
	for _, node := range analysis.Snapshot.Nodes {
		if node.Kind == measure.NodeFile {
			paths[node.Path] = struct{}{}
			languages[node.Path] = node.Language
		}
	}
	for _, change := range analysis.FileChanges {
		if change.Status == projectanalysis.FileStatusDeleted && change.OldPath != "" {
			paths[change.OldPath] = struct{}{}
		}
	}
	out := make([]CodeFile, 0, len(paths))
	for path := range paths {
		change, changed := changes[path]
		source, sourceFound := sources[path]
		if !sourceFound && changed && change.Status == projectanalysis.FileStatusDeleted {
			source, sourceFound = bases[path]
		}
		if !sourceFound {
			reason := projectanalysis.UnavailableNotRetained
			if (changed && change.Status == projectanalysis.FileStatusDeleted && analysis.Comparison.BaseManifest.Truncated) ||
				(!changed || change.Status != projectanalysis.FileStatusDeleted) && analysis.SourceManifest.Truncated {
				reason = projectanalysis.UnavailableLimitExceeded
			}
			source = projectanalysis.SourceFile{Path: path, Reason: reason}
		}
		file := CodeFile{Path: path, Status: "unchanged", Language: languages[path], Lines: source.Lines, FindingCount: annotations[path], Binary: change.Binary, Generated: source.Generated, SourceAvailable: source.Available, SourceReason: source.Reason}
		if changed {
			file.Status, file.OldPath = change.Status.String(), change.OldPath
			for _, r := range change.Added {
				file.ChangedLineCount += r.End - r.Start + 1
			}
		}
		out = append(out, file)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func codeFileByPath(analysis projectanalysis.Analysis, path string) (CodeFile, bool) {
	for _, file := range codeFiles(analysis) {
		if file.Path == path {
			return file, true
		}
	}
	return CodeFile{}, false
}

func manifestOmittedByLimit(manifest projectanalysis.SourceManifest, path string) bool {
	if !manifest.Truncated {
		return false
	}
	for _, file := range manifest.Files {
		if file.Path == path {
			return false
		}
	}
	return true
}

func withSource(file CodeFile, source projectanalysis.SourceFile) CodeFile {
	file.Lines, file.Generated, file.SourceAvailable, file.SourceReason = source.Lines, source.Generated, source.Available, source.Reason
	return file
}

func codeHeadRevision(analysis projectanalysis.Analysis) CodeRevision {
	return CodeRevision{Ref: analysis.SourceRef, Commit: analysis.SourceRevision.Head, ArtifactDigest: analysis.SourceManifest.ArtifactDigest()}
}

func codeBaseRevision(analysis projectanalysis.Analysis) *CodeRevision {
	if !analysis.Comparison.Available {
		return nil
	}
	return &CodeRevision{Ref: analysis.Comparison.BaseRef, Commit: analysis.Comparison.BaseCommit, ArtifactDigest: analysis.Comparison.BaseManifest.ArtifactDigest()}
}

func overlaysForRange(analysis projectanalysis.Analysis, path string, fromLine, toLine int) []CodeLineOverlay {
	covered := analysis.Coverage != nil && analysis.Coverage.Lines[path] != nil
	changed := map[int]bool{}
	for _, change := range analysis.FileChanges {
		if change.NewPath != path {
			continue
		}
		for _, r := range change.Added {
			for line := r.Start; line <= r.End; line++ {
				changed[line] = true
			}
		}
	}
	duplicated := map[int]bool{}
	for _, block := range analysis.Duplication.Blocks {
		for _, occurrence := range block.Occurrences {
			if occurrence.File != path {
				continue
			}
			for line := occurrence.StartLine; line <= occurrence.EndLine; line++ {
				duplicated[line] = true
			}
		}
	}
	out := make([]CodeLineOverlay, 0)
	for line := fromLine; line <= toLine; line++ {
		item := CodeLineOverlay{Line: line, Changed: changed[line], Duplicated: duplicated[line]}
		if covered {
			if value, ok := analysis.Coverage.Lines[path][line]; ok {
				item.Covered = new(bool)
				*item.Covered = value
			}
		}
		if item.Covered != nil || item.Changed || item.Duplicated {
			out = append(out, item)
		}
	}
	return out
}

func codeLines(lines []string, overlays []CodeLineOverlay, fromLine, toLine int) []CodeLine {
	byLine := map[int]CodeLineOverlay{}
	for _, overlay := range overlays {
		byLine[overlay.Line] = overlay
	}
	out := make([]CodeLine, 0, max(0, toLine-fromLine+1))
	for line := fromLine; line <= toLine; line++ {
		overlay := byLine[line]
		change := "unchanged"
		if overlay.Changed {
			change = "addition"
		}
		var coverage *string
		if overlay.Covered != nil {
			value := "uncovered"
			if *overlay.Covered {
				value = "covered"
			}
			coverage = &value
		}
		out = append(out, CodeLine{Number: line, Content: lines[line-1], Change: change, Duplicated: overlay.Duplicated, Coverage: coverage})
	}
	return out
}

func (s *Service) currentFindingStatuses(ctx context.Context, tenantID, projectID shared.ID, annotations []projectanalysis.Annotation) map[string]string {
	store, ok := any(s.issues).(ports.ProjectFindingStatusStore)
	if !ok {
		store, ok = any(s.hotspots).(ports.ProjectFindingStatusStore)
	}
	if !ok || len(annotations) == 0 {
		return nil
	}
	keys := make([]string, 0, len(annotations))
	for _, annotation := range annotations {
		keys = append(keys, annotation.FindingKey)
	}
	statuses, err := store.CurrentFindingStatuses(ctx, tenantID, projectID, keys)
	if err != nil {
		return nil
	}
	return statuses
}

func codeFindings(in []projectanalysis.Annotation, lines []string, statuses map[string]string) []CodeFinding {
	out := make([]CodeFinding, 0, len(in))
	for _, annotation := range in {
		location := annotation.Location
		if location.StartColumn != nil {
			start, end, ok := displayColumns(lines, location)
			if ok {
				location.StartColumn, location.EndColumn = &start, &end
			} else {
				location.StartColumn, location.EndColumn = nil, nil
			}
		}
		kind := "issue"
		if annotation.RuleType == "security_hotspot" {
			kind = "hotspot"
		}
		out = append(out, CodeFinding{
			ID: annotation.FindingKey, Kind: kind, RuleKey: annotation.RuleKey, RuleName: annotation.RuleName, Type: string(annotation.RuleType),
			Severity: annotation.Severity, DetectionStatus: annotation.Status, CurrentStatus: statuses[annotation.FindingKey], Message: annotation.Message, Location: location, New: annotation.New,
		})
	}
	return out
}

func displayColumns(lines []string, location finding.SourceLocation) (int, int, bool) {
	if location.StartColumn == nil || location.EndColumn == nil || location.StartLine < 1 || location.EndLine < location.StartLine || location.EndLine > len(lines) {
		return 0, 0, false
	}
	start, ok := utf16Column(lines[location.StartLine-1], *location.StartColumn)
	if !ok {
		return 0, 0, false
	}
	end, ok := utf16Column(lines[location.EndLine-1], *location.EndColumn)
	return start, end, ok
}

func utf16Column(line string, byteOffset int) (int, bool) {
	if byteOffset < 0 || byteOffset > len(line) || !utf8.ValidString(line) || (byteOffset < len(line) && !utf8.RuneStart(line[byteOffset])) {
		return 0, false
	}
	column := 0
	for _, r := range line[:byteOffset] {
		if r > 0xFFFF {
			column += 2
		} else {
			column++
		}
	}
	return column, true
}

func annotationsForRange(in []projectanalysis.Annotation, path string, fromLine, toLine int) []projectanalysis.Annotation {
	out := make([]projectanalysis.Annotation, 0)
	for _, annotation := range in {
		if annotation.Location.File == path && annotation.Location.EndLine >= fromLine && annotation.Location.StartLine <= toLine {
			out = append(out, annotation)
		}
	}
	return out
}

func splitCodeLines(content string) []string {
	if content == "" {
		return []string{}
	}
	lines := strings.Split(content, "\n")
	if lines[len(lines)-1] == "" {
		return lines[:len(lines)-1]
	}
	return lines
}
