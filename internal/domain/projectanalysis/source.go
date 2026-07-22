package projectanalysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ScanKind identifies the acquisition mode that produced an analysis snapshot.
type ScanKind string

const (
	ScanKindGit     ScanKind = "git"
	ScanKindArchive ScanKind = "archive"
	ScanKindLocal   ScanKind = "local"
)

func (k ScanKind) Valid() bool {
	switch k {
	case ScanKindGit, ScanKindArchive, ScanKindLocal:
		return true
	default:
		return false
	}
}

// UnavailableReason is a safe, stable explanation for an unavailable Code capability.
type UnavailableReason string

const (
	UnavailableNotRetained       UnavailableReason = "not_retained"
	UnavailableCaptureFailed     UnavailableReason = "capture_failed"
	UnavailableFirstAnalysis     UnavailableReason = "first_analysis"
	UnavailableNoComparableBase  UnavailableReason = "no_comparable_base"
	UnavailableUnsupportedTarget UnavailableReason = "unsupported_target"
	UnavailableLimitExceeded     UnavailableReason = "limit_exceeded"
	UnavailableBinary            UnavailableReason = "binary"
	UnavailableNonUTF8           UnavailableReason = "non_utf8"
)

func (r UnavailableReason) Valid() bool {
	switch r {
	case UnavailableNotRetained, UnavailableCaptureFailed, UnavailableFirstAnalysis,
		UnavailableNoComparableBase, UnavailableUnsupportedTarget, UnavailableLimitExceeded,
		UnavailableBinary, UnavailableNonUTF8:
		return true
	default:
		return false
	}
}

var (
	ErrCapabilityReason  = errors.New("source capability reason is invalid")
	ErrFileChangeStatus  = errors.New("file change status is invalid")
	ErrFileChangePaths   = errors.New("file change paths are invalid")
	ErrSourceNotRetained = errors.New("source artifact not retained")
	ErrSourceIntegrity   = errors.New("source artifact integrity mismatch")
	ErrSourceLimit       = errors.New("source artifact exceeds retained limit")
	ErrSourceUnsupported = errors.New("source artifact content is unsupported")
	ErrSourceTransient   = errors.New("source artifact temporarily unavailable")
)

// Capability says whether one analysis-time Code feature can be served. An unavailable
// capability always carries a safe reason; available capabilities never carry one.
type Capability struct {
	Available bool              `json:"available"`
	Reason    UnavailableReason `json:"reason,omitempty"`
}

func (c Capability) Validate() error {
	if c.Available {
		if c.Reason != "" {
			return ErrCapabilityReason
		}
		return nil
	}
	if !c.Reason.Valid() {
		return ErrCapabilityReason
	}
	return nil
}

// SourceCapabilities describes what a historical Code request may truthfully render.
type SourceCapabilities struct {
	Source       Capability `json:"source"`
	Comparison   Capability `json:"comparison"`
	UnifiedDiff  Capability `json:"unified_diff"`
	SplitDiff    Capability `json:"split_diff"`
	Highlighting Capability `json:"highlighting"`
}

func (c SourceCapabilities) Validate() error {
	for _, item := range []Capability{c.Source, c.Comparison, c.UnifiedDiff, c.SplitDiff, c.Highlighting} {
		if err := item.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// SourceRevision identifies the immutable head and, where available, comparison base.
type SourceRevision struct {
	Kind       ScanKind `json:"kind"`
	Head       string   `json:"head,omitempty"`
	Base       string   `json:"base,omitempty"`
	MergeBase  string   `json:"merge_base,omitempty"`
	AnalysisID string   `json:"analysis_id,omitempty"`
}

// DiffRowKind identifies one persisted unified-diff row. Rows retain both sides'
// line numbers so split rendering never needs to rerun Git.
type DiffRowKind string

const (
	DiffRowContext DiffRowKind = "context"
	DiffRowAdded   DiffRowKind = "added"
	DiffRowRemoved DiffRowKind = "removed"
)

func (k DiffRowKind) Valid() bool {
	switch k {
	case DiffRowContext, DiffRowAdded, DiffRowRemoved:
		return true
	default:
		return false
	}
}

// DiffRow is one normalized unified row. A missing side is represented by zero,
// never a magic line-number sentinel.
type DiffRow struct {
	Kind           DiffRowKind `json:"kind"`
	OldLine        int         `json:"old_line,omitempty"`
	NewLine        int         `json:"new_line,omitempty"`
	Text           string      `json:"text"`
	NoFinalNewline bool        `json:"no_final_newline,omitempty"`
}

func (r DiffRow) Validate() error {
	if !r.Kind.Valid() {
		return fmt.Errorf("diff row kind is invalid")
	}
	switch r.Kind {
	case DiffRowContext:
		if r.OldLine < 1 || r.NewLine < 1 {
			return fmt.Errorf("context diff row lines are invalid")
		}
	case DiffRowAdded:
		if r.OldLine != 0 || r.NewLine < 1 {
			return fmt.Errorf("added diff row lines are invalid")
		}
	case DiffRowRemoved:
		if r.OldLine < 1 || r.NewLine != 0 {
			return fmt.Errorf("removed diff row lines are invalid")
		}
	}
	return nil
}

// DiffHunk is an immutable, normalized section of one file change.
type DiffHunk struct {
	OldStart int       `json:"old_start"`
	OldLines int       `json:"old_lines"`
	NewStart int       `json:"new_start"`
	NewLines int       `json:"new_lines"`
	Rows     []DiffRow `json:"rows"`
}

func (h DiffHunk) Validate() error {
	if h.OldStart < 0 || h.OldLines < 0 || h.NewStart < 0 || h.NewLines < 0 ||
		(h.OldLines > 0 && h.OldStart < 1) || (h.NewLines > 0 && h.NewStart < 1) {
		return fmt.Errorf("diff hunk range is invalid")
	}
	oldLines, newLines := 0, 0
	for _, row := range h.Rows {
		if err := row.Validate(); err != nil {
			return err
		}
		if row.Kind != DiffRowAdded {
			oldLines++
		}
		if row.Kind != DiffRowRemoved {
			newLines++
		}
	}
	if oldLines != h.OldLines || newLines != h.NewLines {
		return fmt.Errorf("diff hunk rows do not match ranges")
	}
	return nil
}

// Comparison contains the immutable Git-derived facts needed for historical diff
// rendering. BaseManifest points to analysis-owned base-side artifacts.
type Comparison struct {
	Available          bool              `json:"available"`
	Reason             UnavailableReason `json:"reason,omitempty"`
	BaseRef            string            `json:"base_ref,omitempty"`
	BaseCommit         string            `json:"base_commit,omitempty"`
	MergeBase          string            `json:"merge_base,omitempty"`
	PreviousAnalysisID string            `json:"previous_analysis_id,omitempty"`
	BaseManifest       SourceManifest    `json:"base_manifest,omitempty"`
}

func (c Comparison) Validate() error {
	if c.Available {
		if c.Reason != "" || strings.TrimSpace(c.BaseCommit) == "" || strings.TrimSpace(c.MergeBase) == "" {
			return fmt.Errorf("available comparison is invalid")
		}
		return nil
	}
	if !c.Reason.Valid() {
		return ErrCapabilityReason
	}
	return nil
}

// SourceFile records one captured head or base artifact without storing source bytes in
// the analysis payload. Digest addresses content in the owned artifact store.
type SourceFile struct {
	Path      string            `json:"path"`
	Digest    string            `json:"digest,omitempty"`
	Bytes     int64             `json:"bytes"`
	Lines     int               `json:"lines"`
	Generated bool              `json:"generated"`
	Available bool              `json:"available"`
	Reason    UnavailableReason `json:"reason,omitempty"`
}

func (f SourceFile) Validate() error {
	canonical, err := measure.CanonicalPath(f.Path)
	if err != nil || canonical == "" || canonical != f.Path || f.Bytes < 0 || f.Lines < 0 {
		return fmt.Errorf("source file is invalid")
	}
	if f.Available {
		if strings.TrimSpace(f.Digest) == "" || f.Reason != "" {
			return fmt.Errorf("source file availability is invalid")
		}
		return nil
	}
	if !f.Reason.Valid() || f.Digest != "" {
		return fmt.Errorf("source file availability is invalid")
	}
	return nil
}

// SourceManifest is the analysis-owned source capture inventory. It is immutable after
// publication and reconciled against measure.Snapshot.Nodes before persistence.
type SourceManifest struct {
	Files     []SourceFile `json:"files"`
	Truncated bool         `json:"truncated,omitempty"`
	Digest    string       `json:"digest,omitempty"`
}

// ArtifactDigest returns a stable identity for the manifest's immutable inventory.
// Legacy manifests derive it on read because their serialized payload predates Digest.
func (m SourceManifest) ArtifactDigest() string {
	m.Digest = ""
	data, _ := json.Marshal(m)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (m *SourceManifest) SetArtifactDigest() {
	m.Digest = m.ArtifactDigest()
}

// SourceCapture is the pipeline result needed to publish an immutable source manifest.
// Capture errors are represented as unavailable capabilities rather than failing analysis.
type SourceCapture struct {
	Capabilities SourceCapabilities `json:"capabilities"`
	Manifest     SourceManifest     `json:"manifest"`
}

// FileStatus is the complete persisted Git-style status used by source and diff views.
type FileStatus string

const (
	FileStatusAdded    FileStatus = "added"
	FileStatusModified FileStatus = "modified"
	FileStatusDeleted  FileStatus = "deleted"
	FileStatusRenamed  FileStatus = "renamed"
	FileStatusCopied   FileStatus = "copied"
	FileStatusModeOnly FileStatus = "mode_only"
)

func (s FileStatus) Valid() bool {
	switch s {
	case FileStatusAdded, FileStatusModified, FileStatusDeleted, FileStatusRenamed, FileStatusCopied, FileStatusModeOnly:
		return true
	default:
		return false
	}
}

func (s FileStatus) String() string { return string(s) }

// LineRange is a one-based inclusive range in one diff side.
type LineRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

func (r LineRange) Valid() bool { return r.Start > 0 && r.End >= r.Start }

// FileChange contains persisted file-level comparison metadata. Hunk content and line
// mappings are added separately; the API never re-runs Git for historical analyses.
type FileChange struct {
	Status   FileStatus  `json:"status"`
	OldPath  string      `json:"old_path,omitempty"`
	NewPath  string      `json:"new_path,omitempty"`
	Binary   bool        `json:"binary"`
	ModeOld  string      `json:"mode_old,omitempty"`
	ModeNew  string      `json:"mode_new,omitempty"`
	Added    []LineRange `json:"added,omitempty"`
	Removed  []LineRange `json:"removed,omitempty"`
	Modified []LineRange `json:"modified,omitempty"`
	Hunks    []DiffHunk  `json:"hunks,omitempty"`
}

// Annotation is an immutable, detection-time source marker. Current issue and
// hotspot triage is intentionally not copied here, so later reviews cannot rewrite
// historical analysis state.
type Annotation struct {
	FindingKey string                 `json:"finding_key"`
	RuleKey    string                 `json:"rule_key,omitempty"`
	RuleName   string                 `json:"rule_name,omitempty"`
	RuleType   rule.Type              `json:"rule_type,omitempty"`
	Message    string                 `json:"message,omitempty"`
	Kind       finding.Kind           `json:"kind"`
	Severity   shared.Severity        `json:"severity"`
	Status     finding.Status         `json:"status"`
	Location   finding.SourceLocation `json:"location"`
	New        bool                   `json:"new"`
}

func (a Annotation) Validate() error {
	if strings.TrimSpace(a.FindingKey) == "" || !a.Kind.Valid() || !a.Severity.Valid() || !a.Status.Valid() {
		return fmt.Errorf("annotation is invalid")
	}
	return a.Location.Validate()
}

func (c FileChange) Validate() error {
	if !c.Status.Valid() {
		return ErrFileChangeStatus
	}
	validPath := func(p string) bool {
		canonical, err := measure.CanonicalPath(p)
		return err == nil && canonical != "" && canonical == p
	}
	switch c.Status {
	case FileStatusAdded:
		if c.OldPath != "" || !validPath(c.NewPath) {
			return ErrFileChangePaths
		}
	case FileStatusDeleted:
		if c.NewPath != "" || !validPath(c.OldPath) {
			return ErrFileChangePaths
		}
	default:
		if !validPath(c.OldPath) || !validPath(c.NewPath) {
			return ErrFileChangePaths
		}
	}
	for _, r := range append(append([]LineRange{}, c.Added...), append(c.Removed, c.Modified...)...) {
		if !r.Valid() {
			return ErrFileChangePaths
		}
	}
	for _, hunk := range c.Hunks {
		if err := hunk.Validate(); err != nil {
			return err
		}
	}
	return nil
}
