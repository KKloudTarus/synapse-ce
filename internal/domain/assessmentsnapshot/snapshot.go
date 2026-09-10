// Package assessmentsnapshot defines immutable, comparison-ready Assessment snapshots.
package assessmentsnapshot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const SchemaVersion = 1

type Lifecycle string

const (
	LifecycleBuilding   Lifecycle = "building"
	LifecycleFinalized  Lifecycle = "finalized"
	LifecycleSuperseded Lifecycle = "superseded"
)

type Provenance string

const (
	ProvenanceNative Provenance = "native"
	ProvenanceLegacy Provenance = "legacy"
)

type CoverageState string

const (
	CoverageComplete CoverageState = "complete"
	CoveragePartial  CoverageState = "partial"
	CoverageUnknown  CoverageState = "unknown"
)

const (
	ReasonTrustedTerminalLane = "trusted_terminal_lane"
	ReasonLegacyProvenance    = "legacy_provenance"
	ReasonRunPartial          = "run_partial"
	ReasonRunFailed           = "run_failed"
	ReasonRunCancelled        = "run_cancelled"
	ReasonLanePartial         = "lane_partial"
	ReasonLaneFailed          = "lane_failed"
	ReasonLaneCancelled       = "lane_cancelled"
	ReasonStageFailed         = "stage_failed"
	ReasonStageSkipped        = "stage_skipped"
)

type Boundary struct {
	BusinessAssetID shared.ID                    `json:"business_asset_id,omitempty"`
	Kind            assessmentcycle.BoundaryKind `json:"boundary_kind"`
	ProjectID       shared.ID                    `json:"project_id,omitempty"`
}

type LaneReference struct {
	LaneKey      string `json:"lane_key"`
	ManifestHash string `json:"manifest_hash"`
}

type RunReference struct {
	LaneReferences []LaneReference `json:"lane_refs"`
	ManifestHash   string          `json:"manifest_hash"`
	RunID          string          `json:"run_id"`
}

type Target struct {
	Canonical         string             `json:"canonical"`
	EvaluatedRevision string             `json:"evaluated_revision,omitempty"`
	Kind              scanrun.TargetKind `json:"kind"`
	SchemaVersion     int                `json:"schema_version"`
}

type Version struct {
	Digest  string              `json:"digest,omitempty"`
	Kind    scanrun.VersionKind `json:"kind"`
	Name    string              `json:"name"`
	Version string              `json:"version"`
}

type Dimension struct {
	ExcludedScope    []string      `json:"excluded_scope"`
	FindingKind      string        `json:"finding_kind"`
	IncludedScope    []string      `json:"included_scope"`
	LaneKey          string        `json:"lane_key"`
	LaneManifestHash string        `json:"lane_manifest_hash"`
	Producer         string        `json:"producer"`
	ReasonCode       string        `json:"reason_code"`
	RunID            string        `json:"run_id"`
	State            CoverageState `json:"state"`
	Target           Target        `json:"target"`
	Versions         []Version     `json:"versions"`
}

type Snapshot struct {
	TenantID       shared.ID
	ID             shared.ID
	CycleID        shared.ID
	AssessmentID   shared.ID
	SnapshotNumber int
	DefaultVersion int64
	Lifecycle      Lifecycle
	Provenance     Provenance
	Boundary       Boundary
	RunReferences  []RunReference
	Dimensions     []Dimension
	SchemaVersion  int
	ContentHash    string
	RequestKey     string
	RequestHash    string
	CreatedAt      time.Time
	CreatedBy      string
	FinalizedAt    *time.Time
	FinalizedBy    string
	SupersededAt   *time.Time
	SupersededBy   string
}

type SelectedRun struct {
	ID             string
	ManifestHash   string
	Provenance     scanrun.ProvenanceKind
	TerminalStatus scanrun.TerminalStatus
	Trusted        bool
	Lanes          []scanrun.Lane
}

func NewFinalized(tenantID, id, cycleID, assessmentID shared.ID, boundary Boundary, requestKey, actor string, now time.Time, runs []SelectedRun) (*Snapshot, error) {
	if tenantID.IsZero() || id.IsZero() || cycleID.IsZero() || assessmentID.IsZero() {
		return nil, fmt.Errorf("%w: snapshot tenant, id, cycle, and assessment are required", shared.ErrValidation)
	}
	if strings.TrimSpace(requestKey) == "" || strings.TrimSpace(actor) == "" || now.IsZero() {
		return nil, fmt.Errorf("%w: snapshot request key, actor, and time are required", shared.ErrValidation)
	}
	if err := assessmentcycle.ValidateBoundaryEnforcement(boundary.Kind, boundary.BusinessAssetID, boundary.ProjectID); err != nil {
		return nil, err
	}
	if len(runs) == 0 {
		return nil, fmt.Errorf("%w: snapshot requires at least one selected run", shared.ErrValidation)
	}

	runReferences, dimensions, provenance, err := compileRuns(runs)
	if err != nil {
		return nil, err
	}
	now = now.UTC()
	snapshot := &Snapshot{
		TenantID: tenantID, ID: id, CycleID: cycleID, AssessmentID: assessmentID,
		Lifecycle: LifecycleFinalized, Provenance: provenance, Boundary: boundary,
		RunReferences: runReferences, Dimensions: dimensions, SchemaVersion: SchemaVersion,
		RequestKey: strings.TrimSpace(requestKey), CreatedAt: now, CreatedBy: strings.TrimSpace(actor),
		FinalizedAt: timePointer(now), FinalizedBy: strings.TrimSpace(actor),
	}
	contentHash, err := snapshot.computeContentHash()
	if err != nil {
		return nil, err
	}
	snapshot.ContentHash = contentHash
	snapshot.RequestHash = contentHash
	return snapshot, snapshot.Validate()
}

func (snapshot *Snapshot) Validate() error {
	if snapshot == nil || snapshot.TenantID.IsZero() || snapshot.ID.IsZero() || snapshot.CycleID.IsZero() || snapshot.AssessmentID.IsZero() {
		return fmt.Errorf("%w: snapshot identity is invalid", shared.ErrValidation)
	}
	if snapshot.SchemaVersion != SchemaVersion || !validSHA256(snapshot.ContentHash) || !validSHA256(snapshot.RequestHash) {
		return fmt.Errorf("%w: snapshot schema or hash is invalid", shared.ErrValidation)
	}
	if snapshot.Lifecycle != LifecycleFinalized && snapshot.Lifecycle != LifecycleSuperseded {
		return fmt.Errorf("%w: persisted snapshot must be finalized or superseded", shared.ErrValidation)
	}
	if snapshot.Provenance != ProvenanceNative && snapshot.Provenance != ProvenanceLegacy {
		return fmt.Errorf("%w: snapshot provenance is invalid", shared.ErrValidation)
	}
	if snapshot.FinalizedAt == nil || snapshot.FinalizedAt.IsZero() || strings.TrimSpace(snapshot.FinalizedBy) == "" {
		return fmt.Errorf("%w: snapshot finalization metadata is required", shared.ErrValidation)
	}
	if snapshot.Lifecycle == LifecycleSuperseded && (snapshot.SupersededAt == nil || strings.TrimSpace(snapshot.SupersededBy) == "") {
		return fmt.Errorf("%w: superseded snapshot metadata is required", shared.ErrValidation)
	}
	want, err := snapshot.computeContentHash()
	if err != nil {
		return err
	}
	if want != snapshot.ContentHash {
		return fmt.Errorf("%w: snapshot content hash mismatch", shared.ErrValidation)
	}
	return nil
}

func (snapshot *Snapshot) Supersede(actor string, at time.Time) error {
	if snapshot == nil || snapshot.Lifecycle != LifecycleFinalized || strings.TrimSpace(actor) == "" || at.IsZero() {
		return fmt.Errorf("%w: only a finalized snapshot can be superseded", shared.ErrValidation)
	}
	snapshot.Lifecycle = LifecycleSuperseded
	snapshot.SupersededAt = timePointer(at.UTC())
	snapshot.SupersededBy = strings.TrimSpace(actor)
	return snapshot.Validate()
}

func compileRuns(runs []SelectedRun) ([]RunReference, []Dimension, Provenance, error) {
	ordered := append([]SelectedRun(nil), runs...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	provenance := ProvenanceNative
	seenRuns := map[string]struct{}{}
	seenDimensions := map[string]struct{}{}
	runReferences := make([]RunReference, 0, len(ordered))
	var dimensions []Dimension
	for _, run := range ordered {
		run.ID = strings.TrimSpace(run.ID)
		if run.ID == "" || !validSHA256(run.ManifestHash) {
			return nil, nil, "", fmt.Errorf("%w: selected run identity or manifest hash is invalid", shared.ErrValidation)
		}
		if _, exists := seenRuns[run.ID]; exists {
			return nil, nil, "", fmt.Errorf("%w: selected run %q is duplicated", shared.ErrValidation, run.ID)
		}
		seenRuns[run.ID] = struct{}{}
		if run.Provenance == scanrun.ProvenanceNative {
			if !run.Trusted {
				return nil, nil, "", fmt.Errorf("%w: selected native run %q is not trusted sealed provenance", shared.ErrValidation, run.ID)
			}
		} else if run.Provenance == scanrun.ProvenanceLegacy {
			provenance = ProvenanceLegacy
		} else {
			return nil, nil, "", fmt.Errorf("%w: selected run provenance is invalid", shared.ErrValidation)
		}

		lanes := append([]scanrun.Lane(nil), run.Lanes...)
		sort.Slice(lanes, func(i, j int) bool { return lanes[i].LaneKey < lanes[j].LaneKey })
		reference := RunReference{RunID: run.ID, ManifestHash: run.ManifestHash}
		for _, lane := range lanes {
			if err := validateSealedLane(lane); err != nil {
				return nil, nil, "", fmt.Errorf("validate selected lane %s/%s: %w", run.ID, lane.LaneKey, err)
			}
			reference.LaneReferences = append(reference.LaneReferences, LaneReference{LaneKey: lane.LaneKey, ManifestHash: lane.ManifestHash})
			for _, findingKind := range sortedUnique(lane.AuthoritativeFindingKinds) {
				dimension := dimensionFrom(run, lane, findingKind)
				key := dimensionKey(dimension)
				if _, exists := seenDimensions[key]; exists {
					return nil, nil, "", fmt.Errorf("%w: duplicate snapshot coverage dimension %q", shared.ErrValidation, key)
				}
				seenDimensions[key] = struct{}{}
				dimensions = append(dimensions, dimension)
			}
		}
		runReferences = append(runReferences, reference)
	}
	sort.Slice(dimensions, func(i, j int) bool { return dimensionKey(dimensions[i]) < dimensionKey(dimensions[j]) })
	return runReferences, dimensions, provenance, nil
}

func dimensionFrom(run SelectedRun, lane scanrun.Lane, findingKind string) Dimension {
	state, reason := coverageDecision(run, lane)
	versions := make([]Version, 0, len(lane.Versions))
	for _, version := range lane.Versions {
		versions = append(versions, Version{Digest: version.Digest, Kind: version.VersionKind, Name: version.Name, Version: version.Version})
	}
	sort.Slice(versions, func(i, j int) bool {
		if versions[i].Kind != versions[j].Kind {
			return versions[i].Kind < versions[j].Kind
		}
		return versions[i].Name < versions[j].Name
	})
	return Dimension{
		ExcludedScope: sortedUnique(lane.ExcludedScope), FindingKind: findingKind,
		IncludedScope: sortedUnique(lane.IncludedScope), LaneKey: lane.LaneKey, LaneManifestHash: lane.ManifestHash,
		Producer: lane.Producer, ReasonCode: reason, RunID: run.ID, State: state,
		Target: Target{
			Canonical: lane.Target.TargetIdentityCanonical, EvaluatedRevision: lane.Target.EvaluatedRevision,
			Kind: lane.Target.TargetKind, SchemaVersion: lane.Target.TargetIdentitySchemaVersion,
		},
		Versions: versions,
	}
}

func validateSealedLane(lane scanrun.Lane) error {
	if err := lane.Validate(); err != nil {
		return err
	}
	if !lane.TerminalStatus.IsTerminal() || lane.SealedAt == nil || lane.SealedAt.IsZero() || !validSHA256(lane.ManifestHash) {
		return fmt.Errorf("%w: lane must have terminal, sealed provenance", shared.ErrValidation)
	}
	want, err := scanrun.ComputeManifestHash(lane)
	if err != nil {
		return err
	}
	if want != lane.ManifestHash {
		return fmt.Errorf("%w: lane manifest hash mismatch", shared.ErrValidation)
	}
	return nil
}

func coverageDecision(run SelectedRun, lane scanrun.Lane) (CoverageState, string) {
	if run.Provenance == scanrun.ProvenanceLegacy {
		return CoverageUnknown, ReasonLegacyProvenance
	}
	switch run.TerminalStatus {
	case scanrun.StatusFailed:
		return CoverageUnknown, ReasonRunFailed
	case scanrun.StatusCancelled:
		return CoverageUnknown, ReasonRunCancelled
	case scanrun.StatusPartial:
		return CoveragePartial, ReasonRunPartial
	}
	switch lane.TerminalStatus {
	case scanrun.StatusFailed:
		return CoverageUnknown, ReasonLaneFailed
	case scanrun.StatusCancelled:
		return CoverageUnknown, ReasonLaneCancelled
	case scanrun.StatusPartial:
		return CoveragePartial, ReasonLanePartial
	}
	for _, stage := range lane.Stages {
		if stage.Status == scanrun.StageFailed {
			return CoveragePartial, ReasonStageFailed
		}
		if stage.Status == scanrun.StageSkipped {
			return CoveragePartial, ReasonStageSkipped
		}
	}
	return CoverageComplete, ReasonTrustedTerminalLane
}

func (snapshot Snapshot) computeContentHash() (string, error) {
	type canonicalSnapshot struct {
		AssessmentID string         `json:"assessment_id"`
		Boundary     Boundary       `json:"boundary"`
		CycleID      string         `json:"cycle_id"`
		Dimensions   []Dimension    `json:"dimensions"`
		Provenance   Provenance     `json:"provenance"`
		RunRefs      []RunReference `json:"run_refs"`
		Schema       int            `json:"schema_version"`
		TenantID     string         `json:"tenant_id"`
	}
	// ponytail: this schema intentionally contains no maps or floating-point values; use a full
	// RFC 8785 encoder if future snapshot schemas add either.
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(canonicalSnapshot{
		AssessmentID: snapshot.AssessmentID.String(), Boundary: snapshot.Boundary,
		CycleID: snapshot.CycleID.String(), Dimensions: snapshot.Dimensions,
		Provenance: snapshot.Provenance, RunRefs: snapshot.RunReferences, Schema: snapshot.SchemaVersion,
		TenantID: snapshot.TenantID.String(),
	}); err != nil {
		return "", fmt.Errorf("marshal canonical assessment snapshot: %w", err)
	}
	sum := sha256.Sum256(bytes.TrimSuffix(buffer.Bytes(), []byte("\n")))
	return hex.EncodeToString(sum[:]), nil
}

func dimensionKey(dimension Dimension) string {
	return strings.Join([]string{string(dimension.Target.Kind), fmt.Sprintf("%d", dimension.Target.SchemaVersion), dimension.Target.Canonical, dimension.Producer, dimension.FindingKind}, "\x00")
}

func sortedUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func validSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func timePointer(value time.Time) *time.Time { return &value }
