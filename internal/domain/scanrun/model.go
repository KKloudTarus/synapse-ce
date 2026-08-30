package scanrun

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ProvenanceKind defines whether a scan run was generated via legacy opaque assertions or native sealed facts.
type ProvenanceKind string

const (
	ProvenanceLegacy ProvenanceKind = "legacy"
	ProvenanceNative ProvenanceKind = "native"
)

func (k ProvenanceKind) Valid() bool {
	switch k {
	case ProvenanceLegacy, ProvenanceNative:
		return true
	default:
		return false
	}
}

// TerminalStatus represents the execution outcome of a scan run or producer lane.
type TerminalStatus string

const (
	StatusBuilding  TerminalStatus = "building"
	StatusSucceeded TerminalStatus = "succeeded"
	StatusPartial   TerminalStatus = "partial"
	StatusFailed    TerminalStatus = "failed"
	StatusCancelled TerminalStatus = "cancelled"
	StatusUnknown   TerminalStatus = "unknown"
)

func (s TerminalStatus) Valid() bool {
	switch s {
	case StatusBuilding, StatusSucceeded, StatusPartial, StatusFailed, StatusCancelled, StatusUnknown:
		return true
	default:
		return false
	}
}

func (s TerminalStatus) IsTerminal() bool {
	switch s {
	case StatusSucceeded, StatusPartial, StatusFailed, StatusCancelled, StatusUnknown:
		return true
	default:
		return false
	}
}

// VersionKind classifies the components and dependencies contributing to a scan lane.
type VersionKind string

const (
	VersionTool        VersionKind = "tool"
	VersionScanner     VersionKind = "scanner"
	VersionProfile     VersionKind = "profile"
	VersionRulePack    VersionKind = "rule_pack"
	VersionAdvisoryDB  VersionKind = "advisory_database"
	VersionCorrelation VersionKind = "correlation"
	VersionSchema      VersionKind = "schema"
)

func (k VersionKind) Valid() bool {
	switch k {
	case VersionTool, VersionScanner, VersionProfile, VersionRulePack, VersionAdvisoryDB, VersionCorrelation, VersionSchema:
		return true
	default:
		return false
	}
}

// StageStatus represents the completion state of an individual pipeline stage within a lane.
type StageStatus string

const (
	StageSucceeded StageStatus = "succeeded"
	StageFailed    StageStatus = "failed"
	StageSkipped   StageStatus = "skipped"
)

func (s StageStatus) Valid() bool {
	switch s {
	case StageSucceeded, StageFailed, StageSkipped:
		return true
	default:
		return false
	}
}

// LaneVersion records an authoritative version fact for a tool, rule pack, or database.
type LaneVersion struct {
	VersionKind VersionKind `json:"version_kind"`
	Name        string      `json:"name"`
	Version     string      `json:"version"`
	Digest      string      `json:"digest,omitempty"`
}

func (v LaneVersion) Validate() error {
	if !v.VersionKind.Valid() {
		return fmt.Errorf("%w: invalid version kind %q", shared.ErrValidation, v.VersionKind)
	}
	if strings.TrimSpace(v.Name) == "" {
		return fmt.Errorf("%w: version component name is required", shared.ErrValidation)
	}
	if strings.TrimSpace(v.Version) == "" {
		return fmt.Errorf("%w: version string is required", shared.ErrValidation)
	}
	return nil
}

// LaneStage records the execution status and timing of a specific pipeline stage.
type LaneStage struct {
	StageKey   string      `json:"stage_key"`
	Status     StageStatus `json:"status"`
	ReasonCode string      `json:"reason_code,omitempty"`
	StartedAt  time.Time   `json:"started_at"`
	FinishedAt *time.Time  `json:"finished_at,omitempty"`
}

func (s LaneStage) Validate() error {
	if strings.TrimSpace(s.StageKey) == "" {
		return fmt.Errorf("%w: stage key is required", shared.ErrValidation)
	}
	if !s.Status.Valid() {
		return fmt.Errorf("%w: invalid stage status %q", shared.ErrValidation, s.Status)
	}
	if s.StartedAt.IsZero() {
		return fmt.Errorf("%w: stage started_at is required", shared.ErrValidation)
	}
	return nil
}

// Lane represents a normalized producer-lane provenance execution within a scan run.
type Lane struct {
	TenantID                  shared.ID      `json:"tenant_id"`
	EngagementID              shared.ID      `json:"engagement_id"`
	ScanRunID                 string         `json:"scan_run_id"`
	LaneKey                   string         `json:"lane_key"`
	Producer                  string         `json:"producer"`
	TerminalStatus            TerminalStatus `json:"terminal_status"`
	Target                    TargetIdentity `json:"target"`
	AuthoritativeFindingKinds []string       `json:"authoritative_finding_kinds"`
	IncludedScope             []string       `json:"included_scope"`
	ExcludedScope             []string       `json:"excluded_scope"`
	StartedAt                 time.Time      `json:"started_at"`
	FinishedAt                *time.Time     `json:"finished_at,omitempty"`
	ResultRef                 string         `json:"result_ref,omitempty"`
	EvidenceRef               string         `json:"evidence_ref,omitempty"`
	ResultSHA256              string         `json:"result_sha256,omitempty"`
	ManifestSchemaVersion     int            `json:"manifest_schema_version"`
	ManifestHash              string         `json:"manifest_hash"`
	SealedAt                  *time.Time     `json:"sealed_at,omitempty"`
	Versions                  []LaneVersion  `json:"versions,omitempty"`
	Stages                    []LaneStage    `json:"stages,omitempty"`
}

func (l Lane) Validate() error {
	if l.TenantID.IsZero() {
		return fmt.Errorf("%w: tenant ID is required", shared.ErrValidation)
	}
	if l.EngagementID.IsZero() {
		return fmt.Errorf("%w: engagement ID is required", shared.ErrValidation)
	}
	if strings.TrimSpace(l.ScanRunID) == "" {
		return fmt.Errorf("%w: scan run ID is required", shared.ErrValidation)
	}
	if strings.TrimSpace(l.LaneKey) == "" {
		return fmt.Errorf("%w: lane key is required", shared.ErrValidation)
	}
	if strings.TrimSpace(l.Producer) == "" {
		return fmt.Errorf("%w: producer is required", shared.ErrValidation)
	}
	if !l.TerminalStatus.Valid() {
		return fmt.Errorf("%w: invalid terminal status %q", shared.ErrValidation, l.TerminalStatus)
	}
	if err := l.Target.Validate(); err != nil {
		return fmt.Errorf("invalid lane target: %w", err)
	}
	if l.StartedAt.IsZero() {
		return fmt.Errorf("%w: started_at is required", shared.ErrValidation)
	}
	for _, v := range l.Versions {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("invalid lane version: %w", err)
		}
	}
	for _, s := range l.Stages {
		if err := s.Validate(); err != nil {
			return fmt.Errorf("invalid lane stage: %w", err)
		}
	}
	return nil
}

// ScanRun is the tenant-owned execution header aggregating one or more producer lanes.
type ScanRun struct {
	TenantID              shared.ID       `json:"tenant_id"`
	EngagementID          shared.ID       `json:"engagement_id"`
	ID                    string          `json:"id"`
	Provenance            ProvenanceKind  `json:"provenance"`
	TerminalStatus        TerminalStatus  `json:"terminal_status"`
	ManifestSchemaVersion int             `json:"manifest_schema_version"`
	ManifestHash          string          `json:"manifest_hash,omitempty"`
	SealedAt              *time.Time      `json:"sealed_at,omitempty"`
	CreatedAt             time.Time       `json:"created_at"`
	UpdatedAt             time.Time       `json:"updated_at"`
	LegacyManifest        json.RawMessage `json:"legacy_manifest,omitempty"`
	LegacyFindingKeys     []string        `json:"legacy_finding_keys,omitempty"`
	Lanes                 []Lane          `json:"lanes,omitempty"`
}

func (r ScanRun) Validate() error {
	if r.TenantID.IsZero() {
		return fmt.Errorf("%w: tenant ID is required", shared.ErrValidation)
	}
	if r.EngagementID.IsZero() {
		return fmt.Errorf("%w: engagement ID is required", shared.ErrValidation)
	}
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("%w: scan run ID is required", shared.ErrValidation)
	}
	if !r.Provenance.Valid() {
		return fmt.Errorf("%w: invalid provenance kind %q", shared.ErrValidation, r.Provenance)
	}
	if !r.TerminalStatus.Valid() {
		return fmt.Errorf("%w: invalid terminal status %q", shared.ErrValidation, r.TerminalStatus)
	}
	if r.CreatedAt.IsZero() {
		return fmt.Errorf("%w: created_at is required", shared.ErrValidation)
	}
	for _, lane := range r.Lanes {
		if err := lane.Validate(); err != nil {
			return fmt.Errorf("invalid scan run lane: %w", err)
		}
	}
	return nil
}

// IsSealed reports whether the scan run has been sealed into an immutable record.
func (r ScanRun) IsSealed() bool {
	return r.SealedAt != nil && !r.SealedAt.IsZero()
}

// IsCompleteCoverage checks whether a scan run satisfies the strict complete coverage trust contract.
// A run is complete ONLY if:
// 1. Provenance is native (legacy runs NEVER satisfy complete coverage)
// 2. Terminal status is succeeded (partial, failed, cancelled, unknown NEVER satisfy complete coverage)
// 3. The run is properly sealed with non-empty manifest hash and sealed timestamp
// 4. All lanes have non-empty authoritative finding kinds, valid target revisions, and terminal stages.
func (r ScanRun) IsCompleteCoverage() bool {
	if r.Provenance != ProvenanceNative {
		return false
	}
	if r.TerminalStatus != StatusSucceeded {
		return false
	}
	if !r.IsSealed() || strings.TrimSpace(r.ManifestHash) == "" {
		return false
	}
	if len(r.Lanes) == 0 {
		return false
	}
	for _, lane := range r.Lanes {
		if lane.TerminalStatus != StatusSucceeded {
			return false
		}
		if len(lane.AuthoritativeFindingKinds) == 0 {
			return false
		}
		if strings.TrimSpace(lane.ManifestHash) == "" {
			return false
		}
		if lane.SealedAt == nil || lane.SealedAt.IsZero() {
			return false
		}
		if err := lane.Target.Validate(); err != nil {
			return false
		}
	}
	return true
}

// CanonicalManifestEnvelope is the deterministic data structure hashed to produce manifest_hash.
type CanonicalManifestEnvelope struct {
	ManifestSchemaVersion     int           `json:"manifest_schema_version"`
	Producer                  string        `json:"producer"`
	TargetKind                TargetKind    `json:"target_kind"`
	TargetCanonical           string        `json:"target_canonical"`
	EvaluatedRevision         string        `json:"evaluated_revision,omitempty"`
	AuthoritativeFindingKinds []string      `json:"authoritative_finding_kinds"`
	IncludedScope             []string      `json:"included_scope"`
	ExcludedScope             []string      `json:"excluded_scope"`
	Versions                  []LaneVersion `json:"versions"`
	Stages                    []LaneStage   `json:"stages"`
	ResultSHA256              string        `json:"result_sha256,omitempty"`
}

// ComputeManifestHash calculates a deterministic SHA-256 hash for a producer lane's facts.
func ComputeManifestHash(lane Lane) (string, error) {
	// Normalize & sort slices to guarantee determinism
	findingKinds := make([]string, len(lane.AuthoritativeFindingKinds))
	copy(findingKinds, lane.AuthoritativeFindingKinds)
	sort.Strings(findingKinds)

	incScope := make([]string, len(lane.IncludedScope))
	copy(incScope, lane.IncludedScope)
	sort.Strings(incScope)

	excScope := make([]string, len(lane.ExcludedScope))
	copy(excScope, lane.ExcludedScope)
	sort.Strings(excScope)

	versions := make([]LaneVersion, len(lane.Versions))
	copy(versions, lane.Versions)
	sort.SliceStable(versions, func(i, j int) bool {
		if versions[i].VersionKind != versions[j].VersionKind {
			return versions[i].VersionKind < versions[j].VersionKind
		}
		return versions[i].Name < versions[j].Name
	})

	stages := make([]LaneStage, len(lane.Stages))
	copy(stages, lane.Stages)
	sort.SliceStable(stages, func(i, j int) bool {
		return stages[i].StageKey < stages[j].StageKey
	})

	schemaVer := lane.ManifestSchemaVersion
	if schemaVer < 1 {
		schemaVer = 1
	}

	envelope := CanonicalManifestEnvelope{
		ManifestSchemaVersion:     schemaVer,
		Producer:                  lane.Producer,
		TargetKind:                lane.Target.TargetKind,
		TargetCanonical:           lane.Target.TargetIdentityCanonical,
		EvaluatedRevision:         lane.Target.EvaluatedRevision,
		AuthoritativeFindingKinds: findingKinds,
		IncludedScope:             incScope,
		ExcludedScope:             excScope,
		Versions:                  versions,
		Stages:                    stages,
		ResultSHA256:              lane.ResultSHA256,
	}

	payload, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("marshal canonical manifest envelope: %w", err)
	}

	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}
