package findinglineage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	maxShortTextBytes  = 256
	maxReasonTextBytes = 2000
	maxReasonPayload   = 16
	maxCandidateRefs   = 64
	maxProvenanceText  = 512
)

type Identity struct {
	TenantID                    shared.ID
	CycleID                     shared.ID
	ID                          shared.ID
	ProducerKind                string
	FindingKind                 string
	CanonicalizationVersion     int
	FingerprintSchemaVersion    int
	LineageFingerprint          string
	TargetIdentitySchemaVersion int
	TargetIdentityCanonical     string
	CanonicalIdentityFields     []byte
	FirstSeenSnapshotID         shared.ID
	CreatedAt                   time.Time
}

func (identity Identity) Validate() error {
	if identity.TenantID.IsZero() || identity.CycleID.IsZero() || identity.ID.IsZero() || identity.FirstSeenSnapshotID.IsZero() {
		return fmt.Errorf("%w: finding identity ownership is required", shared.ErrValidation)
	}
	if err := validateShort("producer kind", identity.ProducerKind); err != nil {
		return err
	}
	if err := validateShort("finding kind", identity.FindingKind); err != nil {
		return err
	}
	if identity.CanonicalizationVersion != CanonicalizationVersionV1 || identity.FingerprintSchemaVersion <= 0 || identity.TargetIdentitySchemaVersion <= 0 {
		return fmt.Errorf("%w: finding identity versions are invalid", shared.ErrValidation)
	}
	if !validDigest(identity.LineageFingerprint) {
		return fmt.Errorf("%w: lineage fingerprint must be a SHA-256 digest", shared.ErrValidation)
	}
	if err := validateText("target identity", identity.TargetIdentityCanonical, maxCanonicalTextBytes); err != nil {
		return err
	}
	if err := validateCanonicalIdentityFields(identity.CanonicalIdentityFields); err != nil {
		return fmt.Errorf("validate canonical identity fields: %w", err)
	}
	if identity.CreatedAt.IsZero() {
		return fmt.Errorf("%w: finding identity creation time is required", shared.ErrValidation)
	}
	return nil
}

type Alias struct {
	TenantID        shared.ID
	CycleID         shared.ID
	ID              shared.ID
	IdentityID      shared.ID
	ProducerKind    string
	FindingKind     string
	TargetCanonical string
	SchemaVersion   int
	Fingerprint     string
	ApprovedBy      string
	ApprovedAt      time.Time
}

func (alias Alias) Validate() error {
	if alias.TenantID.IsZero() || alias.CycleID.IsZero() || alias.ID.IsZero() || alias.IdentityID.IsZero() {
		return fmt.Errorf("%w: alias ownership is required", shared.ErrValidation)
	}
	if err := validateShort("alias producer kind", alias.ProducerKind); err != nil {
		return err
	}
	if err := validateShort("alias finding kind", alias.FindingKind); err != nil {
		return err
	}
	if err := validateText("alias target", alias.TargetCanonical, maxCanonicalTextBytes); err != nil {
		return err
	}
	if alias.SchemaVersion <= 0 || !validDigest(alias.Fingerprint) {
		return fmt.Errorf("%w: alias schema and fingerprint are required", shared.ErrValidation)
	}
	if err := validateShort("alias approver", alias.ApprovedBy); err != nil {
		return err
	}
	if alias.ApprovedAt.IsZero() {
		return fmt.Errorf("%w: alias approval time is required", shared.ErrValidation)
	}
	return nil
}

type ScannerProvenance struct {
	ScanRunID   string `json:"scan_run_id,omitempty"`
	LaneKey     string `json:"lane_key,omitempty"`
	ToolName    string `json:"tool_name"`
	ToolVersion string `json:"tool_version,omitempty"`
	RuleID      string `json:"rule_id,omitempty"`
}

func (provenance ScannerProvenance) Validate() error {
	if err := validateShort("scanner tool name", provenance.ToolName); err != nil {
		return err
	}
	for label, value := range map[string]string{
		"scan run id": provenance.ScanRunID, "lane key": provenance.LaneKey,
		"tool version": provenance.ToolVersion, "rule id": provenance.RuleID,
	} {
		if value != "" {
			if err := validateText(label, value, maxProvenanceText); err != nil {
				return err
			}
		}
	}
	return nil
}

type Observation struct {
	TenantID           shared.ID
	CycleID            shared.ID
	ID                 shared.ID
	SnapshotID         shared.ID
	IdentityID         shared.ID
	ProducerKind       string
	FindingKind        string
	TargetCanonical    string
	SourceFindingID    string
	SourceOccurrenceID string
	Severity           shared.Severity
	RiskScoreMilli     *int
	ComponentVersion   string
	Location           string
	Reachability       string
	EvidenceDigest     string
	ScannerProvenance  ScannerProvenance
	ObservedAt         time.Time
}

func (observation Observation) Validate() error {
	if observation.TenantID.IsZero() || observation.CycleID.IsZero() || observation.ID.IsZero() || observation.SnapshotID.IsZero() || observation.IdentityID.IsZero() {
		return fmt.Errorf("%w: finding observation ownership is required", shared.ErrValidation)
	}
	if err := validateShort("observation producer kind", observation.ProducerKind); err != nil {
		return err
	}
	if err := validateShort("observation finding kind", observation.FindingKind); err != nil {
		return err
	}
	if err := validateText("observation target", observation.TargetCanonical, maxCanonicalTextBytes); err != nil {
		return err
	}
	if observation.SourceFindingID == "" && observation.SourceOccurrenceID == "" {
		return fmt.Errorf("%w: source finding or occurrence id is required", shared.ErrValidation)
	}
	for label, value := range map[string]string{
		"source finding id": observation.SourceFindingID, "source occurrence id": observation.SourceOccurrenceID,
		"component version": observation.ComponentVersion, "location": observation.Location, "reachability": observation.Reachability,
	} {
		if value != "" {
			if err := validateText(label, value, maxProvenanceText); err != nil {
				return err
			}
		}
	}
	if !observation.Severity.Valid() {
		return fmt.Errorf("%w: observation severity is invalid", shared.ErrValidation)
	}
	if observation.RiskScoreMilli != nil && (*observation.RiskScoreMilli < 0 || *observation.RiskScoreMilli > 10000) {
		return fmt.Errorf("%w: risk score must be between 0 and 10000 milli-points", shared.ErrValidation)
	}
	if observation.EvidenceDigest != "" && !validDigest(observation.EvidenceDigest) {
		return fmt.Errorf("%w: evidence digest must be a SHA-256 digest", shared.ErrValidation)
	}
	if err := observation.ScannerProvenance.Validate(); err != nil {
		return err
	}
	if observation.ObservedAt.IsZero() {
		return fmt.Errorf("%w: observation time is required", shared.ErrValidation)
	}
	return nil
}

type CandidateReason string

const (
	ReasonFingerprintCollision CandidateReason = "fingerprint_collision"
	ReasonSplit                CandidateReason = "split"
	ReasonMerge                CandidateReason = "merge"
	ReasonInsufficientAnchor   CandidateReason = "insufficient_anchor"
	ReasonLegacyAmbiguous      CandidateReason = "legacy_ambiguous"
)

func (reason CandidateReason) Valid() bool {
	switch reason {
	case ReasonFingerprintCollision, ReasonSplit, ReasonMerge, ReasonInsufficientAnchor, ReasonLegacyAmbiguous:
		return true
	}
	return false
}

type CandidateStatus string

const (
	CandidateOpen       CandidateStatus = "open"
	CandidateResolved   CandidateStatus = "resolved"
	CandidateSuperseded CandidateStatus = "superseded"
)

func (status CandidateStatus) Valid() bool {
	return status == CandidateOpen || status == CandidateResolved || status == CandidateSuperseded
}

type ReferenceRole string

const (
	RoleSource    ReferenceRole = "source"
	RoleCandidate ReferenceRole = "candidate"
	RoleSelected  ReferenceRole = "selected"
	RoleExcluded  ReferenceRole = "excluded"
)

func (role ReferenceRole) Valid() bool {
	return role == RoleSource || role == RoleCandidate || role == RoleSelected || role == RoleExcluded
}

type MatchMethod string

const (
	MethodOverride    MatchMethod = "override"
	MethodProducerID  MatchMethod = "producer_id"
	MethodFingerprint MatchMethod = "fingerprint"
	MethodAlias       MatchMethod = "alias"
	MethodMatcher     MatchMethod = "matcher"
	MethodManual      MatchMethod = "manual"
	MethodNewIdentity MatchMethod = "new_identity"
)

func (method MatchMethod) Valid() bool {
	switch method {
	case MethodOverride, MethodProducerID, MethodFingerprint, MethodAlias, MethodMatcher, MethodManual, MethodNewIdentity:
		return true
	}
	return false
}

type Confidence string

const (
	ConfidenceUnknown Confidence = "unknown"
	ConfidenceLow     Confidence = "low"
	ConfidenceMedium  Confidence = "medium"
	ConfidenceHigh    Confidence = "high"
)

func (confidence Confidence) Valid() bool {
	return confidence == ConfidenceUnknown || confidence == ConfidenceLow || confidence == ConfidenceMedium || confidence == ConfidenceHigh
}

type CandidateRef struct {
	Position              int               `json:"position"`
	Role                  ReferenceRole     `json:"role"`
	IdentityID            shared.ID         `json:"identity_id,omitempty"`
	ObservationID         shared.ID         `json:"observation_id,omitempty"`
	ExternalReferenceHash string            `json:"external_reference_hash,omitempty"`
	Method                MatchMethod       `json:"method"`
	ScoreMilli            int               `json:"score_milli"`
	Confidence            Confidence        `json:"confidence"`
	ReasonPayload         map[string]string `json:"reason_payload,omitempty"`
}

func (reference CandidateRef) Validate() error {
	if reference.Position < 0 || !reference.Role.Valid() || !reference.Method.Valid() || !reference.Confidence.Valid() {
		return fmt.Errorf("%w: candidate reference metadata is invalid", shared.ErrValidation)
	}
	count := 0
	if !reference.IdentityID.IsZero() {
		count++
	}
	if !reference.ObservationID.IsZero() {
		count++
	}
	if reference.ExternalReferenceHash != "" {
		count++
		if !validDigest(reference.ExternalReferenceHash) {
			return fmt.Errorf("%w: external reference hash is invalid", shared.ErrValidation)
		}
	}
	if count != 1 {
		return fmt.Errorf("%w: candidate reference must identify exactly one subject", shared.ErrValidation)
	}
	if reference.ScoreMilli < 0 || reference.ScoreMilli > 1000 {
		return fmt.Errorf("%w: candidate reference score is invalid", shared.ErrValidation)
	}
	return validateReasonPayload(reference.ReasonPayload)
}

type MatchCandidate struct {
	TenantID                 shared.ID
	CycleID                  shared.ID
	SnapshotID               shared.ID
	ID                       shared.ID
	ProducerKind             string
	FindingKind              string
	Reason                   CandidateReason
	FingerprintSchemaVersion int
	Fingerprint              string
	SourceReferenceHash      string
	CandidateSetHash         string
	Status                   CandidateStatus
	Version                  int64
	Refs                     []CandidateRef
	CreatedAt                time.Time
	ResolvedAt               *time.Time
	SupersededAt             *time.Time
	SupersededByCandidateID  shared.ID
}

func NewMatchCandidate(candidate MatchCandidate) (MatchCandidate, error) {
	candidate.Status = CandidateOpen
	candidate.Version = 1
	candidate.ResolvedAt = nil
	candidate.SupersededAt = nil
	candidate.SupersededByCandidateID = ""
	refs, hash, err := normalizeCandidateRefs(candidate.Refs)
	if err != nil {
		return MatchCandidate{}, err
	}
	candidate.Refs, candidate.CandidateSetHash = refs, hash
	if candidate.SourceReferenceHash == "" {
		for _, reference := range refs {
			if reference.Role == RoleSource && reference.ExternalReferenceHash != "" {
				candidate.SourceReferenceHash = reference.ExternalReferenceHash
				break
			}
		}
	}
	if err := candidate.Validate(); err != nil {
		return MatchCandidate{}, err
	}
	return candidate, nil
}

func (candidate MatchCandidate) Validate() error {
	if candidate.TenantID.IsZero() || candidate.CycleID.IsZero() || candidate.SnapshotID.IsZero() || candidate.ID.IsZero() {
		return fmt.Errorf("%w: match candidate ownership is required", shared.ErrValidation)
	}
	if err := validateShort("candidate producer kind", candidate.ProducerKind); err != nil {
		return err
	}
	if err := validateShort("candidate finding kind", candidate.FindingKind); err != nil {
		return err
	}
	if !candidate.Reason.Valid() || !candidate.Status.Valid() || candidate.Version <= 0 {
		return fmt.Errorf("%w: match candidate lifecycle is invalid", shared.ErrValidation)
	}
	if candidate.Fingerprint == "" {
		if candidate.Reason != ReasonInsufficientAnchor || candidate.FingerprintSchemaVersion < 0 {
			return fmt.Errorf("%w: candidate fingerprint is required", shared.ErrValidation)
		}
	} else if candidate.FingerprintSchemaVersion <= 0 || !validDigest(candidate.Fingerprint) {
		return fmt.Errorf("%w: candidate fingerprint is invalid", shared.ErrValidation)
	}
	if !validDigest(candidate.CandidateSetHash) {
		return fmt.Errorf("%w: candidate set hash is invalid", shared.ErrValidation)
	}
	if !validDigest(candidate.SourceReferenceHash) {
		return fmt.Errorf("%w: candidate source reference hash is invalid", shared.ErrValidation)
	}
	if len(candidate.Refs) == 0 || len(candidate.Refs) > maxCandidateRefs {
		return fmt.Errorf("%w: candidate must contain 1-%d references", shared.ErrValidation, maxCandidateRefs)
	}
	for position, reference := range candidate.Refs {
		if reference.Position != position {
			return fmt.Errorf("%w: candidate reference positions must be contiguous", shared.ErrValidation)
		}
		if err := reference.Validate(); err != nil {
			return err
		}
	}
	if candidate.CreatedAt.IsZero() {
		return fmt.Errorf("%w: candidate creation time is required", shared.ErrValidation)
	}
	switch candidate.Status {
	case CandidateOpen:
		if candidate.ResolvedAt != nil || candidate.SupersededAt != nil || !candidate.SupersededByCandidateID.IsZero() {
			return fmt.Errorf("%w: open candidate has terminal metadata", shared.ErrValidation)
		}
	case CandidateResolved:
		if candidate.ResolvedAt == nil || candidate.SupersededAt != nil || !candidate.SupersededByCandidateID.IsZero() {
			return fmt.Errorf("%w: resolved candidate metadata is invalid", shared.ErrValidation)
		}
	case CandidateSuperseded:
		if candidate.SupersededAt == nil || candidate.SupersededByCandidateID.IsZero() || candidate.ResolvedAt != nil {
			return fmt.Errorf("%w: superseded candidate metadata is invalid", shared.ErrValidation)
		}
	}
	return nil
}

type ResolutionAction string

const (
	ResolutionConfirmExisting        ResolutionAction = "confirm_existing"
	ResolutionCreateDistinctIdentity ResolutionAction = "create_distinct_identity"
	ResolutionUnlink                 ResolutionAction = "unlink"
	ResolutionDismiss                ResolutionAction = "dismiss"
	ResolutionSupersede              ResolutionAction = "supersede"
)

func (action ResolutionAction) Valid() bool {
	switch action {
	case ResolutionConfirmExisting, ResolutionCreateDistinctIdentity, ResolutionUnlink, ResolutionDismiss, ResolutionSupersede:
		return true
	}
	return false
}

type ResolutionEvent struct {
	TenantID             shared.ID
	CycleID              shared.ID
	CandidateID          shared.ID
	ID                   shared.ID
	Action               ResolutionAction
	Actor                string
	Reason               string
	BeforeRefs           []CandidateRef
	AfterRefs            []CandidateRef
	SuccessorCandidateID shared.ID
	ExpectedVersion      int64
	Version              int64
	PriorEventID         shared.ID
	ContentHash          string
	CreatedAt            time.Time
}

func (event ResolutionEvent) Validate() error {
	if event.TenantID.IsZero() || event.CycleID.IsZero() || event.CandidateID.IsZero() || event.ID.IsZero() || !event.Action.Valid() {
		return fmt.Errorf("%w: resolution event ownership is invalid", shared.ErrValidation)
	}
	if err := validateShort("resolution actor", event.Actor); err != nil {
		return err
	}
	if err := validateText("resolution reason", event.Reason, maxReasonTextBytes); err != nil {
		return err
	}
	if event.ExpectedVersion <= 0 || event.Version != event.ExpectedVersion+1 || event.CreatedAt.IsZero() {
		return fmt.Errorf("%w: resolution event version is invalid", shared.ErrValidation)
	}
	if event.Action == ResolutionSupersede {
		if event.SuccessorCandidateID.IsZero() {
			return fmt.Errorf("%w: supersede resolution requires a successor candidate", shared.ErrValidation)
		}
	} else if !event.SuccessorCandidateID.IsZero() {
		return fmt.Errorf("%w: successor candidate is only valid for supersede", shared.ErrValidation)
	}
	for _, refs := range [][]CandidateRef{event.BeforeRefs, event.AfterRefs} {
		if len(refs) == 0 {
			continue
		}
		if _, _, err := normalizeCandidateRefs(refs); err != nil {
			return err
		}
	}
	hash, err := hashResolutionEvent(event)
	if err != nil {
		return err
	}
	if event.ContentHash != hash {
		return fmt.Errorf("%w: resolution event content hash is invalid", shared.ErrValidation)
	}
	return nil
}

func ResolveCandidate(candidate MatchCandidate, eventID shared.ID, action ResolutionAction, actor, reason string, afterRefs []CandidateRef, successorCandidateID shared.ID, expectedVersion int64, priorEventID shared.ID, now time.Time) (MatchCandidate, ResolutionEvent, error) {
	if candidate.Status != CandidateOpen || candidate.Version != expectedVersion {
		return MatchCandidate{}, ResolutionEvent{}, fmt.Errorf("%w: candidate version or status changed", shared.ErrConflict)
	}
	if eventID.IsZero() || !action.Valid() || now.IsZero() {
		return MatchCandidate{}, ResolutionEvent{}, fmt.Errorf("%w: resolution event metadata is invalid", shared.ErrValidation)
	}
	if err := validateShort("resolution actor", actor); err != nil {
		return MatchCandidate{}, ResolutionEvent{}, err
	}
	if err := validateText("resolution reason", reason, maxReasonTextBytes); err != nil {
		return MatchCandidate{}, ResolutionEvent{}, err
	}
	normalizedAfter, _, err := normalizeCandidateRefs(afterRefs)
	if err != nil && !(action == ResolutionDismiss && len(afterRefs) == 0) {
		return MatchCandidate{}, ResolutionEvent{}, err
	}
	updated := candidate
	updated.Version++
	if action == ResolutionSupersede {
		if successorCandidateID.IsZero() {
			return MatchCandidate{}, ResolutionEvent{}, fmt.Errorf("%w: supersede resolution requires a successor candidate", shared.ErrValidation)
		}
		updated.Status = CandidateSuperseded
		updated.SupersededAt = &now
		updated.SupersededByCandidateID = successorCandidateID
	} else {
		if !successorCandidateID.IsZero() {
			return MatchCandidate{}, ResolutionEvent{}, fmt.Errorf("%w: successor candidate is only valid for supersede", shared.ErrValidation)
		}
		updated.Status = CandidateResolved
		updated.ResolvedAt = &now
	}
	event := ResolutionEvent{
		TenantID: candidate.TenantID, CycleID: candidate.CycleID, CandidateID: candidate.ID, ID: eventID,
		Action: action, Actor: strings.TrimSpace(actor), Reason: strings.TrimSpace(reason),
		BeforeRefs: cloneCandidateRefs(candidate.Refs), AfterRefs: normalizedAfter,
		SuccessorCandidateID: successorCandidateID, ExpectedVersion: expectedVersion,
		Version: updated.Version, PriorEventID: priorEventID, CreatedAt: now,
	}
	event.ContentHash, err = hashResolutionEvent(event)
	if err != nil {
		return MatchCandidate{}, ResolutionEvent{}, err
	}
	return updated, event, nil
}

type OverrideAction string

const (
	OverrideConfirm   OverrideAction = "confirm"
	OverrideUnlink    OverrideAction = "unlink"
	OverrideSupersede OverrideAction = "supersede"
)

func (action OverrideAction) Valid() bool {
	return action == OverrideConfirm || action == OverrideUnlink || action == OverrideSupersede
}

type OverrideEvent struct {
	TenantID            shared.ID
	CycleID             shared.ID
	ID                  shared.ID
	Action              OverrideAction
	SourceObservationID shared.ID
	SourceIdentityID    shared.ID
	TargetObservationID shared.ID
	TargetIdentityID    shared.ID
	Actor               string
	Reason              string
	ExpectedVersion     int64
	Version             int64
	PriorEventID        shared.ID
	ContentHash         string
	CreatedAt           time.Time
}

func NewOverrideEvent(event OverrideEvent) (OverrideEvent, error) {
	if event.TenantID.IsZero() || event.CycleID.IsZero() || event.ID.IsZero() || event.SourceObservationID.IsZero() || event.TargetIdentityID.IsZero() {
		return OverrideEvent{}, fmt.Errorf("%w: override ownership and references are required", shared.ErrValidation)
	}
	if !event.Action.Valid() || event.ExpectedVersion < 0 || event.Version != event.ExpectedVersion+1 || event.CreatedAt.IsZero() {
		return OverrideEvent{}, fmt.Errorf("%w: override lifecycle metadata is invalid", shared.ErrValidation)
	}
	if err := validateShort("override actor", event.Actor); err != nil {
		return OverrideEvent{}, err
	}
	if err := validateText("override reason", event.Reason, maxReasonTextBytes); err != nil {
		return OverrideEvent{}, err
	}
	event.Actor, event.Reason = strings.TrimSpace(event.Actor), strings.TrimSpace(event.Reason)
	hash, err := hashOverrideEvent(event)
	if err != nil {
		return OverrideEvent{}, err
	}
	event.ContentHash = hash
	return event, nil
}

func (event OverrideEvent) Validate() error {
	validated, err := NewOverrideEvent(event)
	if err != nil {
		return err
	}
	if event.ContentHash != validated.ContentHash {
		return fmt.Errorf("%w: override event content hash is invalid", shared.ErrValidation)
	}
	return nil
}

type SkipReason string

const (
	SkipInvalidTrust      SkipReason = "invalid_trust"
	SkipInvalidOwnership  SkipReason = "invalid_ownership"
	SkipRedactionRequired SkipReason = "redaction_required"
)

func (reason SkipReason) Valid() bool {
	return reason == SkipInvalidTrust || reason == SkipInvalidOwnership || reason == SkipRedactionRequired
}

type SkipRecord struct {
	TenantID            shared.ID
	CycleID             shared.ID
	SnapshotID          shared.ID
	ID                  shared.ID
	ProducerKind        string
	FindingKind         string
	Reason              SkipReason
	SourceReferenceHash string
	DetailCode          string
	CreatedAt           time.Time
}

func (record SkipRecord) Validate() error {
	if record.TenantID.IsZero() || record.CycleID.IsZero() || record.SnapshotID.IsZero() || record.ID.IsZero() {
		return fmt.Errorf("%w: skip record ownership is required", shared.ErrValidation)
	}
	if err := validateShort("skip producer kind", record.ProducerKind); err != nil {
		return err
	}
	if err := validateShort("skip finding kind", record.FindingKind); err != nil {
		return err
	}
	if !record.Reason.Valid() || !validDigest(record.SourceReferenceHash) {
		return fmt.Errorf("%w: skip record reason or source hash is invalid", shared.ErrValidation)
	}
	if err := validateShort("skip detail code", record.DetailCode); err != nil {
		return err
	}
	if record.CreatedAt.IsZero() {
		return fmt.Errorf("%w: skip record creation time is required", shared.ErrValidation)
	}
	return nil
}

func SourceReferenceHash(producerKind, findingKind, targetCanonical, sourceFindingID, sourceOccurrenceID string) (string, error) {
	values := []string{producerKind, findingKind, targetCanonical, sourceFindingID, sourceOccurrenceID}
	for index, value := range values {
		if index < 3 || value != "" {
			if _, err := canonicalRequiredText("source reference", value, maxCanonicalTextBytes); err != nil {
				return "", err
			}
		}
	}
	if sourceFindingID == "" && sourceOccurrenceID == "" {
		return "", fmt.Errorf("%w: source finding or occurrence id is required", shared.ErrValidation)
	}
	payload := strings.Join(values, "\x00")
	digest := sha256.Sum256(append([]byte("synapse:finding-source:v1\x00"), []byte(payload)...))
	return hex.EncodeToString(digest[:]), nil
}

func normalizeCandidateRefs(input []CandidateRef) ([]CandidateRef, string, error) {
	if len(input) == 0 || len(input) > maxCandidateRefs {
		return nil, "", fmt.Errorf("%w: candidate must contain 1-%d references", shared.ErrValidation, maxCandidateRefs)
	}
	refs := cloneCandidateRefs(input)
	sort.Slice(refs, func(left, right int) bool { return refs[left].Position < refs[right].Position })
	for position := range refs {
		if refs[position].ReasonPayload == nil {
			refs[position].ReasonPayload = map[string]string{}
		}
		if refs[position].Position != position {
			return nil, "", fmt.Errorf("%w: candidate reference positions must be contiguous", shared.ErrValidation)
		}
		if err := refs[position].Validate(); err != nil {
			return nil, "", err
		}
	}
	canonicalRefs := make([]CanonicalValue, 0, len(refs))
	for _, reference := range refs {
		fields := map[string]CanonicalValue{
			"confidence":  Text(string(reference.Confidence)),
			"method":      Text(string(reference.Method)),
			"position":    Integer(int64(reference.Position)),
			"role":        Text(string(reference.Role)),
			"score_milli": Integer(int64(reference.ScoreMilli)),
		}
		if !reference.IdentityID.IsZero() {
			fields["identity_id"] = Text(reference.IdentityID.String())
		}
		if !reference.ObservationID.IsZero() {
			fields["observation_id"] = Text(reference.ObservationID.String())
		}
		if reference.ExternalReferenceHash != "" {
			fields["external_reference_hash"] = Text(reference.ExternalReferenceHash)
		}
		if len(reference.ReasonPayload) > 0 {
			payload := make(map[string]CanonicalValue, len(reference.ReasonPayload))
			for key, value := range reference.ReasonPayload {
				payload[key] = Text(value)
			}
			fields["reason_payload"] = Object(payload)
		}
		canonicalRefs = append(canonicalRefs, Object(fields))
	}
	serialized, err := serializeCanonical(OrderedArray(canonicalRefs...))
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(append([]byte("synapse:finding-match-candidate:v1\x00"), serialized...))
	return refs, hex.EncodeToString(digest[:]), nil
}

func validateReasonPayload(payload map[string]string) error {
	if len(payload) > maxReasonPayload {
		return fmt.Errorf("%w: candidate reason payload exceeds %d fields", shared.ErrValidation, maxReasonPayload)
	}
	for key, value := range payload {
		if _, err := canonicalKey(key); err != nil {
			if errors.Is(err, ErrSensitiveInput) {
				return fmt.Errorf("%w: candidate reason payload contains a sensitive key", shared.ErrValidation)
			}
			return err
		}
		if err := validateText("candidate reason payload", value, maxShortTextBytes); err != nil {
			return err
		}
	}
	return nil
}

func validateShort(label, value string) error {
	return validateText(label, value, maxShortTextBytes)
}

func validateText(label, value string, limit int) error {
	value = strings.TrimSpace(value)
	if value == "" || !utf8.ValidString(value) || len(value) > limit {
		return fmt.Errorf("%w: %s is required, valid UTF-8, and at most %d bytes", shared.ErrValidation, label, limit)
	}
	for _, char := range value {
		if char < 32 && char != '\n' && char != '\t' {
			return fmt.Errorf("%w: %s contains invalid control characters", shared.ErrValidation, label)
		}
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func cloneCandidateRefs(input []CandidateRef) []CandidateRef {
	output := make([]CandidateRef, len(input))
	for index, reference := range input {
		output[index] = reference
		if reference.ReasonPayload != nil {
			output[index].ReasonPayload = make(map[string]string, len(reference.ReasonPayload))
			for key, value := range reference.ReasonPayload {
				output[index].ReasonPayload[key] = value
			}
		}
	}
	return output
}

func hashResolutionEvent(event ResolutionEvent) (string, error) {
	beforeRefs := event.BeforeRefs
	if beforeRefs == nil {
		beforeRefs = []CandidateRef{}
	}
	afterRefs := event.AfterRefs
	if afterRefs == nil {
		afterRefs = []CandidateRef{}
	}
	payload, err := json.Marshal(struct {
		Action               ResolutionAction `json:"action"`
		Actor                string           `json:"actor"`
		AfterRefs            []CandidateRef   `json:"after_refs"`
		BeforeRefs           []CandidateRef   `json:"before_refs"`
		CandidateID          shared.ID        `json:"candidate_id"`
		ExpectedVersion      int64            `json:"expected_version"`
		PriorEventID         shared.ID        `json:"prior_event_id,omitempty"`
		Reason               string           `json:"reason"`
		SuccessorCandidateID shared.ID        `json:"successor_candidate_id,omitempty"`
		Version              int64            `json:"version"`
	}{event.Action, event.Actor, afterRefs, beforeRefs, event.CandidateID, event.ExpectedVersion, event.PriorEventID, event.Reason, event.SuccessorCandidateID, event.Version})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("synapse:finding-resolution:v1\x00"), payload...))
	return hex.EncodeToString(digest[:]), nil
}

func hashOverrideEvent(event OverrideEvent) (string, error) {
	payload, err := json.Marshal(struct {
		Action              OverrideAction `json:"action"`
		Actor               string         `json:"actor"`
		ExpectedVersion     int64          `json:"expected_version"`
		PriorEventID        shared.ID      `json:"prior_event_id,omitempty"`
		Reason              string         `json:"reason"`
		SourceIdentityID    shared.ID      `json:"source_identity_id,omitempty"`
		SourceObservationID shared.ID      `json:"source_observation_id"`
		TargetIdentityID    shared.ID      `json:"target_identity_id"`
		TargetObservationID shared.ID      `json:"target_observation_id,omitempty"`
		Version             int64          `json:"version"`
	}{event.Action, event.Actor, event.ExpectedVersion, event.PriorEventID, event.Reason, event.SourceIdentityID, event.SourceObservationID, event.TargetIdentityID, event.TargetObservationID, event.Version})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("synapse:finding-override:v1\x00"), payload...))
	return hex.EncodeToString(digest[:]), nil
}
