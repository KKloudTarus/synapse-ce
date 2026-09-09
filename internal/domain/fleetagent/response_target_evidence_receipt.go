package fleetagent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ResponseTargetEvidenceReceipt is the immutable, server-generated snapshot of bounded target-primary
// telemetry. It is deliberately independent of the observer that later purpose-signs its binding.
type ResponseTargetEvidenceReceipt struct {
	Version               int                            `json:"version"`
	ReceiptID             shared.ID                      `json:"receipt_id"`
	Digest                string                         `json:"digest"`
	TenantID              shared.ID                      `json:"tenant_id"`
	EngagementID          shared.ID                      `json:"engagement_id"`
	ActionID              shared.ID                      `json:"action_id"`
	ActionDigest          string                         `json:"action_digest"`
	AttemptKey            string                         `json:"attempt_key"`
	VerificationChallenge string                         `json:"verification_challenge"`
	Target                responsesaga.TargetFingerprint `json:"target"`
	Reversal              bool                           `json:"reversal"`
	AttemptedAt           time.Time                      `json:"attempted_at"`
	WindowUntil           time.Time                      `json:"window_until"`
	RecordedAt            time.Time                      `json:"recorded_at"`
	SourceAgentID         shared.ID                      `json:"source_agent_id"`
	SourceAgentSessionID  shared.ID                      `json:"source_agent_session_id"`
	SourceHostID          shared.ID                      `json:"source_host_id"`
	Timeline              []endpoint.TimelineEntry       `json:"timeline"`
	Coverage              []sensorstate.CoverageWindow   `json:"coverage"`
	TimelineComplete      bool                           `json:"timeline_complete"`
	CoverageComplete      bool                           `json:"coverage_complete"`
	Saturated             bool                           `json:"saturated"`
	Reasons               []string                       `json:"reasons"`
}

const ResponseTargetEvidenceReceiptVersion = 1

func (r ResponseTargetEvidenceReceipt) Validate() error {
	if r.Version != ResponseTargetEvidenceReceiptVersion || r.ReceiptID.IsZero() || r.TenantID.IsZero() || r.EngagementID.IsZero() || r.ActionID.IsZero() ||
		strings.TrimSpace(r.AttemptKey) == "" || r.AttemptedAt.IsZero() || r.WindowUntil.IsZero() || r.RecordedAt.IsZero() || r.WindowUntil.Before(r.AttemptedAt) || r.RecordedAt.Before(r.WindowUntil) {
		return fmt.Errorf("%w: target evidence receipt has incomplete immutable identity", shared.ErrValidation)
	}
	if err := r.Target.Validate(); err != nil || r.Target.Kind != responsesaga.FingerprintProcess || r.Target.ProcessAssetID.IsZero() {
		return fmt.Errorf("%w: target evidence receipt has invalid target", shared.ErrValidation)
	}
	for _, raw := range []string{r.Digest, r.ActionDigest, r.VerificationChallenge} {
		decoded, err := hex.DecodeString(strings.TrimSpace(raw))
		if err != nil || len(decoded) != sha256.Size {
			return fmt.Errorf("%w: target evidence receipt has invalid digest binding", shared.ErrValidation)
		}
	}
	if len(r.Reasons) == 0 || !sortedUnique(r.Reasons) {
		return fmt.Errorf("%w: target evidence receipt must state sorted completeness reasons", shared.ErrValidation)
	}
	complete := r.TimelineComplete && r.CoverageComplete && !r.Saturated
	if complete && (r.SourceAgentID.IsZero() || r.SourceAgentSessionID.IsZero() || r.SourceHostID.IsZero() || len(r.Reasons) != 1 || r.Reasons[0] != "complete") {
		return fmt.Errorf("%w: complete target evidence receipt has inconsistent source or reasons", shared.ErrValidation)
	}
	if !complete && containsReason(r.Reasons, "complete") {
		return fmt.Errorf("%w: incomplete target evidence receipt cannot claim complete", shared.ErrValidation)
	}
	if !complete && (r.SourceAgentID.IsZero() != r.SourceAgentSessionID.IsZero() || r.SourceAgentID.IsZero() != r.SourceHostID.IsZero()) {
		return fmt.Errorf("%w: incomplete target evidence receipt has partial source identity", shared.ErrValidation)
	}
	if !complete && r.SourceAgentID.IsZero() && (len(r.Reasons) != 1 || (r.Reasons[0] != "source_missing" && r.Reasons[0] != "source_ambiguous" && r.Reasons[0] != "source_stale")) {
		return fmt.Errorf("%w: source-less target evidence receipt has inconsistent reasons", shared.ErrValidation)
	}
	if r.Saturated && r.TimelineComplete && r.CoverageComplete {
		return fmt.Errorf("%w: saturated target evidence receipt cannot claim complete evidence", shared.ErrValidation)
	}
	if r.SourceAgentID.IsZero() && (len(r.Timeline) != 0 || len(r.Coverage) != 0) {
		return fmt.Errorf("%w: source-less receipt cannot contain evidence", shared.ErrValidation)
	}
	for i, entry := range r.Timeline {
		if entry.TenantID != r.TenantID || entry.AssetID != r.Target.ProcessAssetID || entry.SourceAgentID != r.SourceAgentID || entry.SourceAgentSessionID != r.SourceAgentSessionID || entry.EventID.IsZero() || entry.OccurredAt.Before(r.AttemptedAt) || entry.OccurredAt.After(r.WindowUntil) ||
			(i > 0 && (r.Timeline[i-1].OccurredAt.After(entry.OccurredAt) || (r.Timeline[i-1].OccurredAt.Equal(entry.OccurredAt) && r.Timeline[i-1].EventID >= entry.EventID))) {
			return fmt.Errorf("%w: target evidence receipt contains unbound or non-canonical timeline evidence", shared.ErrValidation)
		}
	}
	for i, window := range r.Coverage {
		if err := window.Validate(); err != nil || window.AssetID != r.Target.ProcessAssetID || window.AgentID != r.SourceAgentID || window.HostID != r.SourceHostID || !window.Until.After(r.AttemptedAt) || !window.Since.Before(r.WindowUntil) ||
			(i > 0 && !coverageWindowLess(r.Coverage[i-1], window)) {
			return fmt.Errorf("%w: target evidence receipt contains unbound or non-canonical coverage evidence", shared.ErrValidation)
		}
	}
	if r.Saturated != (containsReason(r.Reasons, "timeline_saturated") || containsReason(r.Reasons, "coverage_saturated")) {
		return fmt.Errorf("%w: target evidence receipt saturation does not match its reasons", shared.ErrValidation)
	}
	if r.Digest != ResponseTargetEvidenceReceiptDigest(r) {
		return fmt.Errorf("%w: target evidence receipt digest does not cover immutable facts", shared.ErrValidation)
	}
	return nil
}

// CloneResponseTargetEvidenceReceipt returns an independent copy of every mutable receipt field.
func CloneResponseTargetEvidenceReceipt(r ResponseTargetEvidenceReceipt) ResponseTargetEvidenceReceipt {
	if r.Timeline != nil {
		r.Timeline = append(make([]endpoint.TimelineEntry, 0, len(r.Timeline)), r.Timeline...)
	}
	if r.Coverage != nil {
		r.Coverage = append(make([]sensorstate.CoverageWindow, 0, len(r.Coverage)), r.Coverage...)
	}
	for i := range r.Coverage {
		if r.Coverage[i].States != nil {
			r.Coverage[i].States = append(make([]detection.ClassCoverage, 0, len(r.Coverage[i].States)), r.Coverage[i].States...)
		}
		if r.Coverage[i].Vector.Reasons != nil {
			r.Coverage[i].Vector.Reasons = append(make([]string, 0, len(r.Coverage[i].Vector.Reasons)), r.Coverage[i].Vector.Reasons...)
		}
	}
	if r.Reasons != nil {
		r.Reasons = append(make([]string, 0, len(r.Reasons)), r.Reasons...)
	}
	return r
}

// SameResponseTargetEvidenceReceipt compares every immutable field, including bounded evidence.
func SameResponseTargetEvidenceReceipt(left, right ResponseTargetEvidenceReceipt) bool {
	left.Digest, right.Digest = "", ""
	left.AttemptedAt, right.AttemptedAt = left.AttemptedAt.UTC().Truncate(time.Microsecond), right.AttemptedAt.UTC().Truncate(time.Microsecond)
	left.WindowUntil, right.WindowUntil = left.WindowUntil.UTC().Truncate(time.Microsecond), right.WindowUntil.UTC().Truncate(time.Microsecond)
	left.RecordedAt, right.RecordedAt = left.RecordedAt.UTC().Truncate(time.Microsecond), right.RecordedAt.UTC().Truncate(time.Microsecond)
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}

func ResponseTargetEvidenceReceiptDigest(r ResponseTargetEvidenceReceipt) string {
	r.Digest = ""
	r.AttemptedAt = r.AttemptedAt.UTC().Truncate(time.Microsecond)
	r.WindowUntil = r.WindowUntil.UTC().Truncate(time.Microsecond)
	r.RecordedAt = r.RecordedAt.UTC().Truncate(time.Microsecond)
	encoded, _ := json.Marshal(r)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func coverageWindowLess(left, right sensorstate.CoverageWindow) bool {
	if !left.Since.Equal(right.Since) {
		return left.Since.Before(right.Since)
	}
	if !left.Until.Equal(right.Until) {
		return left.Until.Before(right.Until)
	}
	return left.Revision < right.Revision
}

func containsReason(reasons []string, want string) bool {
	return sort.SearchStrings(reasons, want) < len(reasons) && reasons[sort.SearchStrings(reasons, want)] == want
}

func sortedUnique(values []string) bool {
	for i, value := range values {
		if strings.TrimSpace(value) == "" || (i > 0 && values[i-1] >= value) {
			return false
		}
	}
	return true
}
