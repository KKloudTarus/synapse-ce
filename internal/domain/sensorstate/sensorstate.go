// Package sensorstate defines immutable endpoint sensor-state observations.
package sensorstate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/riskassessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// RecordKind identifies the durable P0 record represented by an observation.
type RecordKind string

const (
	RecordCoverage    RecordKind = "coverage"
	RecordSensorState RecordKind = "sensor_state"
)

func (k RecordKind) Valid() bool {
	return k == RecordCoverage || k == RecordSensorState
}

// Observation is an append-only, signed endpoint sensor-state record. ReportID is
// deterministic from the local WAL record and makes retries idempotent.
type Observation struct {
	ReportID            shared.ID
	AgentID             shared.ID
	HostID              shared.ID
	AssetID             shared.ID
	Kind                RecordKind
	ObservedAt          time.Time
	PayloadDigest       string
	SignedContentDigest string
	SchemaVersion       int
	States              []detection.ClassCoverage
	RecordedAt          time.Time
}

func (o Observation) Validate() error {
	if o.ReportID.IsZero() || o.AgentID.IsZero() || o.HostID.IsZero() || o.AssetID.IsZero() {
		return fmt.Errorf("%w: sensor-state observation requires report, agent, host and asset ids", shared.ErrValidation)
	}
	if !o.Kind.Valid() || o.ObservedAt.IsZero() || o.RecordedAt.IsZero() || o.SchemaVersion <= 0 {
		return fmt.Errorf("%w: sensor-state observation has invalid required fields", shared.ErrValidation)
	}
	if len(o.PayloadDigest) != sha256.Size*2 {
		return fmt.Errorf("%w: sensor-state observation has invalid payload digest", shared.ErrValidation)
	}
	if _, err := hex.DecodeString(o.PayloadDigest); err != nil {
		return fmt.Errorf("%w: sensor-state observation has invalid payload digest: %v", shared.ErrValidation, err)
	}
	if len(o.SignedContentDigest) != sha256.Size*2 {
		return fmt.Errorf("%w: sensor-state observation has invalid signed content digest", shared.ErrValidation)
	}
	if _, err := hex.DecodeString(o.SignedContentDigest); err != nil {
		return fmt.Errorf("%w: sensor-state observation has invalid signed content digest: %v", shared.ErrValidation, err)
	}
	if len(o.States) == 0 {
		return fmt.Errorf("%w: sensor-state observation has no class states", shared.ErrValidation)
	}
	seen := make(map[detection.Class]struct{}, len(o.States))
	for _, state := range o.States {
		if err := state.Validate(); err != nil {
			return err
		}
		if state.HostID != o.HostID || (state.AgentID != "" && state.AgentID != o.AgentID) {
			return fmt.Errorf("%w: sensor-state class identity does not match observation", shared.ErrValidation)
		}
		if _, ok := seen[state.Class]; ok {
			return fmt.Errorf("%w: sensor-state observation repeats class %q", shared.ErrValidation, state.Class)
		}
		seen[state.Class] = struct{}{}
	}
	return nil
}

// CoverageWindow is an immutable, revisioned explanation of how much telemetry
// can be trusted for one asset over a fixed observed-time interval.
type CoverageWindow struct {
	AssetID        shared.ID
	AgentID        shared.ID
	HostID         shared.ID
	Since          time.Time
	Until          time.Time
	InputDigest    string
	Revision       string
	CreatedAt      time.Time
	States         []detection.ClassCoverage
	SampledCount   int
	TruncatedCount int
	DroppedCount   int
	GapCount       int
	BatchCount     int
	Vector         riskassessment.CoverageVector
}

func (w CoverageWindow) Validate() error {
	if w.AssetID.IsZero() || w.AgentID.IsZero() || w.HostID.IsZero() || w.Since.IsZero() || w.Until.IsZero() || !w.Since.Before(w.Until) || w.CreatedAt.IsZero() {
		return fmt.Errorf("%w: coverage window has invalid identity or non-empty half-open time bounds", shared.ErrValidation)
	}
	if !canonicalRevisionTime(w.Since) || !canonicalRevisionTime(w.Until) {
		return fmt.Errorf("%w: coverage window bounds must use UTC microsecond precision", shared.ErrValidation)
	}
	if err := validateDigest("input digest", w.InputDigest); err != nil {
		return err
	}
	if err := validateDigest("revision", w.Revision); err != nil {
		return err
	}
	if w.SampledCount < 0 || w.TruncatedCount < 0 || w.DroppedCount < 0 || w.GapCount < 0 || w.BatchCount < 0 {
		return fmt.Errorf("%w: coverage window counts cannot be negative", shared.ErrValidation)
	}
	seen := make(map[detection.Class]struct{}, len(w.States))
	for _, state := range w.States {
		if err := state.Validate(); err != nil {
			return err
		}
		if !canonicalRevisionTime(state.Since) {
			return fmt.Errorf("%w: coverage window class state must use UTC microsecond precision", shared.ErrValidation)
		}
		if state.HostID != w.HostID || (state.AgentID != "" && state.AgentID != w.AgentID) {
			return fmt.Errorf("%w: coverage window class identity does not match host or agent", shared.ErrValidation)
		}
		if _, ok := seen[state.Class]; ok {
			return fmt.Errorf("%w: coverage window repeats class %q", shared.ErrValidation, state.Class)
		}
		seen[state.Class] = struct{}{}
	}
	if err := w.Vector.Validate(); err != nil {
		return err
	}
	if !sort.StringsAreSorted(w.Vector.Reasons) {
		return fmt.Errorf("%w: coverage window reasons must be sorted", shared.ErrValidation)
	}
	expected := BuildCoverageVector(w)
	if w.Vector.Process != expected.Process || w.Vector.Network != expected.Network || w.Vector.File != expected.File || w.Vector.Privilege != expected.Privilege || !sameReasons(w.Vector.Reasons, expected.Reasons) {
		return fmt.Errorf("%w: coverage window vector does not match its immutable facts", shared.ErrValidation)
	}
	if w.Revision != RevisionFor(w) {
		return fmt.Errorf("%w: coverage window revision does not match its immutable facts", shared.ErrValidation)
	}
	return nil
}

// NormalizeObservation canonicalizes persisted timestamps to the precision PostgreSQL retains.
// RecordedAt is server-owned and excluded from retry identity.
func NormalizeObservation(o Observation) Observation {
	o.ObservedAt = o.ObservedAt.UTC().Truncate(time.Microsecond)
	o.RecordedAt = o.RecordedAt.UTC().Truncate(time.Microsecond)
	o.States = append([]detection.ClassCoverage(nil), o.States...)
	for i := range o.States {
		o.States[i].Since = o.States[i].Since.UTC().Truncate(time.Microsecond)
	}
	return o
}

func canonicalRevisionTime(at time.Time) bool {
	return at.Equal(at.UTC().Truncate(time.Microsecond))
}

// SameSignedObservation compares immutable signed sensor-state content. It intentionally
// excludes server-generated RecordedAt, allowing delayed retries to converge on the
// first accepted record.
func SameSignedObservation(a, b Observation) bool {
	a, b = NormalizeObservation(a), NormalizeObservation(b)
	if a.ReportID != b.ReportID || a.SignedContentDigest != b.SignedContentDigest {
		return false
	}
	return true
}

func validateDigest(name, value string) error {
	if len(value) != sha256.Size*2 {
		return fmt.Errorf("%w: coverage window has invalid %s", shared.ErrValidation, name)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("%w: coverage window has invalid %s: %v", shared.ErrValidation, name, err)
	}
	return nil
}

func sameReasons(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// BuildCoverageVector deterministically converts the immutable window facts to
// the vector consumed by the existing risk scorer. Loss or delivery-gap facts
// cap affected coverage below complete without changing risk itself.
func BuildCoverageVector(w CoverageWindow) riskassessment.CoverageVector {
	byClass := make(map[detection.Class]detection.ClassCoverage, len(w.States))
	for _, state := range w.States {
		if current, ok := byClass[state.Class]; !ok || state.Since.After(current.Since) || (state.Since.Equal(current.Since) && state.State > current.State) {
			byClass[state.Class] = state
		}
	}
	score := func(class detection.Class) riskassessment.Score {
		state, ok := byClass[class]
		if !ok {
			return 0
		}
		var value riskassessment.Score
		switch state.State {
		case detection.StateActive:
			value = 100
		case detection.StateDegraded:
			value = 60
		case detection.StateDisabled:
			value = 25
		case detection.StateFailed:
			value = 0
		}
		if (w.SampledCount > 0 || w.TruncatedCount > 0 || w.DroppedCount > 0 || w.GapCount > 0) && value > 80 {
			value = 80
		}
		return value
	}
	v := riskassessment.CoverageVector{
		Process: score(detection.ClassProcess), Network: score(detection.ClassNetwork),
		File: score(detection.ClassFile), Privilege: score(detection.ClassPrivilege),
	}
	for _, class := range []detection.Class{detection.ClassProcess, detection.ClassNetwork, detection.ClassFile, detection.ClassPrivilege} {
		state, ok := byClass[class]
		if !ok {
			v.Reasons = append(v.Reasons, string(class)+":missing_state")
			continue
		}
		if state.State != detection.StateActive {
			reason := string(class) + ":" + string(state.State)
			if state.Reason != "" {
				reason += ":" + state.Reason
			}
			v.Reasons = append(v.Reasons, reason)
		}
	}
	for _, loss := range []struct {
		kind  string
		count int
	}{
		{"telemetry_sampled", w.SampledCount},
		{"telemetry_truncated", w.TruncatedCount},
		{"telemetry_dropped", w.DroppedCount},
		{"telemetry_gap", w.GapCount},
	} {
		if loss.count > 0 {
			v.Reasons = append(v.Reasons, fmt.Sprintf("%s:%d", loss.kind, loss.count))
		}
	}
	sort.Strings(v.Reasons)
	return v
}

// RevisionFor returns a stable revision for a fully assembled window. It does not
// use wall clock time, so the same persisted facts always yield the same revision.
func RevisionFor(w CoverageWindow) string {
	h := sha256.New()
	write := func(value string) { _, _ = h.Write([]byte(value)); _, _ = h.Write([]byte{0}) }
	write(w.AssetID.String())
	write(w.AgentID.String())
	write(w.HostID.String())
	write(w.Since.UTC().Format(time.RFC3339Nano))
	write(w.Until.UTC().Format(time.RFC3339Nano))
	write(w.InputDigest)
	write(fmt.Sprintf("%d/%d/%d/%d/%d", w.SampledCount, w.TruncatedCount, w.DroppedCount, w.GapCount, w.BatchCount))
	states := append([]detection.ClassCoverage(nil), w.States...)
	sort.Slice(states, func(i, j int) bool { return states[i].Class < states[j].Class })
	for _, state := range states {
		write(strings.Join([]string{
			string(state.Class),
			state.HostID.String(),
			state.AgentID.String(),
			string(state.State),
			state.Reason,
			state.Since.UTC().Format(time.RFC3339Nano),
		}, "|"))
	}
	vector := BuildCoverageVector(w)
	write(fmt.Sprintf("%d/%d/%d/%d", vector.Process, vector.Network, vector.File, vector.Privilege))
	for _, reason := range vector.Reasons {
		write(reason)
	}
	return hex.EncodeToString(h.Sum(nil))
}
