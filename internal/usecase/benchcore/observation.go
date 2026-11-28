package benchcore

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

// ObservationSchemaVersion names the document an adapter hands the core.
const ObservationSchemaVersion = "synapse-benchmark-observation-v1"

// Observation states. A state other than complete is a fact about the run, never a score.
const (
	StateComplete    = "complete"
	StateIncomplete  = "incomplete"
	StateUnsupported = "unsupported"
	StateFailed      = "failed"
	StateUnknown     = "unknown"
)

// EngineIdentity is everything that identifies what produced an observation. The scorer never reads it;
// BindScorecard copies it onto the scorecard after scoring.
type EngineIdentity struct {
	EngineID           string          `json:"engine_id"`
	AdapterID          string          `json:"adapter_id"`
	AdapterVersion     string          `json:"adapter_version"`
	ScoredComponent    ScoredComponent `json:"scored_component"`
	BinaryDigest       string          `json:"binary_digest,omitempty"`
	DataSnapshotDigest string          `json:"data_snapshot_digest,omitempty"`
	ConfigDigest       string          `json:"config_digest,omitempty"`
	EnvironmentDigest  string          `json:"environment_digest,omitempty"`
}

// Subject is the input an observation was made on.
type Subject struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

// Finding is one normalized detection. Identity is the unit's own key fields (purl and advisory, or
// path, rule and line, or resource and check); it carries no label and no verdict.
type Finding struct {
	UnitKind string            `json:"unit_kind"`
	Identity map[string]string `json:"identity"`
	RawRef   string            `json:"raw_ref,omitempty"`
}

// Unmapped is a raw detection the adapter could not normalize, with the reason.
type Unmapped struct {
	RawRef string `json:"raw_ref"`
	Reason string `json:"reason"`
}

// Observation is an adapter's output for one subject under one profile. It has no field for a label, a
// count or a verdict, and StrictDecode refuses unknown fields, so an adapter cannot supply them.
type Observation struct {
	SchemaVersion        string         `json:"schema_version"`
	ProfileID            string         `json:"profile_id"`
	Engine               EngineIdentity `json:"engine"`
	Subject              Subject        `json:"subject"`
	State                string         `json:"state"`
	Truncated            bool           `json:"truncated"`
	ExecutionError       string         `json:"execution_error,omitempty"`
	DeclaredCapabilities []string       `json:"declared_capabilities"`
	Normalization        Identity       `json:"normalization"`
	RawEvidenceDigest    string         `json:"raw_evidence_digest"`
	Findings             []Finding      `json:"findings"`
	Unmapped             []Unmapped     `json:"unmapped,omitempty"`
}

// ErrInvalidObservation is wrapped by every observation failure.
var ErrInvalidObservation = errors.New("invalid observation")

// DecodeObservation strictly decodes one observation document.
func DecodeObservation(r io.Reader) (Observation, error) {
	var out Observation
	if err := benchmark.StrictDecode(r, &out); err != nil {
		return Observation{}, fmt.Errorf("%w: %v", ErrInvalidObservation, err)
	}
	if err := out.Validate(); err != nil {
		return Observation{}, err
	}
	return out, nil
}

// Validate checks the fields the scorer relies on.
func (o Observation) Validate() error {
	if o.SchemaVersion != ObservationSchemaVersion {
		return fmt.Errorf("%w: schema_version %q", ErrInvalidObservation, o.SchemaVersion)
	}
	if o.ProfileID == "" || o.Subject.ID == "" || o.Engine.EngineID == "" || o.Engine.AdapterID == "" {
		return fmt.Errorf("%w: profile_id, subject.id, engine.engine_id and engine.adapter_id are required", ErrInvalidObservation)
	}
	switch o.State {
	case StateComplete, StateIncomplete, StateUnsupported, StateFailed, StateUnknown:
	default:
		return fmt.Errorf("%w: state %q", ErrInvalidObservation, o.State)
	}
	if o.State == StateFailed && strings.TrimSpace(o.ExecutionError) == "" {
		return fmt.Errorf("%w: a failed observation names its execution error", ErrInvalidObservation)
	}
	if o.Normalization.ID == "" || o.Normalization.Digest == "" {
		return fmt.Errorf("%w: normalization policy id and digest are required", ErrInvalidObservation)
	}
	for i, f := range o.Findings {
		if f.UnitKind == "" || len(f.Identity) == 0 {
			return fmt.Errorf("%w: finding %d needs unit_kind and identity", ErrInvalidObservation, i)
		}
		if !canonicalKind(f.UnitKind) {
			return fmt.Errorf("%w: finding %d unit_kind %q is not lower-case and trimmed", ErrInvalidObservation, i, f.UnitKind)
		}
		if err := checkIdentity(f.Identity); err != nil {
			return fmt.Errorf("%w: finding %d: %v", ErrInvalidObservation, i, err)
		}
	}
	for _, c := range o.DeclaredCapabilities {
		if !canonicalKind(c) {
			return fmt.Errorf("%w: declared capability %q is not lower-case and trimmed", ErrInvalidObservation, c)
		}
	}
	return nil
}

// Canonical sorts the findings, unmapped entries and capabilities so a digest is order-insensitive.
func (o Observation) Canonical() Observation {
	out := o
	out.DeclaredCapabilities = sortedStrings(o.DeclaredCapabilities)
	out.Findings = canonicalFindings(o.Findings)
	out.Unmapped = append([]Unmapped(nil), o.Unmapped...)
	sort.Slice(out.Unmapped, func(i, j int) bool {
		if out.Unmapped[i].RawRef != out.Unmapped[j].RawRef {
			return out.Unmapped[i].RawRef < out.Unmapped[j].RawRef
		}
		return out.Unmapped[i].Reason < out.Unmapped[j].Reason
	})
	return out
}

func canonicalFindings(in []Finding) []Finding {
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		out = append(out, Finding{UnitKind: f.UnitKind, Identity: normalizeIdentity(f.Identity), RawRef: f.RawRef})
	}
	sort.Slice(out, func(i, j int) bool {
		ki, kj := unitKey(out[i].UnitKind, out[i].Identity), unitKey(out[j].UnitKind, out[j].Identity)
		if ki != kj {
			return ki < kj
		}
		return out[i].RawRef < out[j].RawRef
	})
	return out
}

// DigestObservations is the identity of a set of observations, regardless of their order or the order of
// their findings. Engine identity is part of it: the same findings from another adapter are another
// observation.
func DigestObservations(observations []Observation) (string, error) {
	// Each observation is encoded on its own and the encodings are sorted, so the digest is a function of
	// the set of observations and never of their input order, ties included.
	encoded := make([][]byte, 0, len(observations))
	for _, o := range observations {
		e, err := benchmark.CanonicalJSON(o.Canonical())
		if err != nil {
			return "", err
		}
		encoded = append(encoded, e)
	}
	sort.Slice(encoded, func(i, j int) bool { return string(encoded[i]) < string(encoded[j]) })
	all, err := benchmark.CanonicalJSON(encoded)
	if err != nil {
		return "", err
	}
	return benchmark.SHA256Digest(all), nil
}

// canonicalKind reports whether a unit kind is already in its normalized form. Kinds are compared as
// written everywhere (manifest, truth, observation, scorer), so a kind that normalization would change is
// refused rather than silently folded.
func canonicalKind(kind string) bool {
	return kind != "" && kind == strings.ToLower(strings.TrimSpace(kind))
}

// checkIdentity refuses an identity the core could not compare exactly: a key that is not lower-case and
// trimmed, or an empty value. Values are compared byte for byte. Folding case or whitespace in a value is
// the adapter's published normalization, because only the adapter knows which parts of an identifier are
// case-sensitive (a Debian package name is; a CVE id is not).
func checkIdentity(identity map[string]string) error {
	if len(identity) == 0 {
		return errors.New("identity is empty")
	}
	for k, v := range identity {
		if !canonicalKind(k) {
			return fmt.Errorf("identity key %q is not lower-case and trimmed", k)
		}
		if v == "" {
			return fmt.Errorf("identity key %q has an empty value", k)
		}
	}
	return nil
}

// normalizeIdentity returns a copy of a checked identity. The core applies no further normalization.
func normalizeIdentity(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// unitKey is the join key between a finding and a truth unit. Every part is length-prefixed, so no
// identity value can forge another key by embedding a separator.
func unitKey(unitKind string, identity map[string]string) string {
	keys := make([]string, 0, len(identity))
	for k := range identity {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	part := func(v string) {
		b.WriteString(strconv.Itoa(len(v)))
		b.WriteByte(':')
		b.WriteString(v)
	}
	part(unitKind)
	for _, k := range keys {
		part(k)
		part(identity[k])
	}
	return b.String()
}
