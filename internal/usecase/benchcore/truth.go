package benchcore

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

// TruthSchemaVersion names the oracle document.
const TruthSchemaVersion = "synapse-benchmark-truth-v1"

// Truth labels. Unknown is a unit the oracle has not adjudicated; it is never a positive or a negative.
const (
	LabelPositive = "positive"
	LabelNegative = "negative"
	LabelUnknown  = "unknown"
)

// TruthUnit is one adjudicated unit with its provenance.
type TruthUnit struct {
	ID        string            `json:"id"`
	SubjectID string            `json:"subject_id"`
	UnitKind  string            `json:"unit_kind"`
	Identity  map[string]string `json:"identity"`
	// AlternateIdentities are identities the oracle accepts as the same unit, such as an advisory's
	// aliases. They are part of the truth version, so a new alias is a new truth version.
	AlternateIdentities []map[string]string `json:"alternate_identities,omitempty"`
	Label               string              `json:"label"`
	Provenance          string              `json:"provenance"`
	Authorship          string              `json:"authorship"`
	Citations           []string            `json:"citations,omitempty"`
}

// TruthSet is a profile's oracle at one version. ClosedWorld states whether a finding that matches no
// unit is a false positive (closed) or an unknown awaiting adjudication (open).
type TruthSet struct {
	SchemaVersion string `json:"schema_version"`
	ProfileID     string `json:"profile_id"`
	Version       string `json:"version"`
	ClosedWorld   bool   `json:"closed_world"`
	// Subjects are the corpus the truth labels, each with the digest an observation of it must carry.
	Subjects []Subject   `json:"subjects"`
	Units    []TruthUnit `json:"units"`
}

// ErrInvalidTruth is wrapped by every truth failure.
var ErrInvalidTruth = errors.New("invalid truth set")

// DecodeTruth strictly decodes one truth document.
func DecodeTruth(r io.Reader) (TruthSet, error) {
	var out TruthSet
	if err := benchmark.StrictDecode(r, &out); err != nil {
		return TruthSet{}, fmt.Errorf("%w: %v", ErrInvalidTruth, err)
	}
	if err := out.Validate(); err != nil {
		return TruthSet{}, err
	}
	return out, nil
}

// Validate checks labels, provenance and uniqueness.
func (t TruthSet) Validate() error {
	if t.SchemaVersion != TruthSchemaVersion {
		return fmt.Errorf("%w: schema_version %q", ErrInvalidTruth, t.SchemaVersion)
	}
	if t.ProfileID == "" || t.Version == "" {
		return fmt.Errorf("%w: profile_id and version are required", ErrInvalidTruth)
	}
	subjects := map[string]bool{}
	for _, s := range t.Subjects {
		if s.ID == "" || s.Digest == "" {
			return fmt.Errorf("%w: a subject needs an id and a digest", ErrInvalidTruth)
		}
		if subjects[s.ID] {
			return fmt.Errorf("%w: subject %q is listed twice", ErrInvalidTruth, s.ID)
		}
		subjects[s.ID] = true
	}
	ids := map[string]bool{}
	keys := map[string]bool{}
	for _, u := range t.Units {
		if u.ID == "" || u.SubjectID == "" || u.UnitKind == "" || len(u.Identity) == 0 {
			return fmt.Errorf("%w: unit %q needs id, subject_id, unit_kind and identity", ErrInvalidTruth, u.ID)
		}
		if !subjects[u.SubjectID] {
			return fmt.Errorf("%w: unit %q names subject %q, which the truth set does not list", ErrInvalidTruth, u.ID, u.SubjectID)
		}
		if !canonicalKind(u.UnitKind) {
			return fmt.Errorf("%w: unit %q unit_kind %q is not lower-case and trimmed", ErrInvalidTruth, u.ID, u.UnitKind)
		}
		if t.ClosedWorld && u.Label == LabelUnknown {
			return fmt.Errorf("%w: unit %q is unknown in a closed-world truth set; a closed world has adjudicated every unit", ErrInvalidTruth, u.ID)
		}
		if ids[u.ID] {
			return fmt.Errorf("%w: unit %q is listed twice", ErrInvalidTruth, u.ID)
		}
		ids[u.ID] = true
		for _, identity := range append([]map[string]string{u.Identity}, u.AlternateIdentities...) {
			if len(identity) == 0 {
				return fmt.Errorf("%w: unit %q has an empty alternate identity", ErrInvalidTruth, u.ID)
			}
			if err := checkIdentity(identity); err != nil {
				return fmt.Errorf("%w: unit %q: %v", ErrInvalidTruth, u.ID, err)
			}
			key := strconv.Itoa(len(u.SubjectID)) + ":" + u.SubjectID + unitKey(u.UnitKind, identity)
			if keys[key] {
				return fmt.Errorf("%w: unit %q repeats an identity already claimed on the same subject", ErrInvalidTruth, u.ID)
			}
			keys[key] = true
		}
		switch u.Label {
		case LabelPositive, LabelNegative, LabelUnknown:
		default:
			return fmt.Errorf("%w: unit %q has label %q", ErrInvalidTruth, u.ID, u.Label)
		}
		if u.Provenance == "" || u.Authorship == "" {
			return fmt.Errorf("%w: unit %q needs provenance and authorship", ErrInvalidTruth, u.ID)
		}
	}
	return nil
}

// Canonical sorts units and their citations.
func (t TruthSet) Canonical() TruthSet {
	out := t
	out.Units = make([]TruthUnit, 0, len(t.Units))
	for _, u := range t.Units {
		c := u
		c.Identity = normalizeIdentity(u.Identity)
		c.Citations = sortedStrings(u.Citations)
		c.AlternateIdentities = nil
		for _, identity := range u.AlternateIdentities {
			c.AlternateIdentities = append(c.AlternateIdentities, normalizeIdentity(identity))
		}
		sort.Slice(c.AlternateIdentities, func(i, j int) bool {
			return unitKey(u.UnitKind, c.AlternateIdentities[i]) < unitKey(u.UnitKind, c.AlternateIdentities[j])
		})
		out.Units = append(out.Units, c)
	}
	sort.Slice(out.Units, func(i, j int) bool { return out.Units[i].ID < out.Units[j].ID })
	out.Subjects = append([]Subject(nil), t.Subjects...)
	sort.Slice(out.Subjects, func(i, j int) bool { return out.Subjects[i].ID < out.Subjects[j].ID })
	return out
}

// DigestTruth is the truth set's identity.
func DigestTruth(t TruthSet) (string, error) {
	if err := t.Validate(); err != nil {
		return "", err
	}
	encoded, err := benchmark.CanonicalJSON(t.Canonical())
	if err != nil {
		return "", err
	}
	return benchmark.SHA256Digest(encoded), nil
}
