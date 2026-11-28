package benchcore

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

// ScorecardSchemaVersion names the scorecard document.
const ScorecardSchemaVersion = "synapse-benchmark-scorecard-v1"

// Dispositions of a required profile in a closure status.
const (
	ProfileExecuted    = "executed"
	ProfileNotExecuted = "not_executed"
	ProfileBlocked     = "blocked"
	// WorkPackageNotEntered marks a required work package that no profile and no control suite names
	// yet. It blocks closure: a manifest cannot close an EPIC by leaving work packages out of scope.
	WorkPackageNotEntered = "not_entered"
)

// Engine grades. Descriptive means the profile's support is below its minimum and the cells describe
// rather than grade. Ungraded means the measurement itself is invalid, which says nothing about the
// engine.
const (
	GradePass        = "pass"
	GradeFail        = "fail"
	GradeDescriptive = "descriptive"
	GradeUngraded    = "ungraded"
)

// Validity says whether a scorecard is a valid measurement. Validity and grade are separate: a complete,
// correctly scored run of an engine that missed every positive is valid and fails.
type Validity struct {
	Status  string   `json:"status"`
	Reasons []string `json:"reasons,omitempty"`
}

// ControlSuiteResult records one control suite's run bound to this scorecard.
type ControlSuiteResult struct {
	ID            string `json:"id"`
	Version       string `json:"version"`
	Passed        bool   `json:"passed"`
	ReceiptDigest string `json:"receipt_digest"`
}

// Scorecard is one engine's standalone result for one profile under one manifest revision.
type Scorecard struct {
	SchemaVersion         string               `json:"schema_version"`
	ID                    string               `json:"id"`
	Manifest              ManifestRef          `json:"manifest"`
	RunStartReceiptDigest string               `json:"run_start_receipt_digest"`
	ProfileID             string               `json:"profile_id"`
	Engine                EngineIdentity       `json:"engine"`
	Truth                 Identity             `json:"truth"`
	Scorer                Identity             `json:"scorer"`
	MatchingPolicyDigest  string               `json:"matching_policy_digest"`
	EnrollmentDigest      string               `json:"enrollment_digest"`
	ObservationDigest     string               `json:"observation_digest"`
	Validity              Validity             `json:"validity"`
	Disposition           string               `json:"disposition"`
	Cells                 []CellMetrics        `json:"cells"`
	UnmappedCount         int                  `json:"unmapped_count"`
	OutOfScopeFindings    int                  `json:"out_of_scope_findings"`
	EngineGrade           string               `json:"engine_grade"`
	ControlSuiteResults   []ControlSuiteResult `json:"control_suite_results"`
}

// ErrInvalidScorecard is wrapped by every scorecard failure.
var ErrInvalidScorecard = errors.New("invalid scorecard")

// Binding is what BindScorecard needs beside the manifest and the receipt. It carries no control results
// and no cells: BindScorecard runs the controls and computes the cells itself.
type Binding struct {
	Engine       EngineIdentity
	Truth        TruthSet
	Observations []Observation
}

// BindScorecard scores an engine's observations and binds the result to its inputs. The engine must be
// enrolled in the profile with the same adapter and scored component; the truth digest must be the one
// the profile froze; the receipt must belong to the same manifest revision and profile. The cells are
// computed here from the truth, the observations and the capabilities the manifest froze for the
// engine, so no caller can supply a score.
func BindScorecard(m ClosureManifest, receipt RunStartReceipt, b Binding) (Scorecard, error) {
	if err := m.Validate(); err != nil {
		return Scorecard{}, err
	}
	digest, err := DigestManifest(m)
	if err != nil {
		return Scorecard{}, err
	}
	if receipt.Manifest.Digest != digest || receipt.Manifest.Revision != m.Revision || receipt.Manifest.ID != m.ManifestID {
		return Scorecard{}, fmt.Errorf("%w: receipt is bound to manifest %s revision %d at %s, not this manifest", ErrInvalidScorecard, receipt.Manifest.ID, receipt.Manifest.Revision, receipt.Manifest.Digest)
	}
	profile, ok := m.Profile(receipt.ProfileID)
	if !ok {
		return Scorecard{}, fmt.Errorf("%w: receipt profile %q is not in the manifest", ErrInvalidScorecard, receipt.ProfileID)
	}
	enrolled := false
	var capabilities []string
	for _, e := range profile.RequiredEnrollment {
		if e.EngineID == b.Engine.EngineID && e.AdapterID == b.Engine.AdapterID && e.ScoredComponent.ID == b.Engine.ScoredComponent.ID {
			enrolled = true
			capabilities = e.DeclaredCapabilities
		}
	}
	if !enrolled {
		return Scorecard{}, fmt.Errorf("%w: engine %s with adapter %s and component %s is not enrolled in profile %s", ErrInvalidScorecard, b.Engine.EngineID, b.Engine.AdapterID, b.Engine.ScoredComponent.ID, profile.ID)
	}
	truthDigest, err := DigestTruth(b.Truth)
	if err != nil {
		return Scorecard{}, err
	}
	if truthDigest != profile.Truth.Digest {
		return Scorecard{}, fmt.Errorf("%w: truth digest %s is not the one profile %s froze (%s); a truth correction is a new manifest revision", ErrInvalidScorecard, truthDigest, profile.ID, profile.Truth.Digest)
	}
	if b.Truth.ClosedWorld != profile.ClosedWorld {
		return Scorecard{}, fmt.Errorf("%w: truth closed_world %t disagrees with profile %s", ErrInvalidScorecard, b.Truth.ClosedWorld, profile.ID)
	}
	if receipt.ProfileID != profile.ID || receipt.TruthDigest != profile.Truth.Digest || receipt.CorpusDigest != profile.Corpus.Digest || receipt.Scorer != profile.Scorer {
		return Scorecard{}, fmt.Errorf("%w: the receipt's profile, truth, corpus or scorer is not what profile %s froze", ErrInvalidScorecard, profile.ID)
	}
	subjectDigest := map[string]string{}
	for _, s := range b.Truth.Subjects {
		subjectDigest[s.ID] = s.Digest
	}
	for _, o := range b.Observations {
		if o.Normalization.ID != profile.MatchingPolicy.ID || o.Normalization.Digest != profile.MatchingPolicy.Digest {
			return Scorecard{}, fmt.Errorf("%w: observation on %s was normalized under %s@%s, not the profile's matching policy", ErrInvalidScorecard, o.Subject.ID, o.Normalization.ID, o.Normalization.Digest)
		}
		if want, ok := subjectDigest[o.Subject.ID]; ok && o.Subject.Digest != want {
			return Scorecard{}, fmt.Errorf("%w: observation on %s has subject digest %s; the truth labels %s", ErrInvalidScorecard, o.Subject.ID, o.Subject.Digest, want)
		}
	}
	enrollment, err := DigestEnrollment(profile)
	if err != nil {
		return Scorecard{}, err
	}
	if enrollment != receipt.EnrollmentDigest {
		return Scorecard{}, fmt.Errorf("%w: enrollment changed after the run started", ErrInvalidScorecard)
	}
	receiptDigest, err := DigestReceipt(receipt)
	if err != nil {
		return Scorecard{}, err
	}
	observationDigest, err := DigestObservations(b.Observations)
	if err != nil {
		return Scorecard{}, err
	}
	cells, err := Score(ScoringInput{Truth: b.Truth, Observations: b.Observations, Capabilities: capabilities})
	if err != nil {
		return Scorecard{}, fmt.Errorf("%w: %v", ErrInvalidScorecard, err)
	}
	controls, _, err := RunControlSuites(m)
	if err != nil {
		return Scorecard{}, err
	}
	unmapped := 0
	for _, o := range b.Observations {
		if o.Engine != b.Engine {
			return Scorecard{}, fmt.Errorf("%w: observation on %s names engine %s, not %s", ErrInvalidScorecard, o.Subject.ID, o.Engine.EngineID, b.Engine.EngineID)
		}
		unmapped += len(o.Unmapped)
	}
	card := Scorecard{
		SchemaVersion:         ScorecardSchemaVersion,
		Manifest:              receipt.Manifest,
		RunStartReceiptDigest: receiptDigest,
		ProfileID:             profile.ID,
		Engine:                b.Engine,
		Truth:                 Identity{ID: profile.Truth.ID, Version: b.Truth.Version, Digest: truthDigest},
		Scorer:                profile.Scorer,
		MatchingPolicyDigest:  profile.MatchingPolicy.Digest,
		EnrollmentDigest:      enrollment,
		ObservationDigest:     observationDigest,
		Disposition:           ProfileExecuted,
		Cells:                 cells,
		UnmappedCount:         unmapped,
		OutOfScopeFindings:    OutOfScopeFindings(b.Truth, b.Observations),
		ControlSuiteResults:   controls,
	}
	sort.Slice(card.Cells, func(i, j int) bool { return card.Cells[i].UnitKind < card.Cells[j].UnitKind })
	sort.Slice(card.ControlSuiteResults, func(i, j int) bool { return card.ControlSuiteResults[i].ID < card.ControlSuiteResults[j].ID })
	card.Validity = validity(m, controls)
	card.EngineGrade = grade(profile, b.Truth, card)
	id, err := digestScorecard(card)
	if err != nil {
		return Scorecard{}, err
	}
	card.ID = id
	return card, nil
}

// validity is about the measurement, never the engine: every control suite the manifest declares ran
// here and passed. A truncated observation is a fact about the run and is scored as incomplete.
func validity(m ClosureManifest, controls []ControlSuiteResult) Validity {
	var reasons []string
	passed := map[string]bool{}
	for _, r := range controls {
		if r.Passed {
			passed[r.ID+"@"+r.Version] = true
		}
	}
	for _, suite := range m.ControlSuites {
		if !passed[suite.ID+"@"+suite.Version] {
			reasons = append(reasons, "control suite "+suite.ID+"@"+suite.Version+" did not pass")
		}
	}
	sort.Strings(reasons)
	if len(reasons) > 0 {
		return Validity{Status: "invalid", Reasons: reasons}
	}
	return Validity{Status: "valid"}
}

// grade applies the profile's absolute thresholds to the end-to-end cell of each of its unit kinds. An
// invalid measurement grades nothing. A kind whose labelled positives or negatives fall below the
// profile's minimum truth support makes the whole profile descriptive: a pass on thin support is not a
// pass. Kinds are never pooled, and the engine passes only when every kind meets the thresholds. The
// unknown ceiling applies to closed-world profiles only; in an open world an unmatched finding is an
// adjudication backlog item, reported but not held against the engine.
func grade(profile Profile, truth TruthSet, card Scorecard) string {
	if card.Validity.Status != "valid" {
		return GradeUngraded
	}
	support := map[string][2]int{}
	for _, u := range truth.Units {
		s := support[u.UnitKind]
		switch u.Label {
		case LabelPositive:
			s[0]++
		case LabelNegative:
			s[1]++
		}
		support[u.UnitKind] = s
	}
	for _, kind := range profile.UnitKinds {
		if s := support[kind]; s[0] < profile.MinimumTruthSupport.Positives || s[1] < profile.MinimumTruthSupport.Negatives {
			return GradeDescriptive
		}
	}
	if profile.ClosedWorld && card.OutOfScopeFindings > 0 {
		return GradeFail // a closed world judges every report; one outside its kinds or subjects is false
	}
	byKind := map[string]CellMetrics{}
	for _, c := range card.Cells {
		byKind[c.UnitKind] = c
	}
	for _, kind := range profile.UnitKinds {
		c, ok := byKind[kind]
		if !ok {
			return GradeFail
		}
		recall, precision := c.EndToEnd.Recall(), c.EndToEnd.Precision()
		if recall == nil || *recall < profile.Thresholds.MinimumRecall {
			return GradeFail
		}
		if (precision == nil && profile.Thresholds.MinimumPrecision > 0) || (precision != nil && *precision < profile.Thresholds.MinimumPrecision) {
			return GradeFail
		}
		if profile.ClosedWorld && c.EndToEnd.Denominator > 0 && float64(c.EndToEnd.Unknown)/float64(c.EndToEnd.Denominator) > profile.Thresholds.MaximumUnknown {
			return GradeFail
		}
	}
	return GradePass
}

func digestScorecard(card Scorecard) (string, error) {
	card.ID = ""
	encoded, err := benchmark.CanonicalJSON(card)
	if err != nil {
		return "", err
	}
	return benchmark.SHA256Digest(encoded), nil
}

// ValidateScorecard rejects a scorecard whose bindings do not hold: a manifest digest other than m's, a
// receipt whose digest or profile differ, a changed enrollment, a truth digest the profile did not
// freeze, a profile the manifest lacks, or a self digest that no longer matches its content.
func ValidateScorecard(m ClosureManifest, receipt RunStartReceipt, card Scorecard) error {
	digest, err := DigestManifest(m)
	if err != nil {
		return err
	}
	var problems []string
	if card.SchemaVersion != ScorecardSchemaVersion {
		problems = append(problems, "schema_version "+card.SchemaVersion)
	}
	if card.Manifest.Digest != digest || card.Manifest.Revision != m.Revision {
		problems = append(problems, "manifest digest or revision does not match")
	}
	receiptDigest, err := DigestReceipt(receipt)
	if err != nil {
		return err
	}
	if card.RunStartReceiptDigest != receiptDigest || receipt.ProfileID != card.ProfileID {
		problems = append(problems, "run-start receipt does not match")
	}
	profile, ok := m.Profile(card.ProfileID)
	if !ok {
		problems = append(problems, "profile "+card.ProfileID+" is not in the manifest")
	} else {
		if enrollment, err := DigestEnrollment(profile); err != nil || enrollment != card.EnrollmentDigest || enrollment != receipt.EnrollmentDigest {
			problems = append(problems, "enrollment changed after the run")
		}
		if card.Truth.Digest != profile.Truth.Digest || receipt.TruthDigest != profile.Truth.Digest || receipt.CorpusDigest != profile.Corpus.Digest || receipt.Scorer != profile.Scorer {
			problems = append(problems, "truth, corpus or scorer digest is not the one the profile froze")
		}
	}
	if self, err := digestScorecard(card); err != nil || self != card.ID {
		problems = append(problems, "scorecard id does not match its content")
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidScorecard, strings.Join(problems, "; "))
	}
	return nil
}

// ClosureStatus reports each required profile as executed, blocked (an authorization it needs was not
// obtained) or not executed, and each required work package that no required profile and no control suite
// names as not_entered under the key "work_package:<id>". A profile is executed only when every engine it
// requires has a valid scorecard bound to this manifest's digest whose id matches its content. Scorecards
// are content-addressed, not signed: this checks that they are consistent with the manifest, and the run
// record that produced them is what attests that they were computed.
func ClosureStatus(m ClosureManifest, cards []Scorecard) map[string]string {
	digest, err := DigestManifest(m)
	if err != nil {
		digest = ""
	}
	type key struct{ profile, engine, adapter, component string }
	valid := map[key]bool{}
	for _, c := range cards {
		if digest == "" || c.Manifest.ID != m.ManifestID || c.Manifest.Revision != m.Revision || c.Manifest.Digest != digest || c.Validity.Status != "valid" {
			continue
		}
		if self, err := digestScorecard(c); err != nil || self != c.ID {
			continue
		}
		valid[key{c.ProfileID, c.Engine.EngineID, c.Engine.AdapterID, c.Engine.ScoredComponent.ID}] = true
	}
	out := map[string]string{}
	entered := map[string]bool{}
	for _, p := range m.Profiles {
		if p.Disposition != DispositionRequired {
			continue
		}
		for _, wp := range p.WorkPackages {
			entered[wp] = true
		}
	}
	for _, c := range m.ControlSuites {
		entered[c.WorkPackage] = true
	}
	for id, wp := range m.WorkPackages {
		if wp.Required && !entered[id] {
			out["work_package:"+id] = WorkPackageNotEntered
		}
	}
	for _, p := range m.Profiles {
		if p.Disposition != DispositionRequired {
			continue
		}
		executed := len(p.RequiredEnrollment) > 0
		for _, e := range p.RequiredEnrollment {
			if !valid[key{p.ID, e.EngineID, e.AdapterID, e.ScoredComponent.ID}] {
				executed = false
			}
		}
		switch {
		case executed:
			out[p.ID] = ProfileExecuted
		case p.ExecutionAuthorization.Status == AuthorizationNotObtained:
			out[p.ID] = ProfileBlocked
		default:
			out[p.ID] = ProfileNotExecuted
		}
	}
	return out
}

// Closed reports whether every required profile executed.
func Closed(status map[string]string) bool {
	for _, s := range status {
		if s != ProfileExecuted {
			return false
		}
	}
	return len(status) > 0
}
