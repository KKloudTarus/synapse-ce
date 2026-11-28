package benchcore

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
)

// Counts are one cell's raw counts. Unit counts and finding counts are kept apart:
//
//   - Every truth unit in the cell lands in exactly one of TruePositives, FalseNegatives, FalsePositives
//     (a negative the engine reported), TrueNegatives, Unknown, Unsupported, Incomplete, Abstained or
//     ExecutionFailed, and Denominator is their sum. Score checks that identity on every cell.
//   - UnmatchedFindings counts distinct findings that match no unit in a closed world; they are false
//     reports. UnadjudicatedFindings counts the same in an open world, where they wait for adjudication.
//     Both count distinct normalized identities, so a finding reported under two identities the truth does
//     not relate counts twice.
type Counts struct {
	Denominator           int `json:"denominator"`
	Positives             int `json:"positives"`
	TruePositives         int `json:"true_positives"`
	FalseNegatives        int `json:"false_negatives"`
	FalsePositives        int `json:"false_positives"`
	TrueNegatives         int `json:"true_negatives"`
	Unknown               int `json:"unknown"`
	Unsupported           int `json:"unsupported"`
	Incomplete            int `json:"incomplete"`
	Abstained             int `json:"abstained"`
	ExecutionFailed       int `json:"execution_failed"`
	UnmatchedFindings     int `json:"unmatched_findings"`
	UnadjudicatedFindings int `json:"unadjudicated_findings"`
}

// Precision is true positives over everything the engine reported that the truth can judge: true
// positives, reported negatives and, in a closed world, unmatched findings. It is nil when the engine
// reported nothing judgeable.
func (c Counts) Precision() *float64 {
	reported := c.TruePositives + c.FalsePositives + c.UnmatchedFindings
	if reported == 0 {
		return nil
	}
	v := float64(c.TruePositives) / float64(reported)
	return &v
}

// Recall is TP over every labelled positive in the cell's denominator. A positive the engine did not
// assess because it abstained, failed, ran incompletely or does not support the kind is a miss here; the
// assessed-only cell leaves out the unsupported kinds and nothing else.
func (c Counts) Recall() *float64 {
	if c.Positives == 0 {
		return nil
	}
	v := float64(c.TruePositives) / float64(c.Positives)
	return &v
}

func (c Counts) unitSum() int {
	return c.TruePositives + c.FalseNegatives + c.FalsePositives + c.TrueNegatives + c.Unknown + c.Unsupported + c.Incomplete + c.Abstained + c.ExecutionFailed
}

// CellMetrics scores one unit kind twice: end to end, where an unsupported known positive is a miss, and
// assessed only, where it is excluded. The two are reported side by side and never pooled.
type CellMetrics struct {
	UnitKind     string `json:"unit_kind"`
	EndToEnd     Counts `json:"end_to_end"`
	AssessedOnly Counts `json:"assessed_only"`
}

// ScoringInput carries everything the scorer may see. It has no engine identity on purpose: renaming or
// reordering engines cannot change a cell.
type ScoringInput struct {
	Truth        TruthSet
	Observations []Observation
	// Capabilities are the unit kinds the enrolled engine declared for this profile, frozen in the
	// manifest. A truth unit of another kind is unsupported for it.
	Capabilities []string
}

// ErrScoring is wrapped by every scoring failure.
var ErrScoring = errors.New("scoring")

// Score produces one CellMetrics per unit kind in the truth set. Observations are matched to units by
// subject, unit kind and identity, or any alternate identity the unit declares, compared exactly. A
// subject may have one observation. Only a complete, untruncated observation's findings are evidence; a
// truncated one counts as incomplete. A finding on a subject or a unit kind the truth does not contain is
// out of scope and lands in no cell; OutOfScopeFindings counts it.
func Score(in ScoringInput) ([]CellMetrics, error) {
	if err := in.Truth.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrScoring, err)
	}
	supported := map[string]bool{}
	for _, c := range in.Capabilities {
		supported[c] = true
	}
	truthKinds, truthSubjects := truthScope(in.Truth)
	subjectDigest := map[string]string{}
	for _, s := range in.Truth.Subjects {
		subjectDigest[s.ID] = s.Digest
	}
	type subjectView struct {
		state    string
		findings map[string]string // unit key -> unit kind; a repeated finding is one finding
	}
	subjects := map[string]*subjectView{}
	for _, o := range in.Observations {
		if err := o.Validate(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrScoring, err)
		}
		if o.ProfileID != in.Truth.ProfileID {
			return nil, fmt.Errorf("%w: observation on %s is for profile %q, truth is for %q", ErrScoring, o.Subject.ID, o.ProfileID, in.Truth.ProfileID)
		}
		if want, ok := subjectDigest[o.Subject.ID]; ok && o.Subject.Digest != want {
			return nil, fmt.Errorf("%w: observation on %s has subject digest %s; the truth labels %s", ErrScoring, o.Subject.ID, o.Subject.Digest, want)
		}
		if _, dup := subjects[o.Subject.ID]; dup {
			return nil, fmt.Errorf("%w: subject %s has more than one observation", ErrScoring, o.Subject.ID)
		}
		state := o.State
		if o.Truncated && state == StateComplete {
			state = StateIncomplete
		}
		view := &subjectView{state: state, findings: map[string]string{}}
		subjects[o.Subject.ID] = view
		if state != StateComplete || !truthSubjects[o.Subject.ID] {
			continue // only a complete observation of an in-scope subject is evidence
		}
		for _, f := range o.Findings {
			if !truthKinds[f.UnitKind] {
				continue
			}
			view.findings[unitKey(f.UnitKind, f.Identity)] = f.UnitKind
		}
	}
	cells := map[string]*CellMetrics{}
	cell := func(kind string) *CellMetrics {
		c, ok := cells[kind]
		if !ok {
			c = &CellMetrics{UnitKind: kind}
			cells[kind] = c
		}
		return c
	}
	matched := map[string]map[string]bool{} // subject -> unit key -> matched a unit
	for _, u := range in.Truth.Units {
		c := cell(u.UnitKind)
		view := subjects[u.SubjectID]
		if matched[u.SubjectID] == nil {
			matched[u.SubjectID] = map[string]bool{}
		}
		found := false
		if view != nil {
			for _, identity := range append([]map[string]string{u.Identity}, u.AlternateIdentities...) {
				key := unitKey(u.UnitKind, identity)
				if _, ok := view.findings[key]; ok {
					found = true
					matched[u.SubjectID][key] = true
				}
			}
		}
		supportedKind := supported[u.UnitKind]
		positive := 0
		if u.Label == LabelPositive {
			positive = 1
		}
		apply := func(counts *Counts) {
			counts.Denominator++
			counts.Positives += positive
			switch {
			case u.Label == LabelUnknown:
				counts.Unknown++
			case !supportedKind:
				counts.Unsupported++
			case view == nil:
				counts.Abstained++
			case view.state == StateFailed:
				counts.ExecutionFailed++
			case view.state == StateIncomplete:
				counts.Incomplete++
			case view.state == StateUnsupported:
				counts.Unsupported++
			case view.state == StateUnknown:
				counts.Unknown++
			case u.Label == LabelPositive && found:
				counts.TruePositives++
			case u.Label == LabelPositive:
				counts.FalseNegatives++
			case found:
				counts.FalsePositives++
			default:
				counts.TrueNegatives++
			}
		}
		apply(&c.EndToEnd)
		if supportedKind {
			apply(&c.AssessedOnly)
		}
	}
	for subjectID, view := range subjects {
		for key, kind := range view.findings {
			if matched[subjectID][key] {
				continue
			}
			c := cell(kind)
			add := func(counts *Counts) {
				if in.Truth.ClosedWorld {
					counts.UnmatchedFindings++
				} else {
					counts.UnadjudicatedFindings++
				}
			}
			add(&c.EndToEnd)
			if supported[kind] {
				add(&c.AssessedOnly)
			}
		}
	}
	out := make([]CellMetrics, 0, len(cells))
	for _, c := range cells {
		for _, counts := range []Counts{c.EndToEnd, c.AssessedOnly} {
			if counts.unitSum() != counts.Denominator {
				return nil, fmt.Errorf("%w: cell %s counts %d units in states but has denominator %d", ErrScoring, c.UnitKind, counts.unitSum(), counts.Denominator)
			}
		}
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UnitKind < out[j].UnitKind })
	return out, nil
}

// OutOfScopeFindings counts the distinct findings of complete observations that Score leaves out of every
// cell: a subject the truth does not contain, or a unit kind it does not contain. They are deduplicated by
// subject and identity, as unmatched findings are. In a closed-world profile any of them fails the grade,
// so an engine cannot hide a false report by naming a kind outside the profile.
func OutOfScopeFindings(truth TruthSet, observations []Observation) int {
	kinds, subjects := truthScope(truth)
	seen := map[string]bool{}
	for _, o := range observations {
		if o.State != StateComplete || o.Truncated {
			continue
		}
		for _, f := range o.Findings {
			if !subjects[o.Subject.ID] || !kinds[f.UnitKind] {
				seen[strconv.Itoa(len(o.Subject.ID))+":"+o.Subject.ID+unitKey(f.UnitKind, f.Identity)] = true
			}
		}
	}
	return len(seen)
}

func truthScope(t TruthSet) (kinds, subjects map[string]bool) {
	kinds, subjects = map[string]bool{}, map[string]bool{}
	for _, u := range t.Units {
		kinds[u.UnitKind] = true
		subjects[u.SubjectID] = true
	}
	return kinds, subjects
}
