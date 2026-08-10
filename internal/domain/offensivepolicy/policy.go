// Package offensivepolicy is the machine-readable half of the offensive governance policy
// (docs/redteam/offensive-policy.md, issue #418).
//
// It answers one question and answers it fail-closed: may this technique run at all, and under whose
// signature. A technique absent from the register is REFUSED — the register is an allowlist, not a
// denylist, because the set of things an offensive engine could attempt is unbounded while the set it
// has been authorised to attempt is not.
//
// The document is the source of truth. This package embeds policy.yaml, which mirrors the document's
// technique register, and policy_gen_test.go fails the build when the two diverge in either direction.
// Neither file may be edited alone.
//
// Pure domain: no I/O, no clock, no policy decision that depends on anything outside its inputs.
package offensivepolicy

import (
	_ "embed"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

//go:embed policy.yaml
var embeddedPolicy []byte

// Disruption is the probability that executing a technique degrades availability of the target.
type Disruption string

const (
	DisruptionNone Disruption = "none"
	DisruptionLow  Disruption = "low"
	DisruptionHigh Disruption = "high"
)

// Valid reports whether d is one of the three defined levels. An unset or unknown level is not
// classifiable, and an unclassifiable technique is refused.
func (d Disruption) Valid() bool {
	switch d {
	case DisruptionNone, DisruptionLow, DisruptionHigh:
		return true
	default:
		return false
	}
}

// Reversibility is whether target state changes can be undone by a declared, tested cleanup path.
type Reversibility string

const (
	Reversible   Reversibility = "reversible"
	Irreversible Reversibility = "irreversible"
)

// Valid reports whether r is one of the two defined levels.
func (r Reversibility) Valid() bool { return r == Reversible || r == Irreversible }

// RiskClass is the reduction of the two axes, per the document's §3 table.
type RiskClass string

const (
	RiskLow        RiskClass = "low"
	RiskMedium     RiskClass = "medium"
	RiskHigh       RiskClass = "high"
	RiskProhibited RiskClass = "prohibited"
)

// Valid reports whether c is one of the four defined classes.
func (c RiskClass) Valid() bool {
	switch c {
	case RiskLow, RiskMedium, RiskHigh, RiskProhibited:
		return true
	default:
		return false
	}
}

// ApprovalMode is who must sign for a technique before it may execute.
type ApprovalMode string

const (
	// ApprovalNone is the absence of an approval mode, which only a prohibited technique carries. It is
	// deliberately NOT a synonym for "no approval needed" — that is ApprovalAutomatic.
	ApprovalNone      ApprovalMode = ""
	ApprovalAutomatic ApprovalMode = "automatic"
	ApprovalSingle    ApprovalMode = "single"
	ApprovalDual      ApprovalMode = "dual"
)

// RequiredApprovals is how many DISTINCT human approvals the mode demands.
func (m ApprovalMode) RequiredApprovals() int {
	switch m {
	case ApprovalSingle:
		return 1
	case ApprovalDual:
		return 2
	default:
		return 0
	}
}

// Radius is the blast radius of a technique.
type Radius string

const (
	RadiusReadOnly      Radius = "read_only"
	RadiusStateChanging Radius = "state_changing"
)

// Valid reports whether r is one of the two defined radii.
func (r Radius) Valid() bool { return r == RadiusReadOnly || r == RadiusStateChanging }

// CleanupSpec is the ordered path that undoes a state-changing technique, plus how the undo is
// confirmed. A state-changing technique without both is not implementable (document §7) and fails the
// register's validation, which runs in CI rather than at execution time.
type CleanupSpec struct {
	Steps        []string `yaml:"steps"`
	Verification string   `yaml:"verification"`
}

// IsZero reports whether no cleanup path was declared at all.
func (c CleanupSpec) IsZero() bool {
	return len(c.Steps) == 0 && strings.TrimSpace(c.Verification) == ""
}

// TechniquePolicy is one register entry: everything the enforcement path needs to decide whether this
// technique may run, and everything an auditor needs to see why.
type TechniquePolicy struct {
	Technique      string        `yaml:"technique"`
	TaxonomyRef    string        `yaml:"taxonomy_ref"`
	Disruption     Disruption    `yaml:"disruption"`
	Reversibility  Reversibility `yaml:"reversibility"`
	RiskClass      RiskClass     `yaml:"risk_class"`
	Approval       ApprovalMode  `yaml:"approval"`
	BlastRadius    Radius        `yaml:"blast_radius"`
	Cleanup        CleanupSpec   `yaml:"cleanup"`
	ProductionSafe bool          `yaml:"production_safe"`
}

// LegalReview records the document's review status. ProductionSafe is refused for every technique while
// Reviewed is false, so a register cannot quietly claim production readiness ahead of the review.
type LegalReview struct {
	Reviewed bool   `yaml:"reviewed"`
	Date     string `yaml:"date"`
	Owner    string `yaml:"owner"`
}

// Register is the whole policy: the review status plus every classified technique.
type Register struct {
	LegalReview LegalReview       `yaml:"legal_review"`
	Techniques  []TechniquePolicy `yaml:"techniques"`

	byTechnique map[string]TechniquePolicy
}

// Load parses and validates the embedded register. It is the only constructor: there is no way to build
// a Register that has not been validated, because an unvalidated policy is worse than no policy — it
// looks authoritative while permitting whatever it happens to contain.
func Load() (*Register, error) { return parse(embeddedPolicy) }

func parse(raw []byte) (*Register, error) {
	var reg Register
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // a typo'd field would otherwise be silently ignored, and silence is the enemy here
	if err := dec.Decode(&reg); err != nil {
		return nil, fmt.Errorf("%w: decode offensive policy: %v", shared.ErrValidation, err)
	}
	if err := reg.Validate(); err != nil {
		return nil, err
	}
	reg.byTechnique = make(map[string]TechniquePolicy, len(reg.Techniques))
	for _, t := range reg.Techniques {
		reg.byTechnique[t.Technique] = t
	}
	return &reg, nil
}

// Validate enforces every invariant the document states. It runs at load time and in CI, so a malformed
// register fails the build rather than the engagement.
func (r *Register) Validate() error {
	if len(r.Techniques) == 0 {
		return fmt.Errorf("%w: offensive policy register is empty", shared.ErrValidation)
	}
	seen := make(map[string]struct{}, len(r.Techniques))
	for _, t := range r.Techniques {
		name := strings.TrimSpace(t.Technique)
		if name == "" {
			return fmt.Errorf("%w: register entry has no technique id", shared.ErrValidation)
		}
		if _, dup := seen[name]; dup {
			return fmt.Errorf("%w: duplicate register entry %q", shared.ErrValidation, name)
		}
		seen[name] = struct{}{}
		if strings.TrimSpace(t.TaxonomyRef) == "" {
			return fmt.Errorf("%w: %s has no taxonomy reference", shared.ErrValidation, name)
		}
		if !t.Disruption.Valid() || !t.Reversibility.Valid() {
			return fmt.Errorf("%w: %s does not state both risk axes", shared.ErrValidation, name)
		}
		if !t.RiskClass.Valid() {
			return fmt.Errorf("%w: %s has an unknown risk class %q", shared.ErrValidation, name, t.RiskClass)
		}
		if !t.BlastRadius.Valid() {
			return fmt.Errorf("%w: %s has an unknown blast radius %q", shared.ErrValidation, name, t.BlastRadius)
		}
		// The reduction in document §3 is pessimistic and mechanical, so the register cannot disagree
		// with it: a hand-written class that is softer than the axes imply is the exact drift this
		// check exists to stop.
		if t.RiskClass != RiskProhibited {
			if want := reduce(t.Disruption, t.Reversibility); want != t.RiskClass {
				return fmt.Errorf("%w: %s is classed %q but its axes reduce to %q", shared.ErrValidation, name, t.RiskClass, want)
			}
		}
		if err := t.validateApproval(name); err != nil {
			return err
		}
		if err := t.validateCleanup(name); err != nil {
			return err
		}
		if t.ProductionSafe && !r.LegalReview.Reviewed {
			return fmt.Errorf("%w: %s is marked production-safe before the legal review is recorded", shared.ErrValidation, name)
		}
	}
	if r.LegalReview.Reviewed && (strings.TrimSpace(r.LegalReview.Date) == "" || strings.TrimSpace(r.LegalReview.Owner) == "") {
		return fmt.Errorf("%w: a recorded legal review needs both a date and an owner", shared.ErrValidation)
	}
	return nil
}

func (t TechniquePolicy) validateApproval(name string) error {
	if t.RiskClass == RiskProhibited {
		// A prohibited technique has no approval mode at all. Allowing one would imply that some
		// signature could authorise it, and none can.
		if t.Approval != ApprovalNone {
			return fmt.Errorf("%w: prohibited technique %s must not carry an approval mode", shared.ErrValidation, name)
		}
		return nil
	}
	want, ok := requiredApproval(t.RiskClass)
	if !ok {
		return fmt.Errorf("%w: %s has no approval mode for risk class %q", shared.ErrValidation, name, t.RiskClass)
	}
	if t.Approval != want {
		return fmt.Errorf("%w: %s is class %q so its approval must be %q, got %q", shared.ErrValidation, name, t.RiskClass, want, t.Approval)
	}
	return nil
}

func (t TechniquePolicy) validateCleanup(name string) error {
	if t.BlastRadius != RadiusStateChanging {
		if !t.Cleanup.IsZero() {
			return fmt.Errorf("%w: read-only technique %s declares a cleanup path", shared.ErrValidation, name)
		}
		return nil
	}
	// Document §7: a state-changing technique that cannot state its cleanup path is not implementable.
	// Prohibited entries are exempt because they never execute, and demanding a cleanup path for an
	// action we refuse to perform would be theatre.
	if t.RiskClass == RiskProhibited {
		return nil
	}
	if len(t.Cleanup.Steps) == 0 {
		return fmt.Errorf("%w: state-changing technique %s declares no cleanup steps", shared.ErrValidation, name)
	}
	if strings.TrimSpace(t.Cleanup.Verification) == "" {
		return fmt.Errorf("%w: state-changing technique %s declares no cleanup verification", shared.ErrValidation, name)
	}
	return nil
}

// reduce applies the document §3 reduction. It is deliberately pessimistic: one high axis produces a
// high class.
func reduce(d Disruption, r Reversibility) RiskClass {
	if r == Irreversible || d == DisruptionHigh {
		return RiskHigh
	}
	if d == DisruptionLow {
		return RiskMedium
	}
	return RiskLow
}

// requiredApproval is the document §4 matrix.
func requiredApproval(c RiskClass) (ApprovalMode, bool) {
	switch c {
	case RiskLow:
		return ApprovalAutomatic, true
	case RiskMedium:
		return ApprovalSingle, true
	case RiskHigh:
		return ApprovalDual, true
	default:
		return ApprovalNone, false
	}
}

// Lookup returns the policy for a technique. The second result is false when the technique is not in
// the register, which callers MUST treat as a refusal rather than as an absence of restriction.
func (r *Register) Lookup(technique string) (TechniquePolicy, bool) {
	if r == nil {
		return TechniquePolicy{}, false
	}
	t, ok := r.byTechnique[strings.TrimSpace(technique)]
	return t, ok
}

// Techniques returns every entry in a deterministic order, for enumeration and dry-run listing.
func (r *Register) TechniqueIDs() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.byTechnique))
	for name := range r.byTechnique {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// RiskCeilingPermits reports whether an engagement whose ceiling is ceiling may run class have.
//
// The ceiling only ever NARROWS what the register permits (document §5): it cannot widen it, and it can
// never permit a prohibited technique whatever it is set to.
func RiskCeilingPermits(ceiling, have RiskClass) bool {
	// An unset or unknown ceiling permits NOTHING. Ranking it above the classes instead would make a
	// missing engagement field the most permissive setting available, which is the fail-open this whole
	// package exists to avoid. "prohibited" is not a permission level either: it is a refusal, so it
	// cannot appear on either side.
	ceilingRank, ok := permissionRank(ceiling)
	if !ok {
		return false
	}
	haveRank, ok := permissionRank(have)
	if !ok {
		return false
	}
	return haveRank <= ceilingRank
}

// permissionRank orders the three executable classes. The second result is false for anything that is
// not an executable class — unset, unknown, or prohibited.
func permissionRank(c RiskClass) (int, bool) {
	switch c {
	case RiskLow:
		return 1, true
	case RiskMedium:
		return 2, true
	case RiskHigh:
		return 3, true
	default:
		return 0, false
	}
}
