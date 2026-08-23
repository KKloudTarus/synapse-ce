// Package rulepack models signed, versioned detection content and its release metadata (#630).
// It is pure domain code: no I/O, clock, database, transport, or deployment side effects live here.
package rulepack

import (
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetversion"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// SensorRequirement names one sensor/plugin and the minimum version a deployment must provide.
type SensorRequirement struct {
	ID         string `json:"id"`
	MinVersion string `json:"min_version"`
}

// ATTACKMapping binds a detection rule to the public ATT&CK technique it claims to cover.
type ATTACKMapping struct {
	RuleID      string `json:"rule_id"`
	TechniqueID string `json:"technique_id"`
}

// Fixture is one deterministic replay input. Positive fixtures carry the exact rule IDs expected to
// fire. Negative fixtures carry no expected IDs and therefore fail if ANY rule fires.
type Fixture struct {
	ID              string          `json:"id"`
	Event           detection.Event `json:"event"`
	ExpectedRuleIDs []string        `json:"expected_rule_ids,omitempty"`
}

// RuleCostBudget is the maximum measured cost accepted for one rule by the promotion gate. The gate
// consumes measured integer microseconds instead of benchmarking wall-clock duration itself, keeping the
// decision reproducible across machines.
type RuleCostBudget struct {
	RuleID                 string `json:"rule_id"`
	MaxLatencyMicros       int64  `json:"max_latency_micros"`
	MaxCPUMicrosPerHostDay int64  `json:"max_cpu_micros_per_host_day"`
}

// SuppressionPolicy bounds how much rule output may be suppressed without blocking promotion. The value
// is basis points (0..10000), so the gate never depends on floating-point rounding.
type SuppressionPolicy struct {
	MaxSuppressionRateBPS int `json:"max_suppression_rate_bps"`
}

// Resource bounds keep signed or malformed content from turning verification/replay into unbounded work.
const (
	MaxRules                = 1024
	MaxFixturesPerKind      = 4096
	MaxPredicatesPerRule    = 64
	MaxValuesPerPredicate   = 256
	MaxSensors              = 128
	MaxRequiredFields       = 256
	MaxATTACKMappings       = 4096
	MaxRolloutCohorts       = 64
	MaxFixtureEventBytes    = 64 << 10
	MaxIdentifierBytes      = 256
	MaxPredicateStringBytes = 4096
)

// RulePack is the immutable content unit promoted by #630. Digest is derived from every content and
// compatibility field except Digest itself; reordering set-like fields does not change it.
type RulePack struct {
	ID                     string              `json:"id"`
	Version                int                 `json:"version"`
	Digest                 string              `json:"digest"`
	Rules                  []detection.Rule    `json:"rules"`
	MinAgentVersion        string              `json:"min_agent_version"`
	RequiredSchemaVersions []int               `json:"required_schema_versions"`
	RequiredSensors        []SensorRequirement `json:"required_sensors"`
	RequiredFields         []detection.Field   `json:"required_fields"`
	ATTACKMappings         []ATTACKMapping     `json:"attack_mappings"`
	PositiveFixtures       []Fixture           `json:"positive_fixtures"`
	NegativeFixtures       []Fixture           `json:"negative_fixtures"`
	ExpectedCost           []RuleCostBudget    `json:"expected_cost"`
	SuppressionPolicy      SuppressionPolicy   `json:"suppression_policy"`
	RolloutCohort          []string            `json:"rollout_cohort"`
	RollbackVersion        int                 `json:"rollback_version"`
}

// SignedArtifact is a detached RulePack signature plus the exact content it covers. It deliberately does
// not embed a public key: verification requires a caller-supplied trusted key, so an attacker cannot ship
// an arbitrary self-signed key and have the artifact declare itself trusted.
type SignedArtifact struct {
	Pack      RulePack `json:"pack"`
	Algorithm string   `json:"algorithm"`
	KeyID     string   `json:"key_id"`
	Signature string   `json:"signature"`
}

// DeploymentState is the local lifecycle state of one pack. Secure distribution and wire-side
// anti-downgrade enforcement belong to #631; this state is release metadata only.
type DeploymentState string

const (
	DeploymentCandidate  DeploymentState = "candidate"
	DeploymentCanary     DeploymentState = "canary"
	DeploymentPromoted   DeploymentState = "promoted"
	DeploymentRolledBack DeploymentState = "rolled_back"
)

// RulePackDeployment records the engine/plugin compatibility surface and rollout state against which the
// release gate evaluates a RulePack.
type RulePackDeployment struct {
	PackID          string              `json:"pack_id"`
	PackVersion     int                 `json:"pack_version"`
	PackDigest      string              `json:"pack_digest"`
	AgentVersion    string              `json:"agent_version"`
	SchemaVersion   int                 `json:"schema_version"`
	Sensors         []SensorRequirement `json:"sensors"`
	AvailableFields []detection.Field   `json:"available_fields"`
	Cohort          string              `json:"cohort"`
	State           DeploymentState     `json:"state"`
	PreviousVersion int                 `json:"previous_version"`
}

// New validates a RulePack specification, defensively copies it, computes its canonical digest, and
// returns the sealed immutable value. Any caller-supplied Digest is ignored and recomputed.
func New(spec RulePack) (*RulePack, error) {
	p := clonePack(spec)
	p.Digest = ""
	if err := p.validateContent(); err != nil {
		return nil, err
	}
	digest, err := ComputeDigest(p)
	if err != nil {
		return nil, err
	}
	p.Digest = digest
	return &p, nil
}

// Validate checks both RulePack content invariants and that Digest exactly matches the canonical content.
func (p RulePack) Validate() error {
	if err := p.validateContent(); err != nil {
		return err
	}
	if !strings.HasPrefix(p.Digest, DigestPrefix) {
		return fmt.Errorf("%w: rulepack %s has no canonical digest", shared.ErrValidation, p.ID)
	}
	want, err := ComputeDigest(p)
	if err != nil {
		return err
	}
	if p.Digest != want {
		return fmt.Errorf("%w: rulepack %s digest does not match its content", shared.ErrValidation, p.ID)
	}
	return nil
}

func (p RulePack) validateContent() error {
	if strings.TrimSpace(p.ID) == "" || strings.TrimSpace(p.ID) != p.ID || len(p.ID) > MaxIdentifierBytes {
		return fmt.Errorf("%w: rulepack id must be trimmed, non-empty, and at most %d bytes", shared.ErrValidation, MaxIdentifierBytes)
	}
	if p.Version < 1 {
		return fmt.Errorf("%w: rulepack %s version must be >= 1", shared.ErrValidation, p.ID)
	}
	if len(p.Rules) == 0 || len(p.Rules) > MaxRules {
		return fmt.Errorf("%w: rulepack %s must carry 1..%d rules", shared.ErrValidation, p.ID, MaxRules)
	}
	if p.Version == 1 {
		if p.RollbackVersion != 0 {
			return fmt.Errorf("%w: rulepack %s version 1 must use rollback version 0", shared.ErrValidation, p.ID)
		}
	} else if p.RollbackVersion < 1 || p.RollbackVersion >= p.Version {
		return fmt.Errorf("%w: rulepack %s rollback version must be between 1 and %d", shared.ErrValidation, p.ID, p.Version-1)
	}
	if p.MinAgentVersion != "" {
		if strings.TrimSpace(p.MinAgentVersion) != p.MinAgentVersion {
			return fmt.Errorf("%w: rulepack %s min agent version must be trimmed", shared.ErrValidation, p.ID)
		}
		if _, ok := fleetversion.Parse(p.MinAgentVersion); !ok {
			return fmt.Errorf("%w: rulepack %s has unparseable min agent version %q", shared.ErrValidation, p.ID, p.MinAgentVersion)
		}
	}
	if len(p.RequiredSchemaVersions) == 0 || len(p.RequiredSchemaVersions) > 64 {
		return fmt.Errorf("%w: rulepack %s must name 1..64 telemetry schema versions", shared.ErrValidation, p.ID)
	}
	if err := validateUniquePositiveInts("schema version", p.RequiredSchemaVersions); err != nil {
		return fmt.Errorf("rulepack %s: %w", p.ID, err)
	}
	if p.SuppressionPolicy.MaxSuppressionRateBPS < 0 || p.SuppressionPolicy.MaxSuppressionRateBPS > 10000 {
		return fmt.Errorf("%w: rulepack %s suppression rate must be 0..10000 basis points", shared.ErrValidation, p.ID)
	}

	rules := make(map[string]detection.Rule, len(p.Rules))
	for i, r := range p.Rules {
		if len(r.Matcher.All) > MaxPredicatesPerRule {
			return fmt.Errorf("%w: rule %s has more than %d predicates", shared.ErrValidation, r.ID, MaxPredicatesPerRule)
		}
		if err := validatePredicateBounds(r); err != nil {
			return err
		}
		if err := r.Validate(); err != nil {
			return fmt.Errorf("rulepack %s rule[%d]: %w", p.ID, i, err)
		}
		if _, dup := rules[r.ID]; dup {
			return fmt.Errorf("%w: rulepack %s has duplicate rule id %q", shared.ErrValidation, p.ID, r.ID)
		}
		if err := validatePredicatesUnique(r); err != nil {
			return err
		}
		rules[r.ID] = r
	}

	if len(p.RequiredSensors) == 0 || len(p.RequiredSensors) > MaxSensors {
		return fmt.Errorf("%w: rulepack %s must name 1..%d required sensors", shared.ErrValidation, p.ID, MaxSensors)
	}
	if err := validateSensors(p.RequiredSensors); err != nil {
		return err
	}
	matcherFields := make(map[detection.Field]struct{})
	for _, r := range p.Rules {
		for _, pred := range r.Matcher.All {
			matcherFields[pred.Field] = struct{}{}
		}
	}
	if len(p.RequiredFields) > MaxRequiredFields {
		return fmt.Errorf("%w: rulepack %s has more than %d required fields", shared.ErrValidation, p.ID, MaxRequiredFields)
	}
	if len(p.ATTACKMappings) == 0 || len(p.ATTACKMappings) > MaxATTACKMappings {
		return fmt.Errorf("%w: rulepack %s must carry 1..%d ATT&CK mappings", shared.ErrValidation, p.ID, MaxATTACKMappings)
	}
	if len(p.RolloutCohort) > MaxRolloutCohorts {
		return fmt.Errorf("%w: rulepack %s has more than %d rollout cohorts", shared.ErrValidation, p.ID, MaxRolloutCohorts)
	}
	if err := validateRequiredFields(p.RequiredFields, matcherFields); err != nil {
		return err
	}
	if err := validateATTACKMappings(p.ATTACKMappings, rules); err != nil {
		return err
	}
	if err := validateFixtures(p.PositiveFixtures, true, rules); err != nil {
		return err
	}
	if err := validateFixtures(p.NegativeFixtures, false, rules); err != nil {
		return err
	}
	if err := validateFixtureIDsUnique(p.PositiveFixtures, p.NegativeFixtures); err != nil {
		return err
	}
	if err := validateCostBudgets(p.ExpectedCost, rules); err != nil {
		return err
	}
	if err := validateCohorts(p.RolloutCohort); err != nil {
		return err
	}
	return nil
}
