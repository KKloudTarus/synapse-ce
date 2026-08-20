package rulepack

import (
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetversion"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetryschema"
)

// Compatible validates that deployment can execute this exact RulePack without missing a required
// engine/schema/sensor/field capability. Canary deployments must also belong to the pack cohort.
func Compatible(p RulePack, d RulePackDeployment) error {
	if err := validateDeploymentIdentity(p, d); err != nil {
		return err
	}
	if d.PreviousVersion != p.RollbackVersion {
		return fmt.Errorf("%w: deployment previous version %d does not match rulepack rollback version %d", shared.ErrValidation, d.PreviousVersion, p.RollbackVersion)
	}
	if !fleetversion.MeetsFloor(d.AgentVersion, p.MinAgentVersion) {
		return fmt.Errorf("%w: agent version %q is below rulepack floor %q", shared.ErrValidation, d.AgentVersion, p.MinAgentVersion)
	}
	if err := telemetryschema.Validate(d.SchemaVersion); err != nil {
		return fmt.Errorf("%w: deployment telemetry schema is unsupported by this control-plane reader", err)
	}
	if !containsInt(p.RequiredSchemaVersions, d.SchemaVersion) {
		return fmt.Errorf("%w: telemetry schema version %d is not supported by rulepack", shared.ErrValidation, d.SchemaVersion)
	}
	deployedSensors := make(map[string]string, len(d.Sensors))
	for _, s := range d.Sensors {
		deployedSensors[s.ID] = s.MinVersion
	}
	for _, req := range p.RequiredSensors {
		got, ok := deployedSensors[req.ID]
		if !ok || !versionAtLeast(got, req.MinVersion) {
			return fmt.Errorf("%w: sensor %s does not meet required version %s", shared.ErrValidation, req.ID, req.MinVersion)
		}
	}
	available := make(map[detection.Field]struct{}, len(d.AvailableFields))
	for _, f := range d.AvailableFields {
		available[f] = struct{}{}
	}
	for _, f := range p.RequiredFields {
		if _, ok := available[f]; !ok {
			return fmt.Errorf("%w: deployment cannot provide required field %q", shared.ErrValidation, f)
		}
	}
	if (d.State == DeploymentCandidate || d.State == DeploymentCanary) && !containsString(p.RolloutCohort, d.Cohort) {
		return fmt.Errorf("%w: canary deployment cohort %q is not authorized by this rulepack", shared.ErrValidation, d.Cohort)
	}
	return nil
}

func validateDeploymentIdentity(p RulePack, d RulePackDeployment) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := d.Validate(); err != nil {
		return err
	}
	if d.PackID != p.ID || d.PackVersion != p.Version || d.PackDigest != p.Digest {
		return fmt.Errorf("%w: deployment does not identify this exact rulepack", shared.ErrValidation)
	}
	return nil
}

// Validate checks deployment metadata without performing the pack-specific compatibility comparison.
func (d RulePackDeployment) Validate() error {
	if strings.TrimSpace(d.PackID) == "" || strings.TrimSpace(d.PackID) != d.PackID || d.PackVersion < 1 || !strings.HasPrefix(d.PackDigest, DigestPrefix) {
		return fmt.Errorf("%w: rulepack deployment has incomplete pack identity", shared.ErrValidation)
	}
	if strings.TrimSpace(d.AgentVersion) != d.AgentVersion {
		return fmt.Errorf("%w: rulepack deployment agent version must be trimmed", shared.ErrValidation)
	}
	if _, ok := fleetversion.Parse(d.AgentVersion); !ok {
		return fmt.Errorf("%w: rulepack deployment has unparseable agent version %q", shared.ErrValidation, d.AgentVersion)
	}
	if strings.TrimSpace(d.Cohort) == "" || strings.TrimSpace(d.Cohort) != d.Cohort || len(d.Cohort) > MaxIdentifierBytes {
		return fmt.Errorf("%w: rulepack deployment cohort must be trimmed, non-empty, and at most %d bytes", shared.ErrValidation, MaxIdentifierBytes)
	}
	if d.SchemaVersion < 1 {
		return fmt.Errorf("%w: rulepack deployment schema version must be >= 1", shared.ErrValidation)
	}
	if len(d.Sensors) > MaxSensors {
		return fmt.Errorf("%w: deployment has more than %d sensors", shared.ErrValidation, MaxSensors)
	}
	if len(d.AvailableFields) > MaxRequiredFields {
		return fmt.Errorf("%w: deployment has more than %d available fields", shared.ErrValidation, MaxRequiredFields)
	}
	if err := validateSensors(d.Sensors); err != nil {
		return err
	}
	if err := validateFieldSet(d.AvailableFields); err != nil {
		return err
	}
	switch d.State {
	case DeploymentCandidate, DeploymentCanary, DeploymentPromoted, DeploymentRolledBack:
	default:
		return fmt.Errorf("%w: unknown rulepack deployment state %q", shared.ErrValidation, d.State)
	}
	if d.PreviousVersion < 0 || d.PreviousVersion >= d.PackVersion {
		return fmt.Errorf("%w: deployment previous version must be older than pack version", shared.ErrValidation)
	}
	return nil
}

// Transition applies one release-control transition. Forward movement requires full pack compatibility.
// Rollback deliberately requires only exact pack identity plus signed rollback metadata: a sensor/field
// compatibility regression must not disable the escape hatch used to leave the bad rollout. #631 is
// responsible for actually distributing content and enforcing anti-downgrade on the wire.
func Transition(p RulePack, d RulePackDeployment, next DeploymentState) (RulePackDeployment, error) {
	if next == DeploymentRolledBack {
		if err := validateDeploymentIdentity(p, d); err != nil {
			return RulePackDeployment{}, err
		}
		if (d.State != DeploymentCanary && d.State != DeploymentPromoted) || p.RollbackVersion <= 0 || d.PreviousVersion != p.RollbackVersion {
			return RulePackDeployment{}, fmt.Errorf("%w: invalid rulepack deployment transition %s -> %s", shared.ErrValidation, d.State, next)
		}
		out := cloneDeployment(d)
		out.State = next
		return out, nil
	}

	if err := Compatible(p, d); err != nil {
		return RulePackDeployment{}, err
	}
	allowed := d.State == DeploymentCandidate && next == DeploymentCanary || d.State == DeploymentCanary && next == DeploymentPromoted
	if !allowed {
		return RulePackDeployment{}, fmt.Errorf("%w: invalid rulepack deployment transition %s -> %s", shared.ErrValidation, d.State, next)
	}
	out := cloneDeployment(d)
	out.State = next
	return out, nil
}

func cloneDeployment(d RulePackDeployment) RulePackDeployment {
	c := d
	c.Sensors = append([]SensorRequirement(nil), d.Sensors...)
	c.AvailableFields = append([]detection.Field(nil), d.AvailableFields...)
	return c
}

func validateFieldSet(fields []detection.Field) error {
	seen := map[detection.Field]struct{}{}
	for _, f := range fields {
		if !f.Valid() {
			return fmt.Errorf("%w: deployment contains unknown field %q", shared.ErrValidation, f)
		}
		if _, dup := seen[f]; dup {
			return fmt.Errorf("%w: deployment contains duplicate field %q", shared.ErrValidation, f)
		}
		seen[f] = struct{}{}
	}
	return nil
}

func versionAtLeast(got, want string) bool {
	g, gok := fleetversion.Parse(got)
	w, wok := fleetversion.Parse(want)
	return gok && wok && g.Compare(w) >= 0
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func containsString(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
