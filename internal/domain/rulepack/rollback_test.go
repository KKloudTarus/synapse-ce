package rulepack

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
)

func TestRollbackRemainsAvailableAfterCompatibilityRegression(t *testing.T) {
	p := seal(t)
	d := RulePackDeployment{
		PackID: p.ID, PackVersion: p.Version, PackDigest: p.Digest,
		AgentVersion: "1.2.1", SchemaVersion: 1,
		Sensors:         []SensorRequirement{{ID: "ebpf", MinVersion: "2.1.0"}},
		AvailableFields: []detection.Field{detection.FieldProcArg, detection.FieldProcComm},
		Cohort:          "canary-a", State: DeploymentPromoted, PreviousVersion: p.RollbackVersion,
	}

	// Model the failure mode that makes rollback necessary: the forward deployment can no longer
	// satisfy this pack's required telemetry fields. Forward compatibility must fail, but the signed
	// rollback target remains a valid escape hatch.
	d.AvailableFields = []detection.Field{detection.FieldProcComm}
	if err := Compatible(p, d); err == nil {
		t.Fatal("compatibility regression must be detected")
	}
	rolled, err := Transition(p, d, DeploymentRolledBack)
	if err != nil {
		t.Fatalf("compatibility regression must not block rollback: %v", err)
	}
	if rolled.State != DeploymentRolledBack {
		t.Fatalf("rollback state = %q", rolled.State)
	}

	wrong := d
	wrong.PreviousVersion = p.RollbackVersion - 1
	if _, err := Transition(p, wrong, DeploymentRolledBack); err == nil {
		t.Fatal("rollback to a version not named by signed metadata must fail")
	}
}
