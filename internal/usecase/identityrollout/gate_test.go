package identityrollout

import (
	"testing"
)

func cleanLegacySnapshot() GateSnapshot {
	return GateSnapshot{
		TenantID:           "tenant-a",
		Owner:              "identity-operator",
		SourceOfTruth:      "legacy_users",
		AllowedWriters:     []string{"legacy_users"},
		SourceCount:        2,
		ProjectedCount:     2,
		BackfillCompleted:  true,
		LegacyWritesEnabled: true,
		MetricsRecorded:    true,
		ApprovalRecorded:   true,
		LastKnownGoodPhase: string(PhaseExpand),
		RollbackAction:     "disable enterprise reads and restore legacy-authoritative behavior",
	}
}

func TestEvaluateLegacyBackfillRequiresZeroDriftAndExactCardinality(t *testing.T) {
	clean := cleanLegacySnapshot()
	decision, err := Evaluate(PhaseLegacyAuthoritativeBackfill, clean)
	if err != nil || !decision.Allowed {
		t.Fatalf("clean backfill blocked: decision=%+v err=%v", decision, err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*GateSnapshot)
		code   string
	}{
		{name: "drift", mutate: func(s *GateSnapshot) { s.DriftCount = 1 }, code: "backfill_not_reconciled"},
		{name: "missing projection", mutate: func(s *GateSnapshot) { s.ProjectedCount-- }, code: "backfill_not_reconciled"},
		{name: "corrupt hash", mutate: func(s *GateSnapshot) { s.CorruptCredentialCount = 1 }, code: "corrupt_legacy_credential"},
		{name: "duplicate hash", mutate: func(s *GateSnapshot) { s.DuplicateCredentialCount = 1 }, code: "duplicate_legacy_credential"},
		{name: "bootstrap projected", mutate: func(s *GateSnapshot) { s.BootstrapMembershipCount = 1 }, code: "bootstrap_membership_present"},
		{name: "enterprise authority early", mutate: func(s *GateSnapshot) { s.AuthoritativeReads = true }, code: "enterprise_authority_enabled_early"},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := clean
			snapshot.AllowedWriters = append([]string(nil), clean.AllowedWriters...)
			test.mutate(&snapshot)
			decision, err := Evaluate(PhaseLegacyAuthoritativeBackfill, snapshot)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if decision.Allowed || !hasGateBlocker(decision, test.code) {
				t.Fatalf("decision=%+v, want blocker %q", decision, test.code)
			}
		})
	}
}

func TestEvaluateCanaryUsesOperatorSuppliedAbortThreshold(t *testing.T) {
	snapshot := cleanLegacySnapshot()
	snapshot.SourceOfTruth = "shadow_compare"
	snapshot.AllowedWriters = []string{"legacy_users"}
	snapshot.ShadowComparisonComplete = true
	snapshot.AuthoritativeReads = true
	snapshot.ObservationMinutes = 30
	snapshot.AbortThresholdBPS = 100
	snapshot.SessionCount = 1000
	snapshot.ErrorCount = 10

	decision, err := Evaluate(PhaseCanaryAuthoritativeRead, snapshot)
	if err != nil || !decision.Allowed {
		t.Fatalf("threshold boundary should pass: decision=%+v err=%v", decision, err)
	}

	snapshot.ErrorCount = 11
	decision, err = Evaluate(PhaseCanaryAuthoritativeRead, snapshot)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allowed || !hasGateBlocker(decision, "abort_threshold_exceeded") {
		t.Fatalf("decision=%+v, want abort threshold blocker", decision)
	}
}

func TestEvaluatePointOfNoReturnRequiresRecoveryEvidence(t *testing.T) {
	snapshot := cleanLegacySnapshot()
	snapshot.SourceOfTruth = "enterprise_identity"
	snapshot.AllowedWriters = []string{"enterprise_identity"}
	snapshot.ShadowComparisonComplete = true
	snapshot.AuthoritativeReads = true
	snapshot.IdentityMutations = true
	snapshot.LegacyWritesEnabled = false
	snapshot.ObservationMinutes = 30
	snapshot.AbortThresholdBPS = 100
	snapshot.SessionCount = 1000

	decision, err := Evaluate(PhasePointOfNoReturn, snapshot)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allowed || !hasGateBlocker(decision, "recovery_evidence_missing") {
		t.Fatalf("decision=%+v, want recovery blocker", decision)
	}

	snapshot.RollbackDrillPassed = true
	snapshot.PairedBackupApproved = true
	decision, err = Evaluate(PhasePointOfNoReturn, snapshot)
	if err != nil || !decision.Allowed {
		t.Fatalf("recovery-evidenced point of no return blocked: decision=%+v err=%v", decision, err)
	}
}

func TestEvaluateRejectsUnknownOrDuplicateWriterSet(t *testing.T) {
	for _, writers := range [][]string{{"legacy_users", "legacy_users"}, {"legacy_users", "future_writer"}, {}} {
		snapshot := cleanLegacySnapshot()
		snapshot.AllowedWriters = writers
		decision, err := Evaluate(PhaseExpand, snapshot)
		if err != nil {
			t.Fatalf("Evaluate(%v): %v", writers, err)
		}
		if decision.Allowed || !hasGateBlocker(decision, "writer_set_invalid") {
			t.Fatalf("writers=%v decision=%+v, want writer_set_invalid", writers, decision)
		}
	}
}

func hasGateBlocker(decision GateDecision, code string) bool {
	for _, blocker := range decision.Blockers {
		if blocker.Code == code {
			return true
		}
	}
	return false
}
