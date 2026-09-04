package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	lineageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestPostgresFindingLineageRepositoryRLSCollisionCASAndImmutability(t *testing.T) {
	ctx, pool := setupTestDB(t)
	suffix := time.Now().UnixNano()
	tenantA := shared.ID(fmt.Sprintf("lineage-tenant-a-%d", suffix))
	tenantB := shared.ID(fmt.Sprintf("lineage-tenant-b-%d", suffix))
	cycleID, snapshotID := createFindingLineageSnapshot(t, ctx, pool, tenantA, fmt.Sprintf("a-%d", suffix))
	ensureTestTenantAndEngagement(t, ctx, pool, tenantB, shared.ID(fmt.Sprintf("lineage-other-%d", suffix)), "", "")
	repository := NewFindingLineageRepository(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)

	identityOne, observationOne := postgresFindingLineagePair(t, tenantA, cycleID, snapshotID, "identity-one", "observation-one", "source-one", "collision", now)
	identityTwo, observationTwo := postgresFindingLineagePair(t, tenantA, cycleID, snapshotID, "identity-two", "observation-two", "source-two", "collision", now.Add(time.Second))
	if err := repository.CreateIdentityWithObservation(ctx, identityOne, observationOne); err != nil {
		t.Fatal(err)
	}
	if err := repository.CreateIdentityWithObservation(ctx, identityTwo, observationTwo); err != nil {
		t.Fatal(err)
	}
	identities, err := repository.FindIdentitiesByFingerprint(ctx, tenantA, cycleID, "sca", "vulnerability", 1, "repo:example", identityOne.LineageFingerprint)
	if err != nil || len(identities) != 2 {
		t.Fatalf("fingerprint identities=%+v err=%v", identities, err)
	}
	if _, err := repository.GetIdentity(ctx, tenantB, cycleID, identityOne.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant identity read=%v", err)
	}

	aliasFingerprint, err := findinglineage.HashAlias("sca", "vulnerability", "repo:example", 1, "legacy:one")
	if err != nil {
		t.Fatal(err)
	}
	alias := findinglineage.Alias{
		TenantID: tenantA, CycleID: cycleID, ID: "alias-one", IdentityID: identityOne.ID, ProducerKind: "sca",
		FindingKind: "vulnerability", TargetCanonical: "repo:example", SchemaVersion: 1, Fingerprint: aliasFingerprint,
		ApprovedBy: "reviewer", ApprovedAt: now,
	}
	if created, err := repository.AppendAlias(ctx, alias); err != nil || !created {
		t.Fatalf("append alias created=%v err=%v", created, err)
	}
	if created, err := repository.AppendAlias(ctx, alias); err != nil || created {
		t.Fatalf("replay alias created=%v err=%v", created, err)
	}
	aliased, err := repository.FindIdentitiesByAlias(ctx, tenantA, cycleID, "sca", "vulnerability", 1, "repo:example", aliasFingerprint)
	if err != nil || len(aliased) != 1 || aliased[0].ID != identityOne.ID {
		t.Fatalf("aliased identities=%+v err=%v", aliased, err)
	}

	sourceHash, err := findinglineage.SourceReferenceHash("sca", "vulnerability", "repo:example", "incoming", "")
	if err != nil {
		t.Fatal(err)
	}
	refs := []findinglineage.CandidateRef{
		{Position: 0, Role: findinglineage.RoleSource, ExternalReferenceHash: sourceHash, Method: findinglineage.MethodFingerprint, ScoreMilli: 1000, Confidence: findinglineage.ConfidenceHigh},
		{Position: 1, Role: findinglineage.RoleCandidate, IdentityID: identityOne.ID, Method: findinglineage.MethodFingerprint, ScoreMilli: 1000, Confidence: findinglineage.ConfidenceHigh},
		{Position: 2, Role: findinglineage.RoleCandidate, IdentityID: identityTwo.ID, Method: findinglineage.MethodFingerprint, ScoreMilli: 1000, Confidence: findinglineage.ConfidenceHigh},
	}
	newCandidate := func(id shared.ID) findinglineage.MatchCandidate {
		candidate, err := findinglineage.NewMatchCandidate(findinglineage.MatchCandidate{
			TenantID: tenantA, CycleID: cycleID, SnapshotID: snapshotID, ID: id, ProducerKind: "sca", FindingKind: "vulnerability",
			Reason: findinglineage.ReasonFingerprintCollision, FingerprintSchemaVersion: 1, Fingerprint: identityOne.LineageFingerprint,
			SourceReferenceHash: sourceHash, Refs: refs, CreatedAt: now.Add(2 * time.Second),
		})
		if err != nil {
			t.Fatal(err)
		}
		return candidate
	}

	type candidateResult struct {
		candidate findinglineage.MatchCandidate
		created   bool
		err       error
	}
	results := make(chan candidateResult, 2)
	var wait sync.WaitGroup
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			candidate, created, err := repository.CreateCandidate(context.Background(), newCandidate(shared.ID(fmt.Sprintf("candidate-%d", index))), shared.ID(fmt.Sprintf("supersession-%d", index)))
			results <- candidateResult{candidate: candidate, created: created, err: err}
		}(index)
	}
	wait.Wait()
	close(results)
	var winner findinglineage.MatchCandidate
	var creates, replays int
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.created {
			creates++
			winner = result.candidate
		} else {
			replays++
		}
	}
	if creates != 1 || replays != 1 || winner.ID.IsZero() {
		t.Fatalf("candidate concurrency creates=%d replays=%d winner=%+v", creates, replays, winner)
	}

	identityThree, observationThree := postgresFindingLineagePair(t, tenantA, cycleID, snapshotID, "identity-three", "observation-three", "source-three", "collision", now.Add(3*time.Second))
	if err := repository.CreateIdentityWithObservation(ctx, identityThree, observationThree); err != nil {
		t.Fatal(err)
	}
	changedRefs := append(append([]findinglineage.CandidateRef(nil), refs...), findinglineage.CandidateRef{
		Position: 3, Role: findinglineage.RoleCandidate, IdentityID: identityThree.ID, Method: findinglineage.MethodFingerprint, ScoreMilli: 1000, Confidence: findinglineage.ConfidenceHigh,
	})
	changed, err := findinglineage.NewMatchCandidate(findinglineage.MatchCandidate{
		TenantID: tenantA, CycleID: cycleID, SnapshotID: snapshotID, ID: "candidate-changed", ProducerKind: "sca", FindingKind: "vulnerability",
		Reason: findinglineage.ReasonFingerprintCollision, FingerprintSchemaVersion: 1, Fingerprint: identityOne.LineageFingerprint,
		SourceReferenceHash: sourceHash, Refs: changedRefs, CreatedAt: now.Add(4 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	changed, created, err := repository.CreateCandidate(ctx, changed, "candidate-auto-supersession")
	if err != nil || !created {
		t.Fatalf("changed candidate=%+v created=%v err=%v", changed, created, err)
	}
	prior, err := repository.GetCandidate(ctx, tenantA, cycleID, winner.ID)
	if err != nil || prior.Status != findinglineage.CandidateSuperseded || prior.SupersededByCandidateID != changed.ID {
		t.Fatalf("prior candidate=%+v err=%v", prior, err)
	}
	resolutionEvents, err := repository.ListCandidateResolutions(ctx, tenantA, cycleID, winner.ID)
	if err != nil || len(resolutionEvents) != 1 || resolutionEvents[0].Action != findinglineage.ResolutionSupersede {
		t.Fatalf("automatic resolutions=%+v err=%v", resolutionEvents, err)
	}

	if err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE finding_match_candidates SET fingerprint=$1 WHERE tenant_id=$2 AND cycle_id=$3 AND id=$4`, strings.Repeat("f", 64), tenantA.String(), cycleID.String(), changed.ID.String())
		return err
	}); err == nil {
		t.Fatal("candidate immutable fingerprint accepted mutation")
	}

	updated, resolution, err := findinglineage.ResolveCandidate(changed, "resolution-dismiss", findinglineage.ResolutionDismiss,
		"reviewer", "not actionable", nil, "", 1, "", now.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	staleUpdated, staleResolution, err := findinglineage.ResolveCandidate(changed, "resolution-stale", findinglineage.ResolutionDismiss,
		"reviewer", "duplicate decision", nil, "", 1, "", now.Add(6*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	resolved, storedResolution, applied, err := repository.ResolveCandidateCAS(ctx, updated, resolution)
	if err != nil || !applied || resolved.Status != findinglineage.CandidateResolved || storedResolution.Version != 2 {
		t.Fatalf("resolved=%+v event=%+v applied=%v err=%v", resolved, storedResolution, applied, err)
	}
	if _, _, _, err := repository.ResolveCandidateCAS(ctx, staleUpdated, staleResolution); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale resolution=%v", err)
	}
	if replayed, _, applied, err := repository.ResolveCandidateCAS(ctx, updated, resolution); err != nil || applied || replayed.ID != resolved.ID {
		t.Fatalf("resolution replay=%+v applied=%v err=%v", replayed, applied, err)
	}

	override, err := findinglineage.NewOverrideEvent(findinglineage.OverrideEvent{
		TenantID: tenantA, CycleID: cycleID, ID: "override-one", Action: findinglineage.OverrideConfirm,
		SourceObservationID: observationOne.ID, SourceIdentityID: identityOne.ID, TargetObservationID: observationTwo.ID,
		TargetIdentityID: identityTwo.ID, Actor: "reviewer", Reason: "confirmed merge", Version: 1, CreatedAt: now.Add(7 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, applied, err := repository.AppendOverrideCAS(ctx, override); err != nil || !applied {
		t.Fatalf("append override applied=%v err=%v", applied, err)
	}
	if _, applied, err := repository.AppendOverrideCAS(ctx, override); err != nil || applied {
		t.Fatalf("override replay applied=%v err=%v", applied, err)
	}
	staleOverride, err := findinglineage.NewOverrideEvent(findinglineage.OverrideEvent{
		TenantID: tenantA, CycleID: cycleID, ID: "override-stale", Action: findinglineage.OverrideUnlink,
		SourceObservationID: observationOne.ID, TargetIdentityID: identityTwo.ID, Actor: "reviewer", Reason: "stale unlink",
		Version: 1, CreatedAt: now.Add(8 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repository.AppendOverrideCAS(ctx, staleOverride); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale override=%v", err)
	}
	active, err := repository.GetActiveOverride(ctx, tenantA, cycleID, observationOne.ID)
	if err != nil || active.ID != override.ID {
		t.Fatalf("active override=%+v err=%v", active, err)
	}

	if err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE finding_identities SET lineage_fingerprint=$1 WHERE tenant_id=$2 AND cycle_id=$3 AND id=$4`, strings.Repeat("e", 64), tenantA.String(), cycleID.String(), identityOne.ID.String())
		return err
	}); err == nil {
		t.Fatal("identity accepted mutation")
	}
	if err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM finding_match_resolution_events WHERE tenant_id=$1 AND cycle_id=$2 AND id=$3`, tenantA.String(), cycleID.String(), resolution.ID.String())
		return err
	}); err == nil {
		t.Fatal("resolution event accepted deletion")
	}

	for _, table := range []string{
		"finding_identities", "finding_identity_aliases", "finding_observations", "finding_match_candidates",
		"finding_match_candidate_refs", "finding_match_resolution_events", "finding_match_override_events", "finding_lineage_skip_records",
	} {
		var enabled, forced bool
		if err := pool.QueryRow(ctx, `SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&enabled, &forced); err != nil || !enabled || !forced {
			t.Fatalf("RLS %s enabled=%v forced=%v err=%v", table, enabled, forced, err)
		}
	}
}

func TestPostgresSCAMatcherProvisionalIdentityAndCandidate(t *testing.T) {
	ctx, pool := setupTestDB(t)
	suffix := time.Now().UnixNano()
	tenantID := shared.ID(fmt.Sprintf("sca-lineage-tenant-%d", suffix))
	cycleID, snapshotID := createFindingLineageSnapshot(t, ctx, pool, tenantID, fmt.Sprintf("sca-%d", suffix))
	clock := postgresLineageClock{now: time.Now().UTC().Truncate(time.Microsecond)}
	ids := &postgresLineageIDs{prefix: fmt.Sprintf("sca-%d", suffix)}
	service, err := lineageuc.NewService(NewFindingLineageRepository(pool), NewTenantTransactionRunner(pool), postgresLineageAudit{}, clock, ids, nil)
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := lineageuc.NewSCAMatcherV1(nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := matcher.Build(lineageuc.SCAFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", AdvisoryID: "CVE-2026-9090", PackagePURL: "pkg:npm/left-pad@1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	input := plan.Apply(lineageuc.CorrelateInput{
		TenantID: tenantID, CycleID: cycleID, SnapshotID: snapshotID,
		InputTrusted: true, OwnershipValidated: true, RedactionComplete: true,
		Observation: lineageuc.ObservationInput{
			SourceFindingID: fmt.Sprintf("sca-source-%d", suffix), Severity: shared.SeverityHigh,
			ScannerProvenance: findinglineage.ScannerProvenance{ToolName: "sca-matcher-test"}, ObservedAt: clock.now,
		},
		Actor: "integration-test",
	})
	result, err := service.Correlate(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != lineageuc.OutcomeReview || result.Identity == nil || result.Observation == nil || result.Candidate == nil {
		t.Fatalf("provisional result=%+v", result)
	}
	if result.Candidate.Reason != findinglineage.ReasonInsufficientAnchor || len(result.Candidate.Refs) != 2 || result.Candidate.Refs[1].IdentityID != result.Identity.ID {
		t.Fatalf("provisional candidate=%+v", result.Candidate)
	}
	repository := NewFindingLineageRepository(pool)
	if _, err := repository.GetIdentity(ctx, tenantID, cycleID, result.Identity.ID); err != nil {
		t.Fatalf("load provisional identity: %v", err)
	}
	if _, err := repository.GetCandidate(ctx, tenantID, cycleID, result.Candidate.ID); err != nil {
		t.Fatalf("load provisional candidate: %v", err)
	}
}

func TestPostgresSASTMatcherCanonicalIdentityAndTenantIsolation(t *testing.T) {
	ctx, pool := setupTestDB(t)
	suffix := time.Now().UnixNano()
	tenantID := shared.ID(fmt.Sprintf("sast-lineage-tenant-%d", suffix))
	otherTenantID := shared.ID(fmt.Sprintf("sast-lineage-other-%d", suffix))
	cycleID, snapshotID := createFindingLineageSnapshot(t, ctx, pool, tenantID, fmt.Sprintf("sast-%d", suffix))
	ensureTestTenantAndEngagement(t, ctx, pool, otherTenantID, shared.ID(fmt.Sprintf("sast-lineage-other-assessment-%d", suffix)), "", "")
	clock := postgresLineageClock{now: time.Now().UTC().Truncate(time.Microsecond)}
	ids := &postgresLineageIDs{prefix: fmt.Sprintf("sast-%d", suffix)}
	service, err := lineageuc.NewService(NewFindingLineageRepository(pool), NewTenantTransactionRunner(pool), postgresLineageAudit{}, clock, ids, nil)
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := lineageuc.NewSASTMatcherV1(nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := matcher.Build(lineageuc.SASTFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", RepoPath: "src/handler.go", RuleKey: "go:sqli",
		Anchor: lineageuc.SASTAnchorV1{Kind: lineageuc.SASTAnchorSymbol, SchemaVersion: 1, LanguageID: "go", QualifiedSymbol: "example.Handler.Serve"},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := plan.Apply(lineageuc.CorrelateInput{
		TenantID: tenantID, CycleID: cycleID, SnapshotID: snapshotID,
		InputTrusted: true, OwnershipValidated: true, RedactionComplete: true,
		Observation: lineageuc.ObservationInput{
			SourceFindingID: fmt.Sprintf("sast-source-%d", suffix), Severity: shared.SeverityHigh, Location: "src/handler.go:42",
			ScannerProvenance: findinglineage.ScannerProvenance{ToolName: "sast-matcher-test"}, ObservedAt: clock.now,
		},
		Actor: "integration-test",
	})
	result, err := service.Correlate(ctx, input)
	if err != nil || result.Outcome != lineageuc.OutcomeCreated || result.Identity == nil || result.Observation == nil {
		t.Fatalf("SAST result=%+v err=%v", result, err)
	}
	repository := NewFindingLineageRepository(pool)
	stored, err := repository.GetIdentity(ctx, tenantID, cycleID, result.Identity.ID)
	if err != nil || stored.ProducerKind != "sast" || stored.FindingKind != "sast" || !strings.Contains(string(stored.CanonicalIdentityFields), "example.Handler.Serve") {
		t.Fatalf("stored SAST identity=%+v err=%v", stored, err)
	}
	if _, err := repository.GetIdentity(ctx, otherTenantID, cycleID, result.Identity.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant SAST identity read=%v", err)
	}

	provisionalPlan, err := matcher.Build(lineageuc.SASTFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", LegacyDedupKey: "cq:sast:broken",
		LegacySourceValidated: true, LegacyOwnershipValid: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	provisionalInput := provisionalPlan.Apply(lineageuc.CorrelateInput{
		TenantID: tenantID, CycleID: cycleID, SnapshotID: snapshotID,
		InputTrusted: true, OwnershipValidated: true, RedactionComplete: true,
		Observation: lineageuc.ObservationInput{
			SourceFindingID: fmt.Sprintf("sast-legacy-source-%d", suffix), Severity: shared.SeverityHigh,
			ScannerProvenance: findinglineage.ScannerProvenance{ToolName: "sast-matcher-test"}, ObservedAt: clock.now,
		},
		Actor: "integration-test",
	})
	provisional, err := service.Correlate(ctx, provisionalInput)
	if err != nil || provisional.Outcome != lineageuc.OutcomeReview || provisional.Identity == nil || provisional.Candidate == nil {
		t.Fatalf("provisional SAST result=%+v err=%v", provisional, err)
	}
	if _, err := repository.GetCandidate(ctx, tenantID, cycleID, provisional.Candidate.ID); err != nil {
		t.Fatalf("load provisional SAST candidate: %v", err)
	}
}

func TestPostgresQualityMatcherParityAndTenantIsolation(t *testing.T) {
	ctx, pool := setupTestDB(t)
	suffix := time.Now().UnixNano()
	tenantID := shared.ID(fmt.Sprintf("quality-lineage-tenant-%d", suffix))
	otherTenantID := shared.ID(fmt.Sprintf("quality-lineage-other-%d", suffix))
	cycleID, snapshotID := createFindingLineageSnapshot(t, ctx, pool, tenantID, fmt.Sprintf("quality-%d", suffix))
	ensureTestTenantAndEngagement(t, ctx, pool, otherTenantID, shared.ID(fmt.Sprintf("quality-lineage-other-assessment-%d", suffix)), "", "")
	clock := postgresLineageClock{now: time.Now().UTC().Truncate(time.Microsecond)}
	ids := &postgresLineageIDs{prefix: fmt.Sprintf("quality-%d", suffix)}
	service, err := lineageuc.NewService(NewFindingLineageRepository(pool), NewTenantTransactionRunner(pool), postgresLineageAudit{}, clock, ids, nil)
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := lineageuc.NewQualityMatcherV1([]lineageuc.QualityRuleProfileV1{{Primary: "quality:file-license", OneFindingPerFile: true}})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := matcher.Build(lineageuc.QualityFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", FindingClass: "quality", RepoPath: "src/app.go", RuleKey: "quality:file-license",
		Anchor: lineageuc.QualityAnchorV1{Kind: lineageuc.QualityAnchorFile, SchemaVersion: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := plan.Apply(lineageuc.CorrelateInput{
		TenantID: tenantID, CycleID: cycleID, SnapshotID: snapshotID,
		InputTrusted: true, OwnershipValidated: true, RedactionComplete: true,
		Observation: lineageuc.ObservationInput{
			SourceFindingID: fmt.Sprintf("quality-source-%d", suffix), Severity: shared.SeverityLow, Location: "src/app.go:42",
			ScannerProvenance: findinglineage.ScannerProvenance{ToolName: "quality-matcher-test"}, ObservedAt: clock.now,
		},
		Actor: "integration-test",
	})
	result, err := service.Correlate(ctx, input)
	if err != nil || result.Outcome != lineageuc.OutcomeCreated || result.Identity == nil {
		t.Fatalf("quality result=%+v err=%v", result, err)
	}
	repository := NewFindingLineageRepository(pool)
	stored, err := repository.GetIdentity(ctx, tenantID, cycleID, result.Identity.ID)
	if err != nil || stored.ProducerKind != "quality" || stored.FindingKind != "quality" || !strings.Contains(string(stored.CanonicalIdentityFields), `"scope": "file"`) {
		t.Fatalf("stored quality identity=%+v err=%v", stored, err)
	}
	if _, err := repository.GetIdentity(ctx, otherTenantID, cycleID, result.Identity.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant quality identity read=%v", err)
	}

	provisionalPlan, err := matcher.Build(lineageuc.QualityFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", FindingClass: "reliability", LegacyDedupKey: "cq:reliability:reliability-empty-catch:src/app.go:9",
		LegacySourceValidated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	provisionalInput := provisionalPlan.Apply(lineageuc.CorrelateInput{
		TenantID: tenantID, CycleID: cycleID, SnapshotID: snapshotID,
		InputTrusted: true, OwnershipValidated: true, RedactionComplete: true,
		Observation: lineageuc.ObservationInput{
			SourceFindingID: fmt.Sprintf("reliability-source-%d", suffix), Severity: shared.SeverityMedium,
			ScannerProvenance: findinglineage.ScannerProvenance{ToolName: "quality-matcher-test"}, ObservedAt: clock.now,
		},
		Actor: "integration-test",
	})
	provisional, err := service.Correlate(ctx, provisionalInput)
	if err != nil || provisional.Outcome != lineageuc.OutcomeReview || provisional.Identity == nil || provisional.Candidate == nil {
		t.Fatalf("provisional quality result=%+v err=%v", provisional, err)
	}
	if provisional.Identity.ProducerKind != "reliability" || provisional.Candidate.Reason != findinglineage.ReasonInsufficientAnchor {
		t.Fatalf("provisional quality identity=%+v candidate=%+v", provisional.Identity, provisional.Candidate)
	}
}

func TestPostgresSecretMatcherRedactionParityAndTenantIsolation(t *testing.T) {
	ctx, pool := setupTestDB(t)
	suffix := time.Now().UnixNano()
	tenantID := shared.ID(fmt.Sprintf("secret-lineage-tenant-%d", suffix))
	otherTenantID := shared.ID(fmt.Sprintf("secret-lineage-other-%d", suffix))
	cycleID, snapshotID := createFindingLineageSnapshot(t, ctx, pool, tenantID, fmt.Sprintf("secret-%d", suffix))
	ensureTestTenantAndEngagement(t, ctx, pool, otherTenantID, shared.ID(fmt.Sprintf("secret-lineage-other-assessment-%d", suffix)), "", "")
	clock := postgresLineageClock{now: time.Now().UTC().Truncate(time.Microsecond)}
	ids := &postgresLineageIDs{prefix: fmt.Sprintf("secret-%d", suffix)}
	service, err := lineageuc.NewService(NewFindingLineageRepository(pool), NewTenantTransactionRunner(pool), postgresLineageAudit{}, clock, ids, nil)
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := lineageuc.NewSecretMatcherV1(nil)
	if err != nil {
		t.Fatal(err)
	}
	sanitized, err := lineageuc.RedactSecretProducerInputV1(lineageuc.SecretProducerInputV1{
		TargetIdentityCanonical: "repo:example", DetectorKey: "aws-access-key-id", SecretClass: "aws_access_key", RepoPath: "config/app.env",
		Anchor: lineageuc.SecretAnchorV1{Kind: lineageuc.SecretAnchorEnvName, SchemaVersion: 1, ContainerName: "AWS_ACCESS_KEY_ID", ContainerApproved: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := matcher.Build(sanitized)
	if err != nil {
		t.Fatal(err)
	}
	input := plan.Apply(lineageuc.CorrelateInput{
		TenantID: tenantID, CycleID: cycleID, SnapshotID: snapshotID,
		InputTrusted: true, OwnershipValidated: true, RedactionComplete: true,
		Observation: lineageuc.ObservationInput{
			SourceFindingID: fmt.Sprintf("secret-source-%d", suffix), Severity: shared.SeverityCritical, Location: "config/app.env:42",
			ScannerProvenance: findinglineage.ScannerProvenance{ToolName: "secret-matcher-test"}, ObservedAt: clock.now,
		},
		Actor: "integration-test",
	})
	result, err := service.Correlate(ctx, input)
	if err != nil || result.Outcome != lineageuc.OutcomeCreated || result.Identity == nil {
		t.Fatalf("secret result=%+v err=%v", result, err)
	}
	repository := NewFindingLineageRepository(pool)
	stored, err := repository.GetIdentity(ctx, tenantID, cycleID, result.Identity.ID)
	if err != nil || stored.ProducerKind != "secret" || stored.FindingKind != "secret" || !strings.Contains(string(stored.CanonicalIdentityFields), "AWS_ACCESS_KEY_ID") {
		t.Fatalf("stored secret identity=%+v err=%v", stored, err)
	}
	if _, err := repository.GetIdentity(ctx, otherTenantID, cycleID, result.Identity.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant secret identity read=%v", err)
	}

	provisionalPlan, err := matcher.Build(lineageuc.SecretFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", SecretClass: "credential", LegacyDedupKey: "secret:generic-secret:config/app.env:9",
		LegacySourceValidated: true, RedactionComplete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	provisionalInput := provisionalPlan.Apply(lineageuc.CorrelateInput{
		TenantID: tenantID, CycleID: cycleID, SnapshotID: snapshotID,
		InputTrusted: true, OwnershipValidated: true, RedactionComplete: true,
		Observation: lineageuc.ObservationInput{
			SourceFindingID: fmt.Sprintf("secret-legacy-source-%d", suffix), Severity: shared.SeverityHigh,
			ScannerProvenance: findinglineage.ScannerProvenance{ToolName: "secret-matcher-test"}, ObservedAt: clock.now,
		},
		Actor: "integration-test",
	})
	provisional, err := service.Correlate(ctx, provisionalInput)
	if err != nil || provisional.Outcome != lineageuc.OutcomeReview || provisional.Identity == nil || provisional.Candidate == nil {
		t.Fatalf("provisional secret result=%+v err=%v", provisional, err)
	}
	if provisional.Candidate.Reason != findinglineage.ReasonInsufficientAnchor {
		t.Fatalf("provisional secret candidate=%+v", provisional.Candidate)
	}
}

func TestPostgresIaCMatcherAddressParityAndTenantIsolation(t *testing.T) {
	ctx, pool := setupTestDB(t)
	suffix := time.Now().UnixNano()
	tenantID := shared.ID(fmt.Sprintf("iac-lineage-tenant-%d", suffix))
	otherTenantID := shared.ID(fmt.Sprintf("iac-lineage-other-%d", suffix))
	cycleID, snapshotID := createFindingLineageSnapshot(t, ctx, pool, tenantID, fmt.Sprintf("iac-%d", suffix))
	ensureTestTenantAndEngagement(t, ctx, pool, otherTenantID, shared.ID(fmt.Sprintf("iac-lineage-other-assessment-%d", suffix)), "", "")
	clock := postgresLineageClock{now: time.Now().UTC().Truncate(time.Microsecond)}
	ids := &postgresLineageIDs{prefix: fmt.Sprintf("iac-%d", suffix)}
	service, err := lineageuc.NewService(NewFindingLineageRepository(pool), NewTenantTransactionRunner(pool), postgresLineageAudit{}, clock, ids, nil)
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := lineageuc.NewIaCMatcherV1(nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := matcher.Build(lineageuc.IaCFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", ConfigKind: lineageuc.IaCTerraform, RuleKey: "terraform-public-instance", RepoPath: "infra/main.tf",
		SemanticConfigAnchorDigest: strings.Repeat("a", 64), TerraformAddress: `module.network[0].aws_instance.web["blue"]`,
	})
	if err != nil {
		t.Fatal(err)
	}
	input := plan.Apply(lineageuc.CorrelateInput{
		TenantID: tenantID, CycleID: cycleID, SnapshotID: snapshotID,
		InputTrusted: true, OwnershipValidated: true, RedactionComplete: true,
		Observation: lineageuc.ObservationInput{
			SourceFindingID: fmt.Sprintf("iac-source-%d", suffix), Severity: shared.SeverityHigh, Location: "infra/main.tf:42",
			ScannerProvenance: findinglineage.ScannerProvenance{ToolName: "iac-matcher-test"}, ObservedAt: clock.now,
		},
		Actor: "integration-test",
	})
	result, err := service.Correlate(ctx, input)
	if err != nil || result.Outcome != lineageuc.OutcomeCreated || result.Identity == nil {
		t.Fatalf("IaC result=%+v err=%v", result, err)
	}
	repository := NewFindingLineageRepository(pool)
	stored, err := repository.GetIdentity(ctx, tenantID, cycleID, result.Identity.ID)
	if err != nil || stored.ProducerKind != "iac" || stored.FindingKind != "misconfig" || !strings.Contains(string(stored.CanonicalIdentityFields), `aws_instance.web[\"blue\"]`) {
		t.Fatalf("stored IaC identity=%+v err=%v", stored, err)
	}
	if _, err := repository.GetIdentity(ctx, otherTenantID, cycleID, result.Identity.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant IaC identity read=%v", err)
	}

	provisionalPlan, err := matcher.Build(lineageuc.IaCFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", ConfigKind: lineageuc.IaCKubernetes, RuleKey: "kubernetes-privileged", RepoPath: "deploy/app.yaml",
		SemanticConfigAnchorDigest: strings.Repeat("b", 64), KubernetesAPIVersion: "apps/v1", KubernetesKind: "Deployment", KubernetesName: "api",
	})
	if err != nil {
		t.Fatal(err)
	}
	provisionalInput := provisionalPlan.Apply(lineageuc.CorrelateInput{
		TenantID: tenantID, CycleID: cycleID, SnapshotID: snapshotID,
		InputTrusted: true, OwnershipValidated: true, RedactionComplete: true,
		Observation: lineageuc.ObservationInput{
			SourceFindingID: fmt.Sprintf("iac-kubernetes-source-%d", suffix), Severity: shared.SeverityHigh,
			ScannerProvenance: findinglineage.ScannerProvenance{ToolName: "iac-matcher-test"}, ObservedAt: clock.now,
		},
		Actor: "integration-test",
	})
	provisional, err := service.Correlate(ctx, provisionalInput)
	if err != nil || provisional.Outcome != lineageuc.OutcomeReview || provisional.Identity == nil || provisional.Candidate == nil {
		t.Fatalf("provisional IaC result=%+v err=%v", provisional, err)
	}
	if provisional.Candidate.Reason != findinglineage.ReasonInsufficientAnchor {
		t.Fatalf("provisional IaC candidate=%+v", provisional.Candidate)
	}
}

func TestPostgresManualLineageWorkflowParityAndTenantIsolation(t *testing.T) {
	ctx, pool := setupTestDB(t)
	suffix := time.Now().UnixNano()
	tenantID := shared.ID(fmt.Sprintf("manual-lineage-tenant-%d", suffix))
	otherTenantID := shared.ID(fmt.Sprintf("manual-lineage-other-%d", suffix))
	cycleID, snapshotID := createFindingLineageSnapshot(t, ctx, pool, tenantID, fmt.Sprintf("manual-%d", suffix))
	ensureTestTenantAndEngagement(t, ctx, pool, otherTenantID, shared.ID(fmt.Sprintf("manual-lineage-other-assessment-%d", suffix)), "", "")
	clock := postgresLineageClock{now: time.Now().UTC().Truncate(time.Microsecond)}
	ids := &postgresLineageIDs{prefix: fmt.Sprintf("manual-%d", suffix)}
	repository := NewFindingLineageRepository(pool)
	service, err := lineageuc.NewService(repository, NewTenantTransactionRunner(pool), postgresLineageAudit{}, clock, ids, nil)
	if err != nil {
		t.Fatal(err)
	}
	assessmentA := shared.ID(fmt.Sprintf("manual-assessment-a-%d", suffix))
	assessmentB := shared.ID(fmt.Sprintf("manual-assessment-b-%d", suffix))
	identityA := shared.ID(fmt.Sprintf("manual-identity-a-%d", suffix))
	first, err := service.CorrelateNativeManual(ctx, lineageuc.NativeManualInput{
		TenantID: tenantID, CycleID: cycleID, SnapshotID: snapshotID, AssessmentID: assessmentA, IdentityID: identityA,
		FindingClass: lineageuc.ManualFindingOffensive,
		Observation: lineageuc.ObservationInput{
			ID: shared.ID(fmt.Sprintf("manual-observation-a1-%d", suffix)), SourceFindingID: fmt.Sprintf("manual-source-a1-%d", suffix),
			Severity: shared.SeverityHigh, Location: "endpoint:/admin", ScannerProvenance: findinglineage.ScannerProvenance{ToolName: "manual-workflow-test"}, ObservedAt: clock.now,
		},
		Actor: "analyst-a",
	})
	if err != nil || first.Outcome != lineageuc.OutcomeCreated || first.Identity == nil || first.Identity.ID != identityA {
		t.Fatalf("first native manual result=%+v err=%v", first, err)
	}
	second, err := service.CorrelateNativeManual(ctx, lineageuc.NativeManualInput{
		TenantID: tenantID, CycleID: cycleID, SnapshotID: snapshotID, AssessmentID: assessmentA, IdentityID: identityA,
		FindingClass: lineageuc.ManualFindingOffensive,
		Observation: lineageuc.ObservationInput{
			ID: shared.ID(fmt.Sprintf("manual-observation-a2-%d", suffix)), SourceFindingID: fmt.Sprintf("manual-source-a2-%d", suffix),
			Severity: shared.SeverityLow, Location: "endpoint:/renamed", ScannerProvenance: findinglineage.ScannerProvenance{ToolName: "manual-workflow-test"}, ObservedAt: clock.now,
		},
		Actor: "analyst-a",
	})
	if err != nil || second.Outcome != lineageuc.OutcomeMatched || second.Identity == nil || second.Identity.ID != identityA {
		t.Fatalf("same-Assessment native reuse=%+v err=%v", second, err)
	}
	if _, err := service.CorrelateNativeManual(ctx, lineageuc.NativeManualInput{
		TenantID: tenantID, CycleID: cycleID, SnapshotID: snapshotID, AssessmentID: assessmentB, IdentityID: identityA,
		FindingClass: lineageuc.ManualFindingOffensive,
		Observation: lineageuc.ObservationInput{
			SourceFindingID: fmt.Sprintf("manual-source-conflict-%d", suffix), Severity: shared.SeverityHigh,
			ScannerProvenance: findinglineage.ScannerProvenance{ToolName: "manual-workflow-test"}, ObservedAt: clock.now,
		},
		Actor: "analyst-b",
	}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("cross-Assessment explicit identity reuse error=%v", err)
	}
	source, err := service.CorrelateNativeManual(ctx, lineageuc.NativeManualInput{
		TenantID: tenantID, CycleID: cycleID, SnapshotID: snapshotID, AssessmentID: assessmentB,
		IdentityID: shared.ID(fmt.Sprintf("manual-identity-b-%d", suffix)), FindingClass: lineageuc.ManualFindingOffensive,
		Observation: lineageuc.ObservationInput{
			ID: shared.ID(fmt.Sprintf("manual-observation-b-%d", suffix)), SourceFindingID: fmt.Sprintf("manual-source-b-%d", suffix),
			Severity: shared.SeverityHigh, Location: "endpoint:/admin-v2", ScannerProvenance: findinglineage.ScannerProvenance{ToolName: "manual-workflow-test"}, ObservedAt: clock.now,
		},
		Actor: "analyst-b",
	})
	if err != nil || source.Observation == nil || source.Identity == nil {
		t.Fatalf("cross-Assessment source=%+v err=%v", source, err)
	}
	if _, err := repository.GetIdentity(ctx, otherTenantID, cycleID, identityA); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant native identity read=%v", err)
	}

	importPlan, err := lineageuc.BuildManualImportMatchPlanV1(lineageuc.ManualImportFingerprintInputV1{
		TargetIdentityCanonical: "project:example", AssessmentID: assessmentA, FindingClass: lineageuc.ManualFindingNative,
		ImporterNamespace: "csv-import", ImporterSchemaVersion: 1, ExternalStableID: fmt.Sprintf("row-%d", suffix),
		SourceValidated: true, RedactionComplete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	importInput := importPlan.Apply(lineageuc.CorrelateInput{
		TenantID: tenantID, CycleID: cycleID, SnapshotID: snapshotID,
		InputTrusted: true, OwnershipValidated: true, RedactionComplete: true,
		Observation: lineageuc.ObservationInput{
			ID: shared.ID(fmt.Sprintf("manual-import-observation-%d", suffix)), SourceFindingID: fmt.Sprintf("manual-import-source-%d", suffix),
			Severity: shared.SeverityHigh, Location: "endpoint:/imported", ScannerProvenance: findinglineage.ScannerProvenance{ToolName: "manual-import-test"}, ObservedAt: clock.now,
		},
		Actor: "importer",
	})
	imported, err := service.Correlate(ctx, importInput)
	if err != nil || imported.Outcome != lineageuc.OutcomeReview || imported.Identity == nil || imported.Candidate == nil {
		t.Fatalf("import candidate=%+v err=%v", imported, err)
	}
	replay := importInput
	replay.Observation.Location = "endpoint:/different-body"
	if _, err := service.Correlate(ctx, replay); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("same-key different-body import replay error=%v", err)
	}
	if _, err := repository.GetCandidate(ctx, otherTenantID, cycleID, imported.Candidate.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant manual candidate read=%v", err)
	}

	linkInput := lineageuc.ConfirmManualCrossAssessmentLinkInput{
		TenantID: tenantID, CycleID: cycleID, EventID: shared.ID(fmt.Sprintf("manual-link-%d", suffix)),
		SourceObservationID: source.Observation.ID, TargetIdentityID: identityA,
		Actor: "reviewer", Role: userdom.RoleReviewer, Reason: "same verified offensive issue", IfMatchProvided: true, ExpectedVersion: 0,
	}
	event, applied, err := service.ConfirmManualCrossAssessmentLink(ctx, linkInput)
	if err != nil || !applied || event.Action != findinglineage.OverrideConfirm || event.Version != 1 {
		t.Fatalf("manual link event=%+v applied=%v err=%v", event, applied, err)
	}
	replayed, applied, err := service.ConfirmManualCrossAssessmentLink(ctx, linkInput)
	if err != nil || applied || replayed.ID != event.ID {
		t.Fatalf("manual link replay=%+v applied=%v err=%v", replayed, applied, err)
	}
	if _, err := repository.GetActiveOverride(ctx, otherTenantID, cycleID, source.Observation.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant manual override read=%v", err)
	}
}

func createFindingLineageSnapshot(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID shared.ID, suffix string) (shared.ID, shared.ID) {
	t.Helper()
	assessmentID := shared.ID("lineage-assessment-" + suffix)
	cycleID := shared.ID("lineage-cycle-" + suffix)
	runID := shared.ID("lineage-run-" + suffix)
	snapshotID := shared.ID("lineage-snapshot-" + suffix)
	ensureTestTenantAndEngagement(t, ctx, pool, tenantID, assessmentID, "", "")
	now := time.Now().UTC()
	cycle, err := assessmentcycle.NewAssessmentCycle(cycleID, tenantID, "Lineage cycle", assessmentcycle.BoundaryStandalone, "", "", assessmentID, "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	member, err := assessmentcycle.NewInitialMember(tenantID, cycleID, assessmentID, "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	cycleRepository := NewAssessmentCycleRepository(pool)
	if err := cycleRepository.CreateCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	if err := cycleRepository.CreateMember(ctx, member); err != nil {
		t.Fatal(err)
	}
	run := postgresNativeRun(t, tenantID, assessmentID, runID, strings.Repeat("a", 64))
	runRepository := NewScanRunStore(pool)
	sealPostgresNativeRun(t, ctx, runRepository, &run, now)
	snapshot := postgresAssessmentSnapshot(t, tenantID, cycleID, assessmentID, snapshotID.String(), "lineage-request-"+suffix, run)
	stored, created, err := NewAssessmentSnapshotRepository(pool).CreateFinalizedCAS(ctx, snapshot, 0)
	if err != nil || !created {
		t.Fatalf("create lineage snapshot=%+v created=%v err=%v", stored, created, err)
	}
	return cycleID, stored.ID
}

func postgresFindingLineagePair(t *testing.T, tenantID, cycleID, snapshotID shared.ID, identityID, observationID, sourceID, rule string, now time.Time) (findinglineage.Identity, findinglineage.Observation) {
	t.Helper()
	fingerprint, err := findinglineage.CanonicalizeFingerprintV1(findinglineage.FingerprintCanonicalInputV1{
		CanonicalizationVersion: 1, ProducerKind: "sca", TargetIdentitySchemaVersion: 1,
		TargetIdentityCanonical: "repo:example", IdentityFields: map[string]findinglineage.CanonicalValue{"rule_id": findinglineage.Text(rule)},
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := findinglineage.Identity{
		TenantID: tenantID, CycleID: cycleID, ID: shared.ID(identityID), ProducerKind: "sca", FindingKind: "vulnerability",
		CanonicalizationVersion: 1, FingerprintSchemaVersion: 1, LineageFingerprint: fingerprint.Fingerprint,
		TargetIdentitySchemaVersion: 1, TargetIdentityCanonical: "repo:example", CanonicalIdentityFields: fingerprint.IdentityFields,
		FirstSeenSnapshotID: snapshotID, CreatedAt: now,
	}
	observation := findinglineage.Observation{
		TenantID: tenantID, CycleID: cycleID, ID: shared.ID(observationID), SnapshotID: snapshotID, IdentityID: identity.ID,
		ProducerKind: "sca", FindingKind: "vulnerability", TargetCanonical: "repo:example", SourceFindingID: sourceID,
		Severity: shared.SeverityHigh, ScannerProvenance: findinglineage.ScannerProvenance{ToolName: "scanner"}, ObservedAt: now,
	}
	return identity, observation
}

type postgresLineageClock struct{ now time.Time }

func (clock postgresLineageClock) Now() time.Time { return clock.now }

type postgresLineageIDs struct {
	prefix string
	next   int
}

func (ids *postgresLineageIDs) NewID() shared.ID {
	ids.next++
	return shared.ID(fmt.Sprintf("%s-%d", ids.prefix, ids.next))
}

type postgresLineageAudit struct{}

func (postgresLineageAudit) Record(context.Context, ports.AuditEntry) error { return nil }
