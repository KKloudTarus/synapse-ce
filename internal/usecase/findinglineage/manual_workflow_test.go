package findinglineage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

func TestNativeManualExplicitIdentityReuseAndCrossAssessmentIsolation(t *testing.T) {
	repository := memory.NewFindingLineageRepository()
	clock := fixedClock{now: time.Date(2026, 9, 1, 16, 0, 0, 0, time.UTC)}
	service, err := NewService(repository, immediateTransactions{}, &collectingAudit{}, clock, &sequenceIDs{}, &collectingObserver{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.CorrelateNativeManual(context.Background(), NativeManualInput{
		TenantID: "tenant", CycleID: "cycle", SnapshotID: "snapshot-a1", AssessmentID: "assessment-a", IdentityID: "manual-identity",
		FindingClass: ManualFindingNative, Observation: manualObservation("manual-observation-a1", "native-finding-a1", shared.SeverityHigh, "endpoint:/admin"), Actor: "analyst",
	})
	if err != nil || first.Outcome != OutcomeCreated || first.Identity == nil || first.Identity.ID != "manual-identity" || first.Observation == nil {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	second, err := service.CorrelateNativeManual(context.Background(), NativeManualInput{
		TenantID: "tenant", CycleID: "cycle", SnapshotID: "snapshot-a2", AssessmentID: "assessment-a", IdentityID: "manual-identity",
		FindingClass: ManualFindingNative, Observation: manualObservation("manual-observation-a2", "native-finding-a2", shared.SeverityLow, "endpoint:/renamed"), Actor: "analyst",
	})
	if err != nil || second.Outcome != OutcomeMatched || second.Identity == nil || second.Identity.ID != first.Identity.ID {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	if _, err := service.CorrelateNativeManual(context.Background(), NativeManualInput{
		TenantID: "tenant", CycleID: "cycle", SnapshotID: "snapshot-b1", AssessmentID: "assessment-b", IdentityID: "manual-identity",
		FindingClass: ManualFindingNative, Observation: manualObservation("manual-observation-b1", "native-finding-b1", shared.SeverityHigh, "endpoint:/admin"), Actor: "analyst",
	}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("cross-assessment explicit identity reuse error=%v", err)
	}
	observations, err := repository.ListObservationsBySnapshot(context.Background(), "tenant", "cycle", "snapshot-a2")
	if err != nil || len(observations) != 1 || observations[0].IdentityID != "manual-identity" {
		t.Fatalf("snapshot observations=%+v err=%v", observations, err)
	}
	if strings.Contains(string(first.Identity.CanonicalIdentityFields), "endpoint:/admin") || strings.Contains(string(second.Identity.CanonicalIdentityFields), "endpoint:/renamed") {
		t.Fatal("manual endpoint observation leaked into identity")
	}
}

func TestManualImportGoldenScopingCandidateAndReplayConflict(t *testing.T) {
	firstPlan, err := BuildManualImportMatchPlanV1(ManualImportFingerprintInputV1{
		TargetIdentityCanonical: "project:example", AssessmentID: "assessment-a", FindingClass: ManualFindingOffensive,
		ImporterNamespace: "burp-enterprise", ImporterSchemaVersion: 2, ExternalStableID: "issue-123", SourceValidated: true, RedactionComplete: true,
	})
	if err != nil || !firstPlan.ProvisionalIdentity || firstPlan.ReasonCode != "imported_identity_requires_review" {
		t.Fatalf("first plan=%+v err=%v", firstPlan, err)
	}
	fingerprint, err := domain.CanonicalizeFingerprintV1(firstPlan.FingerprintInput)
	if err != nil {
		t.Fatal(err)
	}
	const wantFingerprint = "25795765d908c19d15e7d05b662c4919858af7a9936dcf97d11176f9cd347ce5"
	if fingerprint.Fingerprint != wantFingerprint {
		t.Fatalf("fingerprint=%s want=%s canonical=%s", fingerprint.Fingerprint, wantFingerprint, fingerprint.Bytes)
	}
	secondAssessment, err := BuildManualImportMatchPlanV1(ManualImportFingerprintInputV1{
		TargetIdentityCanonical: "project:example", AssessmentID: "assessment-b", FindingClass: ManualFindingOffensive,
		ImporterNamespace: "burp-enterprise", ImporterSchemaVersion: 2, ExternalStableID: "issue-123", SourceValidated: true, RedactionComplete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondFingerprint, _ := domain.CanonicalizeFingerprintV1(secondAssessment.FingerprintInput)
	if secondFingerprint.Fingerprint == fingerprint.Fingerprint {
		t.Fatal("imported stable ID crossed Assessment scope")
	}
	missingID, err := BuildManualImportMatchPlanV1(ManualImportFingerprintInputV1{
		TargetIdentityCanonical: "project:example", AssessmentID: "assessment-a", FindingClass: ManualFindingNative,
		ImporterNamespace: "csv-import", ImporterSchemaVersion: 1, SourceValidated: true, RedactionComplete: true,
	})
	if err != nil || missingID.ReviewReason != domain.ReasonInsufficientAnchor || missingID.ReasonCode != "missing_external_stable_id" {
		t.Fatalf("missing id=%+v err=%v", missingID, err)
	}

	repository := memory.NewFindingLineageRepository()
	clock := fixedClock{now: time.Date(2026, 9, 1, 17, 0, 0, 0, time.UTC)}
	observer := &collectingObserver{}
	service, err := NewService(repository, immediateTransactions{}, &collectingAudit{}, clock, &sequenceIDs{}, observer)
	if err != nil {
		t.Fatal(err)
	}
	input := firstPlan.Apply(correlateInput("manual-import", "unused"))
	input.TenantID, input.CycleID, input.SnapshotID = "tenant", "cycle", "snapshot-import"
	input.Observation.ID = "import-observation"
	input.Observation.SourceFindingID = "import-source"
	input.Observation.Location = "endpoint:/old-title-is-not-identity"
	input.Observation.Severity = shared.SeverityHigh
	result, err := service.Correlate(context.Background(), input)
	if err != nil || result.Outcome != OutcomeReview || result.Identity == nil || result.Candidate == nil {
		t.Fatalf("import result=%+v err=%v", result, err)
	}
	replay := input
	replay.Observation.Severity = shared.SeverityLow
	replay.Observation.Location = "endpoint:/different-body"
	if _, err := service.Correlate(context.Background(), replay); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("same-key different-body replay error=%v", err)
	}
	if strings.Contains(string(result.Identity.CanonicalIdentityFields), input.Observation.Location) {
		t.Fatalf("imported title/endpoint leaked into identity: %s", result.Identity.CanonicalIdentityFields)
	}

	redactionPlan, err := BuildManualImportMatchPlanV1(ManualImportFingerprintInputV1{
		TargetIdentityCanonical: "project:example", AssessmentID: "assessment-a", FindingClass: ManualFindingNative,
		ImporterNamespace: "csv-import", ImporterSchemaVersion: 1, ExternalStableID: "row-1", SourceValidated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	redactionResult, err := service.Correlate(context.Background(), redactionPlan.Apply(correlateInput("manual-import-redaction", "unused")))
	if err != nil || redactionResult.Outcome != OutcomeSkipped || redactionResult.Skip == nil || redactionResult.Skip.Reason != domain.SkipRedactionRequired {
		t.Fatalf("redaction result=%+v err=%v", redactionResult, err)
	}
	if len(observer.outcomes) != 2 {
		t.Fatalf("metrics=%+v", observer.outcomes)
	}
}

func TestManualCrossAssessmentLinkRequiresReviewIfMatchAndIsIdempotent(t *testing.T) {
	repository := memory.NewFindingLineageRepository()
	clock := fixedClock{now: time.Date(2026, 9, 1, 18, 0, 0, 0, time.UTC)}
	service, err := NewService(repository, immediateTransactions{}, &collectingAudit{}, clock, &sequenceIDs{}, &collectingObserver{})
	if err != nil {
		t.Fatal(err)
	}
	source, err := service.CorrelateNativeManual(context.Background(), NativeManualInput{
		TenantID: "tenant", CycleID: "cycle", SnapshotID: "snapshot-b", AssessmentID: "assessment-b", IdentityID: "manual-b",
		FindingClass: ManualFindingOffensive, Observation: manualObservation("observation-b", "finding-b", shared.SeverityHigh, "endpoint:/b"), Actor: "analyst-b",
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := service.CorrelateNativeManual(context.Background(), NativeManualInput{
		TenantID: "tenant", CycleID: "cycle", SnapshotID: "snapshot-a", AssessmentID: "assessment-a", IdentityID: "manual-a",
		FindingClass: ManualFindingOffensive, Observation: manualObservation("observation-a", "finding-a", shared.SeverityHigh, "endpoint:/a"), Actor: "analyst-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	base := ConfirmManualCrossAssessmentLinkInput{
		TenantID: "tenant", CycleID: "cycle", EventID: "manual-link-event", SourceObservationID: source.Observation.ID,
		TargetIdentityID: target.Identity.ID, Actor: "reviewer", Role: userdom.RoleReviewer, Reason: "same verified offensive issue",
		IfMatchProvided: true, ExpectedVersion: 0,
	}
	denied := base
	denied.Role = userdom.RoleConsultant
	if _, _, err := service.ConfirmManualCrossAssessmentLink(context.Background(), denied); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("consultant link error=%v", err)
	}
	missingIfMatch := base
	missingIfMatch.IfMatchProvided = false
	if _, _, err := service.ConfirmManualCrossAssessmentLink(context.Background(), missingIfMatch); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing If-Match error=%v", err)
	}
	event, applied, err := service.ConfirmManualCrossAssessmentLink(context.Background(), base)
	if err != nil || !applied || event.Action != domain.OverrideConfirm || event.Version != 1 {
		t.Fatalf("event=%+v applied=%v err=%v", event, applied, err)
	}
	replayed, applied, err := service.ConfirmManualCrossAssessmentLink(context.Background(), base)
	if err != nil || applied || replayed.ID != event.ID {
		t.Fatalf("replay=%+v applied=%v err=%v", replayed, applied, err)
	}
	changedBody := base
	changedBody.Reason = "different reason"
	if _, _, err := service.ConfirmManualCrossAssessmentLink(context.Background(), changedBody); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("same event different body error=%v", err)
	}
	stale := base
	stale.EventID = "manual-link-stale"
	if _, _, err := service.ConfirmManualCrossAssessmentLink(context.Background(), stale); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale If-Match error=%v", err)
	}
	events, err := repository.ListOverrideEvents(context.Background(), "tenant", "cycle", source.Observation.ID)
	if err != nil || len(events) != 1 || events[0].ID != event.ID {
		t.Fatalf("events=%+v err=%v", events, err)
	}
}

func manualObservation(id, source string, severity shared.Severity, location string) ObservationInput {
	return ObservationInput{
		ID: shared.ID(id), SourceFindingID: source, Severity: severity, Location: location,
		ScannerProvenance: domain.ScannerProvenance{ToolName: "native-manual"},
	}
}
