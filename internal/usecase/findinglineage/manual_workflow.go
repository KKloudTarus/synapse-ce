package findinglineage

import (
	"context"
	"errors"
	"fmt"
	"strings"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

const (
	ManualNativeFingerprintSchemaVersionV1 = 1
	ManualImportFingerprintSchemaVersionV1 = 1
	ManualTargetIdentitySchemaVersionV1    = 1
)

type ManualFindingClass string

const (
	ManualFindingNative    ManualFindingClass = "manual"
	ManualFindingOffensive ManualFindingClass = "offensive"
)

func (class ManualFindingClass) Valid() bool {
	return class == ManualFindingNative || class == ManualFindingOffensive
}

type NativeManualInput struct {
	TenantID     shared.ID
	CycleID      shared.ID
	SnapshotID   shared.ID
	AssessmentID shared.ID
	IdentityID   shared.ID
	FindingClass ManualFindingClass
	Observation  ObservationInput
	Actor        string
}

func (service *Service) CorrelateNativeManual(ctx context.Context, input NativeManualInput) (Result, error) {
	input.TenantID = shared.TenantOrDefault(input.TenantID)
	if input.TenantID.IsZero() || input.CycleID.IsZero() || input.SnapshotID.IsZero() || input.AssessmentID.IsZero() || !input.FindingClass.Valid() || strings.TrimSpace(input.Actor) == "" {
		return Result{}, fmt.Errorf("%w: native manual lineage ownership and class are required", shared.ErrValidation)
	}
	if input.IdentityID.IsZero() {
		input.IdentityID = service.ids.NewID()
	}
	target := "assessment:" + input.AssessmentID.String()
	fingerprintInput := domain.FingerprintCanonicalInputV1{
		CanonicalizationVersion: domain.CanonicalizationVersionV1, ProducerKind: "manual_native",
		TargetIdentitySchemaVersion: ManualTargetIdentitySchemaVersionV1, TargetIdentityCanonical: target,
		IdentityFields: map[string]domain.CanonicalValue{
			"assessment_id":        domain.Text(input.AssessmentID.String()),
			"explicit_identity_id": domain.Text(input.IdentityID.String()),
			"finding_class":        domain.Text(string(input.FindingClass)),
			"identity_schema":      domain.Integer(1),
		},
	}
	fingerprint, err := domain.CanonicalizeFingerprintV1(fingerprintInput)
	if err != nil {
		return Result{}, err
	}
	if existing, getErr := service.repository.GetIdentity(ctx, input.TenantID, input.CycleID, input.IdentityID); getErr == nil {
		if existing.ProducerKind != "manual_native" || existing.FindingKind != string(input.FindingClass) || existing.TargetIdentityCanonical != target || existing.LineageFingerprint != fingerprint.Fingerprint {
			return Result{}, fmt.Errorf("%w: explicit native identity cannot be reused across Assessments or finding classes", shared.ErrConflict)
		}
	} else if getErr != nil && !errors.Is(getErr, shared.ErrNotFound) {
		return Result{}, getErr
	}
	matches, err := service.repository.FindIdentitiesByFingerprint(ctx, input.TenantID, input.CycleID, "manual_native", string(input.FindingClass), ManualNativeFingerprintSchemaVersionV1, target, fingerprint.Fingerprint)
	if err != nil {
		return Result{}, err
	}
	for _, match := range matches {
		if match.ID != input.IdentityID {
			return Result{}, fmt.Errorf("%w: native manual fingerprint already belongs to another explicit identity", shared.ErrConflict)
		}
	}
	if input.Observation.SourceFindingID == "" && input.Observation.SourceOccurrenceID == "" {
		input.Observation.SourceFindingID = input.IdentityID.String()
	}
	if strings.TrimSpace(input.Observation.ScannerProvenance.ToolName) == "" {
		input.Observation.ScannerProvenance.ToolName = "native-manual"
	}
	return service.Correlate(ctx, CorrelateInput{
		TenantID: input.TenantID, CycleID: input.CycleID, SnapshotID: input.SnapshotID, IdentityID: input.IdentityID,
		ProducerKind: "manual_native", FindingKind: string(input.FindingClass), FingerprintSchemaVersion: ManualNativeFingerprintSchemaVersionV1,
		FingerprintInput: fingerprintInput, InputTrusted: true, OwnershipValidated: true, RedactionComplete: true,
		Observation: input.Observation, Actor: input.Actor,
	})
}

type ManualImportFingerprintInputV1 struct {
	TargetIdentityCanonical string
	AssessmentID            shared.ID
	FindingClass            ManualFindingClass
	ImporterNamespace       string
	ImporterSchemaVersion   int
	ExternalStableID        string
	SourceValidated         bool
	RedactionComplete       bool
}

type ManualImportMatchPlanV1 struct {
	FingerprintInput    domain.FingerprintCanonicalInputV1
	FindingClass        ManualFindingClass
	ReasonCode          string
	ReviewReason        domain.CandidateReason
	ProvisionalIdentity bool
	SkipInput           bool
	SkipRedaction       bool
}

func BuildManualImportMatchPlanV1(input ManualImportFingerprintInputV1) (ManualImportMatchPlanV1, error) {
	if input.AssessmentID.IsZero() || !input.FindingClass.Valid() || input.ImporterSchemaVersion <= 0 {
		return ManualImportMatchPlanV1{}, fmt.Errorf("%w: manual import ownership, class, and schema are required", shared.ErrValidation)
	}
	target, err := normalizeSourceText("manual import", "target identity", input.TargetIdentityCanonical, 2048, false)
	if err != nil {
		return ManualImportMatchPlanV1{}, err
	}
	namespace, err := normalizeSourceText("manual import", "importer namespace", input.ImporterNamespace, 256, true)
	if err != nil {
		return ManualImportMatchPlanV1{}, err
	}
	fields := map[string]domain.CanonicalValue{
		"assessment_id":           domain.Text(input.AssessmentID.String()),
		"finding_class":           domain.Text(string(input.FindingClass)),
		"importer_namespace":      domain.Text(namespace),
		"importer_schema_version": domain.Integer(int64(input.ImporterSchemaVersion)),
	}
	externalID := strings.TrimSpace(input.ExternalStableID)
	if externalID != "" {
		externalID, err = normalizeSourceText("manual import", "external stable id", externalID, 512, false)
		if err != nil {
			return ManualImportMatchPlanV1{}, err
		}
		fields["external_stable_id"] = domain.Text(externalID)
	}
	plan := ManualImportMatchPlanV1{
		FingerprintInput: domain.FingerprintCanonicalInputV1{
			CanonicalizationVersion: domain.CanonicalizationVersionV1, ProducerKind: "manual_import",
			TargetIdentitySchemaVersion: ManualTargetIdentitySchemaVersionV1, TargetIdentityCanonical: target, IdentityFields: fields,
		},
		FindingClass: input.FindingClass, ReviewReason: domain.ReasonLegacyAmbiguous, ProvisionalIdentity: true, ReasonCode: "imported_identity_requires_review",
	}
	switch {
	case !input.RedactionComplete:
		plan.SkipRedaction, plan.ReasonCode = true, "redaction_not_complete"
	case !input.SourceValidated:
		plan.SkipInput, plan.ReasonCode = true, "import_source_not_validated"
	case externalID == "":
		plan.ReviewReason, plan.ReasonCode = domain.ReasonInsufficientAnchor, "missing_external_stable_id"
	}
	return plan, nil
}

func (plan ManualImportMatchPlanV1) Apply(input CorrelateInput) CorrelateInput {
	input.ProducerKind = "manual_import"
	input.FindingKind = string(plan.FindingClass)
	input.FingerprintSchemaVersion = ManualImportFingerprintSchemaVersionV1
	input.FingerprintInput = plan.FingerprintInput
	input.ReviewReason = plan.ReviewReason
	input.ReviewDetailCode = plan.ReasonCode
	input.ProvisionalIdentity = plan.ProvisionalIdentity
	if plan.SkipInput {
		input.InputTrusted = false
	}
	if plan.SkipRedaction {
		input.RedactionComplete = false
	}
	return input
}

type ConfirmManualCrossAssessmentLinkInput struct {
	TenantID            shared.ID
	CycleID             shared.ID
	EventID             shared.ID
	SourceObservationID shared.ID
	TargetIdentityID    shared.ID
	TargetObservationID shared.ID
	Actor               string
	Role                userdom.Role
	Reason              string
	IfMatchProvided     bool
	ExpectedVersion     int64
	PriorEventID        shared.ID
}

func (service *Service) ConfirmManualCrossAssessmentLink(ctx context.Context, input ConfirmManualCrossAssessmentLinkInput) (domain.OverrideEvent, bool, error) {
	input.TenantID = shared.TenantOrDefault(input.TenantID)
	if !input.Role.Can(userdom.PermReview) {
		return domain.OverrideEvent{}, false, shared.ErrForbidden
	}
	if input.EventID.IsZero() || input.SourceObservationID.IsZero() || input.TargetIdentityID.IsZero() || strings.TrimSpace(input.Actor) == "" || strings.TrimSpace(input.Reason) == "" || !input.IfMatchProvided || input.ExpectedVersion < 0 {
		return domain.OverrideEvent{}, false, fmt.Errorf("%w: review event, references, reason, and If-Match are required", shared.ErrValidation)
	}
	sourceObservation, err := service.repository.GetObservation(ctx, input.TenantID, input.CycleID, input.SourceObservationID)
	if err != nil {
		return domain.OverrideEvent{}, false, err
	}
	sourceIdentity, err := service.repository.GetIdentity(ctx, input.TenantID, input.CycleID, sourceObservation.IdentityID)
	if err != nil {
		return domain.OverrideEvent{}, false, err
	}
	targetIdentity, err := service.repository.GetIdentity(ctx, input.TenantID, input.CycleID, input.TargetIdentityID)
	if err != nil {
		return domain.OverrideEvent{}, false, err
	}
	if !nativeManualIdentity(sourceIdentity) || !nativeManualIdentity(targetIdentity) || sourceIdentity.ID == targetIdentity.ID {
		return domain.OverrideEvent{}, false, fmt.Errorf("%w: cross-Assessment manual link requires two native manual/offensive identities", shared.ErrValidation)
	}
	if sourceIdentity.TargetIdentityCanonical == targetIdentity.TargetIdentityCanonical {
		return domain.OverrideEvent{}, false, fmt.Errorf("%w: identities already belong to the same Assessment", shared.ErrValidation)
	}
	return service.AppendOverride(ctx, OverrideInput{
		TenantID: input.TenantID, CycleID: input.CycleID, EventID: input.EventID, Action: domain.OverrideConfirm,
		SourceObservationID: input.SourceObservationID, SourceIdentityID: sourceIdentity.ID,
		TargetObservationID: input.TargetObservationID, TargetIdentityID: input.TargetIdentityID,
		Actor: input.Actor, Reason: input.Reason, ExpectedVersion: input.ExpectedVersion, PriorEventID: input.PriorEventID,
	})
}

func nativeManualIdentity(identity domain.Identity) bool {
	return identity.ProducerKind == "manual_native" && (identity.FindingKind == string(ManualFindingNative) || identity.FindingKind == string(ManualFindingOffensive))
}
