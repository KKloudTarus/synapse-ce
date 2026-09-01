package findinglineage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type Outcome string

const (
	OutcomeMatched Outcome = "matched"
	OutcomeCreated Outcome = "created"
	OutcomeReview  Outcome = "needs_review"
	OutcomeSkipped Outcome = "skipped"
)

type ObservationInput struct {
	ID                 shared.ID
	SourceFindingID    string
	SourceOccurrenceID string
	Severity           shared.Severity
	RiskScoreMilli     *int
	ComponentVersion   string
	Location           string
	Reachability       string
	EvidenceDigest     string
	ScannerProvenance  domain.ScannerProvenance
	ObservedAt         time.Time
}

type AliasInput struct {
	SchemaVersion int
	Value         string
}

type CorrelateInput struct {
	TenantID                    shared.ID
	CycleID                     shared.ID
	SnapshotID                  shared.ID
	IdentityID                  shared.ID
	ProducerKind                string
	FindingKind                 string
	FingerprintSchemaVersion    int
	FingerprintInput            domain.FingerprintCanonicalInputV1
	InputTrusted                bool
	OwnershipValidated          bool
	RedactionComplete           bool
	TrustedProducerID           bool
	OverrideSourceObservationID shared.ID
	Aliases                     []AliasInput
	ReviewReason                domain.CandidateReason
	ReviewDetailCode            string
	SkipDetailCode              string
	ReviewRefs                  []domain.CandidateRef
	ProvisionalIdentity         bool
	Observation                 ObservationInput
	Actor                       string
}

type Result struct {
	Outcome     Outcome
	Method      domain.MatchMethod
	Reason      string
	Identity    *domain.Identity
	Observation *domain.Observation
	Candidate   *domain.MatchCandidate
	Skip        *domain.SkipRecord
}

type ResolveInput struct {
	TenantID             shared.ID
	CycleID              shared.ID
	CandidateID          shared.ID
	EventID              shared.ID
	Action               domain.ResolutionAction
	Actor                string
	Reason               string
	AfterRefs            []domain.CandidateRef
	SuccessorCandidateID shared.ID
	ExpectedVersion      int64
	PriorEventID         shared.ID
}

type OverrideInput struct {
	TenantID            shared.ID
	CycleID             shared.ID
	EventID             shared.ID
	Action              domain.OverrideAction
	SourceObservationID shared.ID
	SourceIdentityID    shared.ID
	TargetObservationID shared.ID
	TargetIdentityID    shared.ID
	Actor               string
	Reason              string
	ExpectedVersion     int64
	PriorEventID        shared.ID
}

type ApproveAliasInput struct {
	TenantID        shared.ID
	CycleID         shared.ID
	IdentityID      shared.ID
	AliasID         shared.ID
	ProducerKind    string
	FindingKind     string
	TargetCanonical string
	SchemaVersion   int
	Value           string
	Actor           string
}

type Service struct {
	repository   ports.FindingLineageRepository
	transactions ports.TenantTransactionRunner
	audit        ports.AuditLogger
	clock        ports.Clock
	ids          ports.IDGenerator
	observer     ports.FindingLineageObserver
}

func NewService(repository ports.FindingLineageRepository, transactions ports.TenantTransactionRunner, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator, observer ports.FindingLineageObserver) (*Service, error) {
	if repository == nil || transactions == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: finding lineage dependencies are required", shared.ErrValidation)
	}
	if observer == nil {
		observer = noopObserver{}
	}
	return &Service{repository: repository, transactions: transactions, audit: audit, clock: clock, ids: ids, observer: observer}, nil
}

func (service *Service) Correlate(ctx context.Context, input CorrelateInput) (Result, error) {
	input.TenantID = shared.TenantOrDefault(input.TenantID)
	input.Actor = strings.TrimSpace(input.Actor)
	if err := validateCorrelateInput(input); err != nil {
		return Result{}, err
	}
	sourceHash, err := domain.SourceReferenceHash(input.ProducerKind, input.FindingKind, input.FingerprintInput.TargetIdentityCanonical,
		input.Observation.SourceFindingID, input.Observation.SourceOccurrenceID)
	if err != nil {
		return Result{}, err
	}
	if input.ProvisionalIdentity {
		fields := make(map[string]domain.CanonicalValue, len(input.FingerprintInput.IdentityFields)+1)
		for key, value := range input.FingerprintInput.IdentityFields {
			fields[key] = value
		}
		fields["provisional_source_reference_hash"] = domain.Text(sourceHash)
		input.FingerprintInput.IdentityFields = fields
	}
	var result Result
	err = service.transactions.Run(ctx, input.TenantID, func(txCtx context.Context) error {
		var err error
		switch {
		case !input.InputTrusted:
			result, err = service.skip(txCtx, input, sourceHash, domain.SkipInvalidTrust, skipDetailCode(input.SkipDetailCode, "input_not_trusted"))
			return err
		case !input.OwnershipValidated:
			result, err = service.skip(txCtx, input, sourceHash, domain.SkipInvalidOwnership, skipDetailCode(input.SkipDetailCode, "ownership_not_validated"))
			return err
		case !input.RedactionComplete:
			result, err = service.skip(txCtx, input, sourceHash, domain.SkipRedactionRequired, skipDetailCode(input.SkipDetailCode, "redaction_not_complete"))
			return err
		}

		fingerprint, canonicalErr := domain.CanonicalizeFingerprintV1(input.FingerprintInput)
		if errors.Is(canonicalErr, domain.ErrSensitiveInput) {
			result, err = service.skip(txCtx, input, sourceHash, domain.SkipRedactionRequired, "sensitive_canonical_field")
			return err
		}
		if canonicalErr != nil && !errors.Is(canonicalErr, domain.ErrIncompleteIdentity) {
			return canonicalErr
		}
		if canonicalErr == nil {
			existing, lookupErr := service.repository.GetObservationBySource(txCtx, input.TenantID, input.CycleID, input.SnapshotID,
				input.ProducerKind, input.FindingKind, input.FingerprintInput.TargetIdentityCanonical,
				input.Observation.SourceFindingID, input.Observation.SourceOccurrenceID)
			if lookupErr == nil {
				if !observationReplayMatches(existing, input.Observation) {
					return fmt.Errorf("%w: source observation replay body differs", shared.ErrConflict)
				}
				identity, getErr := service.repository.GetIdentity(txCtx, input.TenantID, input.CycleID, existing.IdentityID)
				if getErr != nil {
					return getErr
				}
				result = matchedResult(identity, existing, domain.MethodProducerID, "observation_replay")
				return service.auditResult(txCtx, input, result, sourceHash)
			}
			if !errors.Is(lookupErr, shared.ErrNotFound) {
				return lookupErr
			}
		}

		excluded := map[shared.ID]struct{}{}
		if !input.OverrideSourceObservationID.IsZero() {
			override, lookupErr := service.repository.GetActiveOverride(txCtx, input.TenantID, input.CycleID, input.OverrideSourceObservationID)
			if lookupErr == nil {
				if override.Action == domain.OverrideUnlink {
					excluded[override.TargetIdentityID] = struct{}{}
				} else {
					identity, getErr := service.repository.GetIdentity(txCtx, input.TenantID, input.CycleID, override.TargetIdentityID)
					if getErr != nil {
						return getErr
					}
					result, err = service.link(txCtx, input, identity, domain.MethodOverride, "active_override", sourceHash)
					return err
				}
			} else if !errors.Is(lookupErr, shared.ErrNotFound) {
				return lookupErr
			}
		}

		if input.TrustedProducerID {
			sourceID := input.Observation.SourceFindingID
			if sourceID == "" {
				sourceID = input.Observation.SourceOccurrenceID
			}
			identities, lookupErr := service.repository.FindIdentitiesByProducerID(txCtx, input.TenantID, input.CycleID,
				input.ProducerKind, input.FindingKind, input.FingerprintInput.TargetIdentityCanonical, sourceID)
			if lookupErr != nil {
				return lookupErr
			}
			identities = withoutExcluded(identities, excluded)
			switch len(identities) {
			case 1:
				result, err = service.link(txCtx, input, identities[0], domain.MethodProducerID, "trusted_producer_id", sourceHash)
				return err
			case 2:
				fallthrough
			default:
				if len(identities) > 1 {
					result, err = service.review(txCtx, input, sourceHash, fingerprint, domain.ReasonLegacyAmbiguous, domain.MethodProducerID, identities, nil)
					return err
				}
			}
		}

		if canonicalErr == nil {
			identities, lookupErr := service.repository.FindIdentitiesByFingerprint(txCtx, input.TenantID, input.CycleID,
				input.ProducerKind, input.FindingKind, input.FingerprintSchemaVersion,
				input.FingerprintInput.TargetIdentityCanonical, fingerprint.Fingerprint)
			if lookupErr != nil {
				return lookupErr
			}
			identities = withoutExcluded(identities, excluded)
			if len(identities) == 1 {
				result, err = service.link(txCtx, input, identities[0], domain.MethodFingerprint, "exact_fingerprint", sourceHash)
				return err
			}
			if len(identities) > 1 {
				result, err = service.review(txCtx, input, sourceHash, fingerprint, domain.ReasonFingerprintCollision, domain.MethodFingerprint, identities, nil)
				return err
			}
		}

		aliasIdentities := make([]domain.Identity, 0)
		seenAliases := map[shared.ID]struct{}{}
		for _, alias := range input.Aliases {
			aliasFingerprint, hashErr := domain.HashAlias(input.ProducerKind, input.FindingKind,
				input.FingerprintInput.TargetIdentityCanonical, alias.SchemaVersion, alias.Value)
			if hashErr != nil {
				return hashErr
			}
			matches, lookupErr := service.repository.FindIdentitiesByAlias(txCtx, input.TenantID, input.CycleID,
				input.ProducerKind, input.FindingKind, alias.SchemaVersion,
				input.FingerprintInput.TargetIdentityCanonical, aliasFingerprint)
			if lookupErr != nil {
				return lookupErr
			}
			for _, identity := range withoutExcluded(matches, excluded) {
				if _, exists := seenAliases[identity.ID]; exists {
					continue
				}
				seenAliases[identity.ID] = struct{}{}
				aliasIdentities = append(aliasIdentities, identity)
			}
		}
		if len(aliasIdentities) == 1 {
			result, err = service.link(txCtx, input, aliasIdentities[0], domain.MethodAlias, "approved_alias", sourceHash)
			return err
		}
		if len(aliasIdentities) > 1 {
			result, err = service.review(txCtx, input, sourceHash, fingerprint, domain.ReasonMerge, domain.MethodAlias, aliasIdentities, nil)
			return err
		}

		if canonicalErr == nil && input.ProvisionalIdentity {
			identity, observation, createErr := service.createIdentityObservation(txCtx, input, fingerprint)
			if createErr != nil {
				return createErr
			}
			result, err = service.review(txCtx, input, sourceHash, fingerprint, input.ReviewReason, domain.MethodMatcher, []domain.Identity{identity}, input.ReviewRefs)
			if err == nil {
				result.Identity, result.Observation = &identity, &observation
			}
			return err
		}
		if canonicalErr != nil {
			result, err = service.review(txCtx, input, sourceHash, domain.CanonicalFingerprint{}, domain.ReasonInsufficientAnchor, domain.MethodMatcher, nil, input.ReviewRefs)
			return err
		}
		if len(input.ReviewRefs) > 0 || input.ReviewReason.Valid() {
			if !input.ReviewReason.Valid() {
				return fmt.Errorf("%w: review reason is required", shared.ErrValidation)
			}
			result, err = service.review(txCtx, input, sourceHash, fingerprint, input.ReviewReason, domain.MethodMatcher, nil, input.ReviewRefs)
			return err
		}

		identity, observation, createErr := service.createIdentityObservation(txCtx, input, fingerprint)
		if createErr != nil {
			return createErr
		}
		result = Result{Outcome: OutcomeCreated, Method: domain.MethodNewIdentity, Reason: "new_identity", Identity: &identity, Observation: &observation}
		return service.auditResult(txCtx, input, result, sourceHash)
	})
	if err != nil {
		return Result{}, err
	}
	service.observer.ObserveFindingLineage(string(result.Outcome), string(result.Method), result.Reason)
	return result, nil
}

func (service *Service) ResolveCandidate(ctx context.Context, input ResolveInput) (domain.MatchCandidate, domain.ResolutionEvent, bool, error) {
	input.TenantID = shared.TenantOrDefault(input.TenantID)
	if input.TenantID.IsZero() || input.CycleID.IsZero() || input.CandidateID.IsZero() || input.ExpectedVersion <= 0 || strings.TrimSpace(input.Actor) == "" {
		return domain.MatchCandidate{}, domain.ResolutionEvent{}, false, fmt.Errorf("%w: resolution ownership and version are required", shared.ErrValidation)
	}
	if input.EventID.IsZero() {
		input.EventID = service.ids.NewID()
	}
	var candidate domain.MatchCandidate
	var event domain.ResolutionEvent
	var applied bool
	err := service.transactions.Run(ctx, input.TenantID, func(txCtx context.Context) error {
		if !input.EventID.IsZero() {
			events, err := service.repository.ListCandidateResolutions(txCtx, input.TenantID, input.CycleID, input.CandidateID)
			if err != nil {
				return err
			}
			for _, existing := range events {
				if existing.ID != input.EventID {
					continue
				}
				candidate, err = service.repository.GetCandidate(txCtx, input.TenantID, input.CycleID, input.CandidateID)
				if err != nil {
					return err
				}
				event, applied = existing, false
				return service.audit.Record(txCtx, ports.AuditEntry{
					Actor: strings.TrimSpace(input.Actor), Action: "finding_lineage.candidate_resolved", Target: candidate.ID.String(), At: event.CreatedAt,
					Metadata: map[string]string{"tenant_id": input.TenantID.String(), "cycle_id": input.CycleID.String(), "action": string(existing.Action), "applied": "false", "version": fmt.Sprintf("%d", event.Version)},
				})
			}
		}
		current, err := service.repository.GetCandidate(txCtx, input.TenantID, input.CycleID, input.CandidateID)
		if err != nil {
			return err
		}
		updated, resolution, err := domain.ResolveCandidate(current, input.EventID, input.Action, input.Actor, input.Reason,
			input.AfterRefs, input.SuccessorCandidateID, input.ExpectedVersion, input.PriorEventID, service.clock.Now().UTC())
		if err != nil {
			return err
		}
		candidate, event, applied, err = service.repository.ResolveCandidateCAS(txCtx, updated, resolution)
		if err != nil {
			return err
		}
		return service.audit.Record(txCtx, ports.AuditEntry{
			Actor: strings.TrimSpace(input.Actor), Action: "finding_lineage.candidate_resolved", Target: candidate.ID.String(), At: event.CreatedAt,
			Metadata: map[string]string{"tenant_id": input.TenantID.String(), "cycle_id": input.CycleID.String(), "action": string(input.Action), "applied": fmt.Sprintf("%t", applied), "version": fmt.Sprintf("%d", event.Version)},
		})
	})
	if err == nil {
		service.observer.ObserveFindingLineage("resolved", string(domain.MethodManual), string(input.Action))
	}
	return candidate, event, applied, err
}

func (service *Service) AppendOverride(ctx context.Context, input OverrideInput) (domain.OverrideEvent, bool, error) {
	input.TenantID = shared.TenantOrDefault(input.TenantID)
	if input.EventID.IsZero() {
		input.EventID = service.ids.NewID()
	}
	event, err := domain.NewOverrideEvent(domain.OverrideEvent{
		TenantID: input.TenantID, CycleID: input.CycleID, ID: input.EventID, Action: input.Action,
		SourceObservationID: input.SourceObservationID, SourceIdentityID: input.SourceIdentityID,
		TargetObservationID: input.TargetObservationID, TargetIdentityID: input.TargetIdentityID,
		Actor: input.Actor, Reason: input.Reason, ExpectedVersion: input.ExpectedVersion, Version: input.ExpectedVersion + 1,
		PriorEventID: input.PriorEventID, CreatedAt: service.clock.Now().UTC(),
	})
	if err != nil {
		return domain.OverrideEvent{}, false, err
	}
	var stored domain.OverrideEvent
	var applied bool
	err = service.transactions.Run(ctx, input.TenantID, func(txCtx context.Context) error {
		var appendErr error
		stored, applied, appendErr = service.repository.AppendOverrideCAS(txCtx, event)
		if appendErr != nil {
			return appendErr
		}
		return service.audit.Record(txCtx, ports.AuditEntry{
			Actor: stored.Actor, Action: "finding_lineage.override_appended", Target: stored.ID.String(), At: stored.CreatedAt,
			Metadata: map[string]string{"tenant_id": stored.TenantID.String(), "cycle_id": stored.CycleID.String(), "action": string(stored.Action), "applied": fmt.Sprintf("%t", applied), "version": fmt.Sprintf("%d", stored.Version)},
		})
	})
	if err == nil {
		service.observer.ObserveFindingLineage("override", string(domain.MethodOverride), string(stored.Action))
	}
	return stored, applied, err
}

func (service *Service) ApproveAlias(ctx context.Context, input ApproveAliasInput) (domain.Alias, bool, error) {
	input.TenantID = shared.TenantOrDefault(input.TenantID)
	if input.AliasID.IsZero() {
		input.AliasID = service.ids.NewID()
	}
	fingerprint, err := domain.HashAlias(input.ProducerKind, input.FindingKind, input.TargetCanonical, input.SchemaVersion, input.Value)
	if err != nil {
		return domain.Alias{}, false, err
	}
	alias := domain.Alias{
		TenantID: input.TenantID, CycleID: input.CycleID, ID: input.AliasID, IdentityID: input.IdentityID,
		ProducerKind: input.ProducerKind, FindingKind: input.FindingKind, TargetCanonical: input.TargetCanonical,
		SchemaVersion: input.SchemaVersion, Fingerprint: fingerprint, ApprovedBy: strings.TrimSpace(input.Actor), ApprovedAt: service.clock.Now().UTC(),
	}
	if err := alias.Validate(); err != nil {
		return domain.Alias{}, false, err
	}
	created := false
	err = service.transactions.Run(ctx, input.TenantID, func(txCtx context.Context) error {
		var appendErr error
		created, appendErr = service.repository.AppendAlias(txCtx, alias)
		if appendErr != nil {
			return appendErr
		}
		return service.audit.Record(txCtx, ports.AuditEntry{
			Actor: alias.ApprovedBy, Action: "finding_lineage.alias_approved", Target: alias.IdentityID.String(), At: alias.ApprovedAt,
			Metadata: map[string]string{"tenant_id": alias.TenantID.String(), "cycle_id": alias.CycleID.String(), "alias_id": alias.ID.String(), "created": fmt.Sprintf("%t", created), "schema_version": fmt.Sprintf("%d", alias.SchemaVersion)},
		})
	})
	return alias, created, err
}

func (service *Service) link(ctx context.Context, input CorrelateInput, identity domain.Identity, method domain.MatchMethod, reason, sourceHash string) (Result, error) {
	observation, err := service.observation(input, identity.ID)
	if err != nil {
		return Result{}, err
	}
	if err := service.repository.AppendObservation(ctx, observation); err != nil {
		return Result{}, err
	}
	result := matchedResult(identity, observation, method, reason)
	return result, service.auditResult(ctx, input, result, sourceHash)
}

func (service *Service) review(ctx context.Context, input CorrelateInput, sourceHash string, fingerprint domain.CanonicalFingerprint, reason domain.CandidateReason, method domain.MatchMethod, identities []domain.Identity, extraRefs []domain.CandidateRef) (Result, error) {
	reasonCode := string(reason)
	if input.ReviewDetailCode != "" {
		reasonCode = input.ReviewDetailCode
	}
	refs := []domain.CandidateRef{{Position: 0, Role: domain.RoleSource, ExternalReferenceHash: sourceHash, Method: method, ScoreMilli: 1000, Confidence: domain.ConfidenceHigh, ReasonPayload: map[string]string{"reason_code": reasonCode}}}
	for _, identity := range identities {
		refs = append(refs, domain.CandidateRef{Position: len(refs), Role: domain.RoleCandidate, IdentityID: identity.ID, Method: method, ScoreMilli: 1000, Confidence: domain.ConfidenceHigh, ReasonPayload: map[string]string{"reason_code": reasonCode}})
	}
	for _, reference := range extraRefs {
		reference.Position = len(refs)
		if reference.Role == domain.RoleSource {
			reference.Role = domain.RoleCandidate
		}
		refs = append(refs, reference)
	}
	candidate, err := domain.NewMatchCandidate(domain.MatchCandidate{
		TenantID: input.TenantID, CycleID: input.CycleID, SnapshotID: input.SnapshotID, ID: service.ids.NewID(),
		ProducerKind: input.ProducerKind, FindingKind: input.FindingKind, Reason: reason,
		FingerprintSchemaVersion: input.FingerprintSchemaVersion, Fingerprint: fingerprint.Fingerprint,
		SourceReferenceHash: sourceHash, Refs: refs, CreatedAt: service.clock.Now().UTC(),
	})
	if err != nil {
		return Result{}, err
	}
	stored, created, err := service.repository.CreateCandidate(ctx, candidate, service.ids.NewID())
	if err != nil {
		return Result{}, err
	}
	result := Result{Outcome: OutcomeReview, Method: method, Reason: reasonCode, Candidate: &stored}
	if err := service.auditResult(ctx, input, result, sourceHash); err != nil {
		return Result{}, err
	}
	_ = created
	return result, nil
}

func (service *Service) skip(ctx context.Context, input CorrelateInput, sourceHash string, reason domain.SkipReason, detailCode string) (Result, error) {
	record := domain.SkipRecord{
		TenantID: input.TenantID, CycleID: input.CycleID, SnapshotID: input.SnapshotID, ID: service.ids.NewID(),
		ProducerKind: input.ProducerKind, FindingKind: input.FindingKind, Reason: reason,
		SourceReferenceHash: sourceHash, DetailCode: detailCode, CreatedAt: service.clock.Now().UTC(),
	}
	if _, err := service.repository.AppendSkip(ctx, record); err != nil {
		return Result{}, err
	}
	result := Result{Outcome: OutcomeSkipped, Reason: string(reason), Skip: &record}
	return result, service.auditResult(ctx, input, result, sourceHash)
}

func (service *Service) observation(input CorrelateInput, identityID shared.ID) (domain.Observation, error) {
	id := input.Observation.ID
	if id.IsZero() {
		id = service.ids.NewID()
	}
	observedAt := input.Observation.ObservedAt
	if observedAt.IsZero() {
		observedAt = service.clock.Now().UTC()
	}
	observation := domain.Observation{
		TenantID: input.TenantID, CycleID: input.CycleID, ID: id, SnapshotID: input.SnapshotID, IdentityID: identityID,
		ProducerKind: input.ProducerKind, FindingKind: input.FindingKind, TargetCanonical: input.FingerprintInput.TargetIdentityCanonical,
		SourceFindingID: input.Observation.SourceFindingID, SourceOccurrenceID: input.Observation.SourceOccurrenceID,
		Severity: input.Observation.Severity, RiskScoreMilli: input.Observation.RiskScoreMilli,
		ComponentVersion: input.Observation.ComponentVersion, Location: input.Observation.Location,
		Reachability: input.Observation.Reachability, EvidenceDigest: input.Observation.EvidenceDigest,
		ScannerProvenance: input.Observation.ScannerProvenance, ObservedAt: observedAt,
	}
	return observation, observation.Validate()
}

func (service *Service) createIdentityObservation(ctx context.Context, input CorrelateInput, fingerprint domain.CanonicalFingerprint) (domain.Identity, domain.Observation, error) {
	identityID := input.IdentityID
	if identityID.IsZero() {
		identityID = service.ids.NewID()
	}
	identity := domain.Identity{
		TenantID: input.TenantID, CycleID: input.CycleID, ID: identityID, ProducerKind: input.ProducerKind,
		FindingKind: input.FindingKind, CanonicalizationVersion: domain.CanonicalizationVersionV1,
		FingerprintSchemaVersion: input.FingerprintSchemaVersion, LineageFingerprint: fingerprint.Fingerprint,
		TargetIdentitySchemaVersion: input.FingerprintInput.TargetIdentitySchemaVersion,
		TargetIdentityCanonical:     input.FingerprintInput.TargetIdentityCanonical,
		CanonicalIdentityFields:     fingerprint.IdentityFields, FirstSeenSnapshotID: input.SnapshotID, CreatedAt: service.clock.Now().UTC(),
	}
	observation, err := service.observation(input, identity.ID)
	if err != nil {
		return domain.Identity{}, domain.Observation{}, err
	}
	if err := service.repository.CreateIdentityWithObservation(ctx, identity, observation); err != nil {
		return domain.Identity{}, domain.Observation{}, err
	}
	return identity, observation, nil
}

func observationReplayMatches(existing domain.Observation, incoming ObservationInput) bool {
	if !incoming.ID.IsZero() && incoming.ID != existing.ID {
		return false
	}
	if incoming.SourceFindingID != existing.SourceFindingID || incoming.SourceOccurrenceID != existing.SourceOccurrenceID ||
		incoming.Severity != existing.Severity || !sameOptionalRiskScore(incoming.RiskScoreMilli, existing.RiskScoreMilli) ||
		incoming.ComponentVersion != existing.ComponentVersion || incoming.Location != existing.Location || incoming.Reachability != existing.Reachability ||
		incoming.EvidenceDigest != existing.EvidenceDigest || incoming.ScannerProvenance != existing.ScannerProvenance {
		return false
	}
	return incoming.ObservedAt.IsZero() || incoming.ObservedAt.Equal(existing.ObservedAt)
}

func sameOptionalRiskScore(left, right *int) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func (service *Service) auditResult(ctx context.Context, input CorrelateInput, result Result, sourceHash string) error {
	target := sourceHash
	if result.Identity != nil {
		target = result.Identity.ID.String()
	}
	if result.Candidate != nil {
		target = result.Candidate.ID.String()
	}
	if result.Skip != nil {
		target = result.Skip.ID.String()
	}
	return service.audit.Record(ctx, ports.AuditEntry{
		Actor: input.Actor, Action: "finding_lineage.correlated", Target: target, At: service.clock.Now().UTC(),
		Metadata: map[string]string{
			"tenant_id": input.TenantID.String(), "cycle_id": input.CycleID.String(), "snapshot_id": input.SnapshotID.String(),
			"outcome": string(result.Outcome), "method": string(result.Method), "reason": result.Reason, "source_reference_hash": sourceHash,
		},
	})
}

func validateCorrelateInput(input CorrelateInput) error {
	if input.TenantID.IsZero() || input.CycleID.IsZero() || input.SnapshotID.IsZero() || input.FingerprintSchemaVersion <= 0 || input.Actor == "" || len(input.Actor) > 256 {
		return fmt.Errorf("%w: correlation ownership, actor, and fingerprint version are required", shared.ErrValidation)
	}
	if strings.TrimSpace(input.ProducerKind) == "" || strings.TrimSpace(input.FindingKind) == "" || len(input.ProducerKind) > 256 || len(input.FindingKind) > 256 {
		return fmt.Errorf("%w: producer and finding kind are required", shared.ErrValidation)
	}
	if input.FingerprintInput.ProducerKind != input.ProducerKind || input.FingerprintInput.CanonicalizationVersion != domain.CanonicalizationVersionV1 || input.FingerprintInput.TargetIdentitySchemaVersion <= 0 || strings.TrimSpace(input.FingerprintInput.TargetIdentityCanonical) == "" {
		return fmt.Errorf("%w: fingerprint metadata does not match correlation input", shared.ErrValidation)
	}
	if input.Observation.SourceFindingID == "" && input.Observation.SourceOccurrenceID == "" {
		return fmt.Errorf("%w: source finding or occurrence id is required", shared.ErrValidation)
	}
	if len(input.Observation.SourceFindingID) > 512 || len(input.Observation.SourceOccurrenceID) > 512 {
		return fmt.Errorf("%w: source finding identifiers exceed 512 bytes", shared.ErrValidation)
	}
	for _, alias := range input.Aliases {
		if alias.SchemaVersion <= 0 || strings.TrimSpace(alias.Value) == "" {
			return fmt.Errorf("%w: alias schema and value are required", shared.ErrValidation)
		}
	}
	if input.ProvisionalIdentity && !input.ReviewReason.Valid() {
		return fmt.Errorf("%w: provisional identity review reason is required", shared.ErrValidation)
	}
	if input.ReviewDetailCode != "" && !validReasonCode(input.ReviewDetailCode) {
		return fmt.Errorf("%w: review detail code is invalid", shared.ErrValidation)
	}
	if input.SkipDetailCode != "" && !validReasonCode(input.SkipDetailCode) {
		return fmt.Errorf("%w: skip detail code is invalid", shared.ErrValidation)
	}
	if _, reserved := input.FingerprintInput.IdentityFields["provisional_source_reference_hash"]; reserved {
		return fmt.Errorf("%w: provisional source hash is service-owned", shared.ErrValidation)
	}
	return nil
}

func skipDetailCode(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func validReasonCode(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if char != '_' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func matchedResult(identity domain.Identity, observation domain.Observation, method domain.MatchMethod, reason string) Result {
	return Result{Outcome: OutcomeMatched, Method: method, Reason: reason, Identity: &identity, Observation: &observation}
}

func withoutExcluded(identities []domain.Identity, excluded map[shared.ID]struct{}) []domain.Identity {
	filtered := make([]domain.Identity, 0, len(identities))
	for _, identity := range identities {
		if _, exists := excluded[identity.ID]; !exists {
			filtered = append(filtered, identity)
		}
	}
	return filtered
}

type noopObserver struct{}

func (noopObserver) ObserveFindingLineage(string, string, string) {}
