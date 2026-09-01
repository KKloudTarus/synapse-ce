package findinglineage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestCorrelatePrecedenceTable(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		withOverride  bool
		trustedSource bool
		fingerprint   string
		alias         bool
		wantMethod    domain.MatchMethod
		wantIdentity  shared.ID
		wantOutcome   Outcome
	}{
		{name: "override", withOverride: true, trustedSource: true, fingerprint: "fingerprint", alias: true, wantMethod: domain.MethodOverride, wantIdentity: "identity-override", wantOutcome: OutcomeMatched},
		{name: "producer id", trustedSource: true, fingerprint: "fingerprint", alias: true, wantMethod: domain.MethodProducerID, wantIdentity: "identity-producer", wantOutcome: OutcomeMatched},
		{name: "fingerprint", fingerprint: "fingerprint", alias: true, wantMethod: domain.MethodFingerprint, wantIdentity: "identity-fingerprint", wantOutcome: OutcomeMatched},
		{name: "alias", fingerprint: "unique-alias", alias: true, wantMethod: domain.MethodAlias, wantIdentity: "identity-alias", wantOutcome: OutcomeMatched},
		{name: "new identity", fingerprint: "unique-new", wantMethod: domain.MethodNewIdentity, wantOutcome: OutcomeCreated},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			repository := memory.NewFindingLineageRepository()
			clock := fixedClock{now: time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)}
			ids := &sequenceIDs{}
			audit := &collectingAudit{}
			service, err := NewService(repository, immediateTransactions{}, audit, clock, ids, &collectingObserver{})
			if err != nil {
				t.Fatal(err)
			}

			seedIdentity(t, repository, clock.now, "identity-override", "observation-override", "override-source", "override")
			seedIdentity(t, repository, clock.now, "identity-producer", "observation-producer", "trusted-source", "producer")
			seedIdentity(t, repository, clock.now, "identity-fingerprint", "observation-fingerprint", "fingerprint-source", "fingerprint")
			seedIdentity(t, repository, clock.now, "identity-alias", "observation-alias", "alias-source", "alias-target")
			aliasFingerprint, err := domain.HashAlias("sca", "vulnerability", "repo:example", 1, "legacy-alias")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := repository.AppendAlias(context.Background(), domain.Alias{
				TenantID: "tenant", CycleID: "cycle", ID: "alias", IdentityID: "identity-alias", ProducerKind: "sca",
				FindingKind: "vulnerability", TargetCanonical: "repo:example", SchemaVersion: 1, Fingerprint: aliasFingerprint,
				ApprovedBy: "reviewer", ApprovedAt: clock.now,
			}); err != nil {
				t.Fatal(err)
			}
			if testCase.withOverride {
				override, err := domain.NewOverrideEvent(domain.OverrideEvent{
					TenantID: "tenant", CycleID: "cycle", ID: "override-event", Action: domain.OverrideConfirm,
					SourceObservationID: "observation-producer", TargetIdentityID: "identity-override",
					Actor: "reviewer", Reason: "manual confirmation", Version: 1, CreatedAt: clock.now,
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := repository.AppendOverrideCAS(context.Background(), override); err != nil {
					t.Fatal(err)
				}
			}

			input := correlateInput(testCase.name, testCase.fingerprint)
			if testCase.trustedSource {
				input.Observation.SourceFindingID = "trusted-source"
				input.TrustedProducerID = true
			}
			if testCase.withOverride {
				input.OverrideSourceObservationID = "observation-producer"
			}
			if testCase.alias {
				input.Aliases = []AliasInput{{SchemaVersion: 1, Value: "legacy-alias"}}
			}
			result, err := service.Correlate(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if result.Outcome != testCase.wantOutcome || result.Method != testCase.wantMethod {
				t.Fatalf("result=%+v", result)
			}
			if !testCase.wantIdentity.IsZero() && (result.Identity == nil || result.Identity.ID != testCase.wantIdentity) {
				t.Fatalf("identity=%+v want=%s", result.Identity, testCase.wantIdentity)
			}
			if len(audit.entries) != 1 {
				t.Fatalf("audit entries=%d", len(audit.entries))
			}
		})
	}
}

func TestCorrelateCollisionReplayAndChangedSetSupersession(t *testing.T) {
	repository := memory.NewFindingLineageRepository()
	clock := fixedClock{now: time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC)}
	service, err := NewService(repository, immediateTransactions{}, &collectingAudit{}, clock, &sequenceIDs{}, &collectingObserver{})
	if err != nil {
		t.Fatal(err)
	}
	seedIdentity(t, repository, clock.now, "identity-one", "observation-one", "source-one", "collision")
	seedIdentity(t, repository, clock.now, "identity-two", "observation-two", "source-two", "collision")

	input := correlateInput("collision", "collision")
	first, err := service.Correlate(context.Background(), input)
	if err != nil || first.Outcome != OutcomeReview || first.Candidate == nil || first.Candidate.Reason != domain.ReasonFingerprintCollision {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	replay, err := service.Correlate(context.Background(), input)
	if err != nil || replay.Candidate == nil || replay.Candidate.ID != first.Candidate.ID {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}

	seedIdentity(t, repository, clock.now, "identity-three", "observation-three", "source-three", "collision")
	changed, err := service.Correlate(context.Background(), input)
	if err != nil || changed.Candidate == nil || changed.Candidate.ID == first.Candidate.ID {
		t.Fatalf("changed=%+v err=%v", changed, err)
	}
	prior, err := repository.GetCandidate(context.Background(), "tenant", "cycle", first.Candidate.ID)
	if err != nil || prior.Status != domain.CandidateSuperseded || prior.SupersededByCandidateID != changed.Candidate.ID {
		t.Fatalf("prior=%+v err=%v", prior, err)
	}
	events, err := repository.ListCandidateResolutions(context.Background(), "tenant", "cycle", first.Candidate.ID)
	if err != nil || len(events) != 1 || events[0].Action != domain.ResolutionSupersede {
		t.Fatalf("events=%+v err=%v", events, err)
	}
}

func TestCorrelateSensitiveInputCreatesSecretSafeSkip(t *testing.T) {
	repository := memory.NewFindingLineageRepository()
	clock := fixedClock{now: time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)}
	service, err := NewService(repository, immediateTransactions{}, &collectingAudit{}, clock, &sequenceIDs{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	input := correlateInput("sensitive", "unused")
	input.FingerprintInput.IdentityFields = map[string]domain.CanonicalValue{"api_token": domain.Text("must-not-persist")}
	result, err := service.Correlate(context.Background(), input)
	if err != nil || result.Outcome != OutcomeSkipped || result.Skip == nil || result.Skip.Reason != domain.SkipRedactionRequired {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if result.Skip.DetailCode != "sensitive_canonical_field" || result.Skip.SourceReferenceHash == "" {
		t.Fatalf("skip=%+v", result.Skip)
	}
	records, err := repository.ListSkipsBySnapshot(context.Background(), "tenant", "cycle", input.SnapshotID)
	if err != nil || len(records) != 1 || strings.Contains(fmt.Sprintf("%+v", records[0]), "must-not-persist") {
		t.Fatalf("records=%+v err=%v", records, err)
	}
}

func TestResolveCandidateIsCASAndEventIdempotent(t *testing.T) {
	repository := memory.NewFindingLineageRepository()
	clock := fixedClock{now: time.Date(2026, 8, 31, 11, 0, 0, 0, time.UTC)}
	service, err := NewService(repository, immediateTransactions{}, &collectingAudit{}, clock, &sequenceIDs{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	seedIdentity(t, repository, clock.now, "identity-one", "observation-one", "source-one", "resolve")
	seedIdentity(t, repository, clock.now, "identity-two", "observation-two", "source-two", "resolve")
	match, err := service.Correlate(context.Background(), correlateInput("resolve", "resolve"))
	if err != nil || match.Candidate == nil {
		t.Fatalf("match=%+v err=%v", match, err)
	}
	input := ResolveInput{
		TenantID: "tenant", CycleID: "cycle", CandidateID: match.Candidate.ID, EventID: "resolution-event",
		Action: domain.ResolutionDismiss, Actor: "reviewer", Reason: "not actionable", ExpectedVersion: 1,
	}
	resolved, event, applied, err := service.ResolveCandidate(context.Background(), input)
	if err != nil || !applied || resolved.Status != domain.CandidateResolved || event.Version != 2 {
		t.Fatalf("resolved=%+v event=%+v applied=%v err=%v", resolved, event, applied, err)
	}
	replayed, replayEvent, applied, err := service.ResolveCandidate(context.Background(), input)
	if err != nil || applied || replayed.ID != resolved.ID || replayEvent.ID != event.ID {
		t.Fatalf("replay=%+v event=%+v applied=%v err=%v", replayed, replayEvent, applied, err)
	}
	stale := input
	stale.EventID = "stale-event"
	if _, _, _, err := service.ResolveCandidate(context.Background(), stale); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale error=%v", err)
	}
}

func correlateInput(name, rule string) CorrelateInput {
	return CorrelateInput{
		TenantID: "tenant", CycleID: "cycle", SnapshotID: shared.ID("snapshot-new-" + name),
		ProducerKind: "sca", FindingKind: "vulnerability", FingerprintSchemaVersion: 1,
		FingerprintInput: domain.FingerprintCanonicalInputV1{
			CanonicalizationVersion: domain.CanonicalizationVersionV1, ProducerKind: "sca", TargetIdentitySchemaVersion: 1,
			TargetIdentityCanonical: "repo:example", IdentityFields: map[string]domain.CanonicalValue{"rule_id": domain.Text(rule)},
		},
		InputTrusted: true, OwnershipValidated: true, RedactionComplete: true,
		Observation: ObservationInput{
			ID: shared.ID("incoming-" + name), SourceFindingID: "incoming-source-" + name, Severity: shared.SeverityHigh,
			ScannerProvenance: domain.ScannerProvenance{ToolName: "scanner"},
		},
		Actor: "operator",
	}
}

func seedIdentity(t *testing.T, repository *memory.FindingLineageRepository, now time.Time, identityID, observationID, sourceID, rule string) {
	t.Helper()
	fingerprint, err := domain.CanonicalizeFingerprintV1(domain.FingerprintCanonicalInputV1{
		CanonicalizationVersion: domain.CanonicalizationVersionV1, ProducerKind: "sca", TargetIdentitySchemaVersion: 1,
		TargetIdentityCanonical: "repo:example", IdentityFields: map[string]domain.CanonicalValue{"rule_id": domain.Text(rule)},
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := domain.Identity{
		TenantID: "tenant", CycleID: "cycle", ID: shared.ID(identityID), ProducerKind: "sca", FindingKind: "vulnerability",
		CanonicalizationVersion: 1, FingerprintSchemaVersion: 1, LineageFingerprint: fingerprint.Fingerprint,
		TargetIdentitySchemaVersion: 1, TargetIdentityCanonical: "repo:example", CanonicalIdentityFields: fingerprint.IdentityFields,
		FirstSeenSnapshotID: "snapshot-old", CreatedAt: now,
	}
	observation := domain.Observation{
		TenantID: "tenant", CycleID: "cycle", ID: shared.ID(observationID), SnapshotID: "snapshot-old", IdentityID: identity.ID,
		ProducerKind: "sca", FindingKind: "vulnerability", TargetCanonical: "repo:example", SourceFindingID: sourceID,
		Severity: shared.SeverityUnknown, ScannerProvenance: domain.ScannerProvenance{ToolName: "scanner"}, ObservedAt: now,
	}
	if err := repository.CreateIdentityWithObservation(context.Background(), identity, observation); err != nil {
		t.Fatal(err)
	}
}

type immediateTransactions struct{}

func (immediateTransactions) Run(ctx context.Context, _ shared.ID, fn func(context.Context) error) error {
	return fn(ctx)
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

type sequenceIDs struct{ next int }

func (ids *sequenceIDs) NewID() shared.ID {
	ids.next++
	return shared.ID(fmt.Sprintf("generated-%d", ids.next))
}

type collectingAudit struct{ entries []ports.AuditEntry }

func (audit *collectingAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	audit.entries = append(audit.entries, entry)
	return nil
}

type collectingObserver struct{ outcomes []string }

func (observer *collectingObserver) ObserveFindingLineage(outcome, method, reason string) {
	observer.outcomes = append(observer.outcomes, outcome+":"+method+":"+reason)
}
