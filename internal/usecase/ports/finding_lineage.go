package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type FindingLineageRepository interface {
	CreateIdentityWithObservation(context.Context, findinglineage.Identity, findinglineage.Observation) error
	AppendObservation(context.Context, findinglineage.Observation) error
	AppendAlias(context.Context, findinglineage.Alias) (bool, error)
	GetIdentity(context.Context, shared.ID, shared.ID, shared.ID) (findinglineage.Identity, error)
	GetObservation(context.Context, shared.ID, shared.ID, shared.ID) (findinglineage.Observation, error)
	GetObservationBySource(context.Context, shared.ID, shared.ID, shared.ID, string, string, string, string, string) (findinglineage.Observation, error)
	FindIdentitiesByProducerID(context.Context, shared.ID, shared.ID, string, string, string, string) ([]findinglineage.Identity, error)
	FindIdentitiesByFingerprint(context.Context, shared.ID, shared.ID, string, string, int, string, string) ([]findinglineage.Identity, error)
	FindIdentitiesByAlias(context.Context, shared.ID, shared.ID, string, string, int, string, string) ([]findinglineage.Identity, error)
	ListObservationsBySnapshot(context.Context, shared.ID, shared.ID, shared.ID) ([]findinglineage.Observation, error)
	ListOpenCandidatesBySnapshot(context.Context, shared.ID, shared.ID, shared.ID) ([]findinglineage.MatchCandidate, error)
	ListActiveOverridesBySnapshot(context.Context, shared.ID, shared.ID, shared.ID) ([]findinglineage.OverrideEvent, error)
	CreateCandidate(context.Context, findinglineage.MatchCandidate, shared.ID) (findinglineage.MatchCandidate, bool, error)
	GetCandidate(context.Context, shared.ID, shared.ID, shared.ID) (findinglineage.MatchCandidate, error)
	ResolveCandidateCAS(context.Context, findinglineage.MatchCandidate, findinglineage.ResolutionEvent) (findinglineage.MatchCandidate, findinglineage.ResolutionEvent, bool, error)
	ListCandidateResolutions(context.Context, shared.ID, shared.ID, shared.ID) ([]findinglineage.ResolutionEvent, error)
	GetActiveOverride(context.Context, shared.ID, shared.ID, shared.ID) (findinglineage.OverrideEvent, error)
	AppendOverrideCAS(context.Context, findinglineage.OverrideEvent) (findinglineage.OverrideEvent, bool, error)
	ListOverrideEvents(context.Context, shared.ID, shared.ID, shared.ID) ([]findinglineage.OverrideEvent, error)
	AppendSkip(context.Context, findinglineage.SkipRecord) (bool, error)
	ListSkipsBySnapshot(context.Context, shared.ID, shared.ID, shared.ID) ([]findinglineage.SkipRecord, error)
}

type FindingLineageObserver interface {
	ObserveFindingLineage(outcome, method, reason string)
}
