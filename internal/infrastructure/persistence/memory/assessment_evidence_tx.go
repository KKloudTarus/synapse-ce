package memory

import (
	"context"
	"github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func (repository *FindingLineageRepository) registerRollback(ctx context.Context) {
	registerTenantCheckpoint(ctx, repository, func(tenantID shared.ID) func() {
		identities := captureTenantEntries(repository.identities, func(k lineageKey, _ findinglineage.Identity) bool { return k.tenantID == tenantID })
		observations := captureTenantEntries(repository.observations, func(k lineageKey, _ findinglineage.Observation) bool { return k.tenantID == tenantID })
		aliases := captureTenantEntries(repository.aliases, func(k lineageKey, _ findinglineage.Alias) bool { return k.tenantID == tenantID })
		candidates := captureTenantEntries(repository.candidates, func(k lineageKey, _ findinglineage.MatchCandidate) bool { return k.tenantID == tenantID })
		resolutions := captureTenantEntries(repository.resolutions, func(k lineageKey, _ findinglineage.ResolutionEvent) bool { return k.tenantID == tenantID })
		overrides := captureTenantEntries(repository.overrides, func(k lineageKey, _ findinglineage.OverrideEvent) bool { return k.tenantID == tenantID })
		skips := captureTenantEntries(repository.skips, func(k lineageKey, _ findinglineage.SkipRecord) bool { return k.tenantID == tenantID })
		return func() {
			repository.mu.Lock()
			defer repository.mu.Unlock()
			identities()
			observations()
			aliases()
			candidates()
			resolutions()
			overrides()
			skips()
		}
	})
}
