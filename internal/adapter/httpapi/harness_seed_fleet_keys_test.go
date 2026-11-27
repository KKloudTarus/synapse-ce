package httpapi

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/keyregistry"
)

// The fleet keys seed registers one signing key for a tenantA agent. The key is derived from a fixed
// seed and window, so its id, which the revoke route is addressed by, is known before Run plants it.
const fleetKeysAgent = shared.ID("harness-agent-A")

var (
	fleetKeysNotBefore = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	fleetKeysNotAfter  = fleetKeysNotBefore.Add(24 * time.Hour)
	fleetKeysKey       = mustFleetKeysKey()
)

func mustFleetKeysKey() fleetagent.AgentSigningKey {
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, "harness-fleet-key-tenant-A-seed!")
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	key, err := fleetagent.NewSigningKey(fleetKeysAgent, fleetagent.PurposeDetectionBatch, pub, fleetKeysNotBefore, fleetKeysNotAfter)
	if err != nil {
		panic(err)
	}
	return key
}

func init() {
	list := "GET /api/v1/agents/{id}/keys"
	revoke := "POST /api/v1/agents/{id}/keys/{keyID}/revoke"
	registerHarnessSeed(harnessSeed{
		Name:   "fleet keys",
		Routes: []string{list},
		// The signing-key store scopes by the tenant on the request context, as the auth middleware
		// sets it; the routes take no engagement to resolve a tenant from.
		TenantBound: []string{list, revoke},
		RoutePathValues: map[string]map[string]string{
			list:   {"{id}": fleetKeysAgent.String()},
			revoke: {"{id}": fleetKeysAgent.String(), "{keyID}": fleetKeysKey.KeyID},
		},
		Run: seedFleetKeys,
	})
}

// seedFleetKeys wires the real key registry over the in-memory store and plants the key in tenantA
// directly, since its proof-of-possession is the agent plane's concern and not the operator routes'.
func seedFleetKeys(w *harnessWorld) []string {
	w.t.Helper()
	ctx := shared.WithTenant(context.Background(), "tenantA")
	agents := memory.NewFleetAgentStore()
	if err := agents.CreateAgent(ctx, &fleetagent.Agent{ID: fleetKeysAgent, TenantID: "tenantA", Name: "agent A"}); err != nil {
		w.t.Fatalf("seed tenantA agent: %v", err)
	}
	store := memory.NewAgentSigningKeyStore()
	if err := store.Register(ctx, fleetKeysKey); err != nil {
		w.t.Fatalf("seed tenantA signing key: %v", err)
	}
	service, err := keyregistry.NewService(store, &harnessAudit{}, engmiscClock{})
	if err != nil {
		w.t.Fatalf("key registry: %v", err)
	}
	service.SetAgentDirectory(agents)
	w.rt.SetFleetKeyAdmin(service)
	return []string{fleetKeysKey.KeyID}
}
