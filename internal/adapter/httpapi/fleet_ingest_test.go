package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	dci "github.com/KKloudTarus/synapse-ce/internal/domain/clusterinventory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/worksign"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/assetuc"
	clusterinventoryuc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/clusterinventory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetagentuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetwork"
)

// setupFleetWithIngest builds the fleet transport plus a real cluster-inventory ingest use case
// backed by an in-memory asset store, so an ingest actually persists assets.
func setupFleetWithIngest(t *testing.T) (http.Handler, *fleetagentuc.Service, *memory.AssetStore) {
	t.Helper()
	agentSvc, err := fleetagentuc.NewService(memory.NewFleetAgentStore(), ftAudit{}, ftClock{}, &ftIDs{})
	if err != nil {
		t.Fatalf("agent svc: %v", err)
	}
	signer, err := worksign.New([]byte("0123456789012345678901234567890123"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	workSvc, err := fleetwork.NewService(memory.NewWorkOrderStore(), signer, ftAudit{}, ftClock{}, &ftIDs{})
	if err != nil {
		t.Fatalf("work svc: %v", err)
	}
	store := memory.NewAssetStore()
	assetSvc, err := assetuc.NewService(store, ftAudit{}, ftClock{}, &ftIDs{})
	if err != nil {
		t.Fatalf("asset svc: %v", err)
	}
	ciSvc, err := clusterinventoryuc.NewService(assetSvc, ftAudit{}, ftClock{})
	if err != nil {
		t.Fatalf("cluster inventory svc: %v", err)
	}
	rt := &Router{log: discardLog()}
	rt.SetFleet(agentSvc, workSvc, func() time.Time { return time.Now().UTC() }, "")
	rt.SetFleetAdmin(agentSvc)
	rt.SetFleetClusterInventory(ciSvc)
	return rt.fleet.handler(), agentSvc, store
}

func enrolAgentToken(t *testing.T, h http.Handler, agentSvc *fleetagentuc.Service) string {
	t.Helper()
	tok, err := agentSvc.MintEnrolToken(context.Background(), "op", "default", time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/enrol", tok, map[string]any{"name": "cluster-agent", "platform": "kubernetes"}, true)
	if w.Code != http.StatusCreated {
		t.Fatalf("enrol should be 201, got %d (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Token == "" {
		t.Fatalf("enrol response: %v (%s)", err, w.Body.String())
	}
	return resp.Token
}

func sampleClusterSnapshot() dci.Snapshot {
	return dci.Snapshot{
		Cluster: "prod-eu",
		Namespaces: []dci.Namespace{{
			Name: "payments",
			Workloads: []dci.Workload{{
				Kind: "Deployment", Name: "api", ServiceAccount: "payments-sa",
				Containers: []dci.Container{{Name: "api", Image: "reg/api:v1", Digest: "sha256:aaa"}},
			}},
		}},
	}
}

func TestClusterInventoryIngestPersists(t *testing.T) {
	h, agentSvc, store := setupFleetWithIngest(t)
	token := enrolAgentToken(t, h, agentSvc)

	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/inventory/cluster", token, sampleClusterSnapshot(), true)
	if w.Code != http.StatusOK {
		t.Fatalf("ingest should be 200, got %d (%s)", w.Code, w.Body.String())
	}
	var summary struct {
		Assets int `json:"assets"`
		Edges  int `json:"edges"`
		Gaps   int `json:"coverage_gaps"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &summary); err != nil {
		t.Fatalf("summary: %v", err)
	}
	if summary.Assets == 0 || summary.Edges == 0 {
		t.Fatalf("expected assets+edges persisted, got %+v", summary)
	}
	// nothing scanned -> the running digest is an unscanned coverage gap, surfaced not swallowed.
	if summary.Gaps == 0 {
		t.Fatalf("an unscanned running digest must be reported as a coverage gap")
	}

	// The assets were actually persisted under the agent's tenant ("default").
	assets, err := store.ListAssets(context.Background(), "default")
	if err != nil {
		t.Fatalf("list assets: %v", err)
	}
	if len(assets) == 0 {
		t.Fatalf("expected assets persisted in the store for tenant default")
	}
	var haveWorkload bool
	for _, a := range assets {
		if a.Kind == "workload" && a.Name == "api" {
			haveWorkload = true
		}
	}
	if !haveWorkload {
		t.Fatalf("expected the api workload asset persisted, got %d assets", len(assets))
	}
}

func TestClusterInventoryIngestWireContractIsSnakeCase(t *testing.T) {
	// A hand-written snake_case payload (the documented wire contract) must decode + persist, proving
	// the API is the json tags, not the Go field layout.
	h, agentSvc, store := setupFleetWithIngest(t)
	token := enrolAgentToken(t, h, agentSvc)
	raw := json.RawMessage(`{
		"cluster": "prod-eu",
		"namespaces": [{
			"name": "payments",
			"has_network_policy": false,
			"workloads": [{
				"kind": "Deployment", "name": "api", "service_account": "payments-sa",
				"containers": [{"name": "api", "image": "reg/api:v1", "digest": "sha256:aaa"}]
			}]
		}]
	}`)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/inventory/cluster", token, raw, true)
	if w.Code != http.StatusOK {
		t.Fatalf("snake_case payload should be 200, got %d (%s)", w.Code, w.Body.String())
	}
	assets, _ := store.ListAssets(context.Background(), "default")
	var haveWorkload bool
	for _, a := range assets {
		if a.Kind == "workload" && a.Name == "api" {
			haveWorkload = true
		}
	}
	if !haveWorkload {
		t.Fatalf("snake_case payload must persist the api workload; got %d assets", len(assets))
	}
}

func TestClusterInventoryIngestRequiresAuth(t *testing.T) {
	h, _, _ := setupFleetWithIngest(t)
	// No bearer token -> unauthenticated (the authed() wrapper rejects before the handler).
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/inventory/cluster", "", sampleClusterSnapshot(), true)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated ingest must be 401, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestClusterInventoryIngestNotEnabled(t *testing.T) {
	// Fleet transport without the ingest use case wired -> route returns 404, not a panic.
	h, agentSvc, _ := setupFleet(t)
	token := enrolAgentToken(t, h, agentSvc)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/inventory/cluster", token, sampleClusterSnapshot(), true)
	if w.Code != http.StatusNotFound {
		t.Fatalf("ingest without the use case wired must be 404, got %d (%s)", w.Code, w.Body.String())
	}
}
