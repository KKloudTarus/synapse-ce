package httpapi

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/agentspool"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/agentstate"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/spool"
	"github.com/KKloudTarus/synapse-ce/internal/platform/worksign"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/detectionship"
	detectledger "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/detectledger"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/keyregistry"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetagentuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetwork"
)

// TestAgentDetectionShipperLivePath exercises the complete remaining A4 path with real adapters:
// durable P1 WAL → private-key persistence → PoP registration over HTTP → signed batch over HTTP →
// server-side key resolution/content verification → SealOnce bridge → detection projection → local ACK.
func TestAgentDetectionShipperLivePath(t *testing.T) {
	agentSvc, err := fleetagentuc.NewService(memory.NewFleetAgentStore(), ftAudit{}, ftClock{}, &ftIDs{})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := worksign.New([]byte("0123456789012345678901234567890123"))
	if err != nil {
		t.Fatal(err)
	}
	workSvc, err := fleetwork.NewService(memory.NewWorkOrderStore(), signer, ftAudit{}, ftClock{}, &ftIDs{})
	if err != nil {
		t.Fatal(err)
	}
	keyStore := memory.NewAgentSigningKeyStore()
	keySvc, err := keyregistry.NewService(keyStore, ftAudit{}, ftClock{})
	if err != nil {
		t.Fatal(err)
	}
	records := memory.NewDetectionRecordStore()
	detectionSvc, err := detectledger.NewService(records, fakeDetChain{}, keyStore, ftAudit{}, ftClock{}, &ftIDs{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	router := &Router{log: discardLog()}
	router.SetFleet(agentSvc, workSvc, func() time.Time { return time.Now().UTC() }, "")
	router.SetFleetKeyRegistration(keySvc)
	router.SetFleetDetectionIngest(detectionSvc)
	handler := router.fleet.handler()
	token, agentID := enrolAgent(t, handler, agentSvc)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	spoolConfig := spool.DefaultConfig()
	spoolConfig.Dir = t.TempDir()
	spoolConfig.Session = fleetagent.SessionID("session-1")
	spoolConfig.Boot = fleetagent.BootID("boot-1")
	durable, err := spool.Open(spoolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = durable.Close() })
	sink, err := agentspool.NewDetectionSink(durable)
	if err != nil {
		t.Fatal(err)
	}
	first := mkTestDetection(t, agentID)
	second := mkTestDetection(t, agentID)
	second.Observed = second.Observed.Add(time.Second)
	second.Evidence[0].At = second.Evidence[0].At.Add(time.Second)
	second.Evidence[0].Process.PID++
	if err := sink.Emit(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := sink.Emit(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	client := fleetclient.New(server.URL, 5*time.Second)
	shipper, err := detectionship.NewService(durable, client, agentstate.NewDetectionStore(t.TempDir()), detectionship.Config{
		AgentID: agentID, EngagementID: shared.ID("eng-1"), Token: token,
		Now: time.Now, Retry: func(error, uint) (bool, time.Duration) { return false, 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	delivered, err := shipper.DeliverOnce(context.Background())
	if err != nil || !delivered {
		t.Fatalf("DeliverOnce delivered=%v err=%v", delivered, err)
	}

	tenantCtx := shared.WithTenant(context.Background(), enrolTenant)
	stored, err := records.ListDetections(tenantCtx, "eng-1")
	if err != nil || len(stored) != 2 {
		t.Fatalf("stored detections=%d err=%v", len(stored), err)
	}
	keys, err := keyStore.ListByAgent(tenantCtx, agentID)
	if err != nil || len(keys) != 1 || keys[0].Purpose != fleetagent.PurposeDetectionBatch {
		t.Fatalf("registered keys=%#v err=%v", keys, err)
	}
	stats, err := durable.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, lane := range stats.Priorities {
		if lane.Priority == fleetagent.PriorityP1 && lane.Records != 0 {
			t.Fatalf("delivered detection WAL still has %d records", lane.Records)
		}
	}
}
