package httpapi

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	siemuc "github.com/KKloudTarus/synapse-ce/internal/usecase/siem"
)

// siemSinksMarker appears in the body of a SIEM sink route only when tenantA's own sink was served:
// it is the sink's name. It is distinct from every identifier the other seeds plant and from the
// name of the sink the fixture's own SIEM checks create, and a tenantB response must never contain
// it.
const siemSinksMarker = "tenantA-siem-seed-marker"

// siemSinksSink is the id of the one sink this seed plants. The seed's service takes ids from a
// generator of its own, so this is the first id it hands out; Run fails if the sink comes back under
// another one.
const siemSinksSink = shared.ID("siem-seed-sink-1")

func init() {
	routes := []string{
		"GET /api/v1/siem/sinks/{id}",
		"GET /api/v1/siem/sinks/{id}/status",
	}
	// "{id}" is an engagement on most routes; on these it is the sink.
	values := map[string]map[string]string{}
	for _, route := range routes {
		values[route] = map[string]string{"{id}": siemSinksSink.String()}
	}
	registerHarnessSeed(harnessSeed{
		Name:            "siem",
		Routes:          routes,
		RoutePathValues: values,
		Run:             seedSIEMSinks,
	})
}

// seedSIEMSinks plants one tenantA sink in the store behind the fixture's SIEM service. The fixture
// wires that service before the seeds run, and its own SIEM checks read a sealed secret back out of
// the store, so this seed does not replace the router's service. It creates the sink through a
// second service over the same store instead, the way a second API process over one database
// would, so the row takes the path a create request takes and gets an id this seed controls.
//
// No route here has a guard of its own: the handler passes the caller's tenant in the context, and
// the store keys every sink by it. That key is what stands between tenantB and this sink.
func seedSIEMSinks(w *harnessWorld) []string {
	t := w.t
	t.Helper()
	if w.siem == nil {
		t.Fatal("the fixture wires no SIEM store; the siem seed plants its sink there")
	}
	service, err := siemuc.NewService(w.siem, w.siem, w.siem, harnessSIEMSealer{harnessSIEMCipher(t)},
		map[siem.Provider]ports.SIEMDriver{siem.ProviderSplunk: harnessSIEMDriver{}}, nil,
		siemClock{now: time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)}, &siemSinksIDs{}, testSIEMSchema(t))
	if err != nil {
		t.Fatalf("siem seed service: %v", err)
	}
	sink, err := service.Create(shared.WithTenant(context.Background(), "tenantA"), "siem-seed-admin", siemuc.SinkInput{
		Name: "sink " + siemSinksMarker, NamePresent: true, Provider: siem.ProviderSplunk, ProviderPresent: true,
		Origin: "https://splunk-seed-a.example:8088", OriginPresent: true, Secret: "splunk-seed-token",
	})
	if err != nil {
		t.Fatalf("seed siem sink: %v", err)
	}
	if sink.ID != siemSinksSink {
		t.Fatalf("planted siem sink %s, but the routes are addressed with %s", sink.ID, siemSinksSink)
	}
	return []string{siemSinksMarker}
}

// siemSinksIDs hands out the ids of the sinks this seed creates.
type siemSinksIDs struct{ n int }

func (g *siemSinksIDs) NewID() shared.ID {
	g.n++
	return shared.ID(fmt.Sprintf("siem-seed-sink-%d", g.n))
}
