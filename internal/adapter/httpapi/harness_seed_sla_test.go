package httpapi

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// slaSeedMarker appears in the body of an SLA or vulnerability route only when tenantA's own row was
// served. It is distinct from every identifier the other seeds plant, and a tenantB response must
// never contain it.
const slaSeedMarker = "tenantA-sla-marker"

// slaSeedNow is the instant every row planted by this seed carries, so the responses are stable.
var slaSeedNow = time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)

// The sweep fills each path parameter with a fixed value (harnessPathValues), so the planted rows
// must carry exactly them.
const (
	slaSeedEngagement = shared.ID("engA")
	slaSeedFinding    = shared.ID("f1")
)

func init() {
	routes := []string{
		"GET /api/v1/engagements/{id}/slas",
		"GET /api/v1/engagements/{id}/slas/{fid}",
		"GET /api/v1/engagements/{id}/slas/{fid}/assessments",
		"GET /api/v1/engagements/{id}/slas/{fid}/events",
		"GET /api/v1/engagements/{id}/vulnerability/actions",
		"GET /api/v1/engagements/{id}/vulnerability/occurrences",
	}
	registerHarnessSeed(harnessSeed{
		Name:   "sla",
		Routes: routes,
		// Every use case behind these routes reads the tenant from the request context and refuses a
		// request whose path tenant disagrees with it, as the production auth middleware sets it.
		TenantBound: routes,
		Run:         seedSLA,
	})
}

// seedSLA wires the SLA governance service and the vulnerability action and read services over
// their in-memory stores and plants one tenantA row in each. The subsystems share nothing but the
// world, so a failure names the one that broke.
func seedSLA(w *harnessWorld) []string {
	w.t.Helper()
	seedSLAGovernance(w)
	seedSLAVulnerability(w)
	return []string{slaSeedMarker}
}

// slaSeedTenantCtx is the context a store write needs: the memory stores read the tenant from it.
func slaSeedTenantCtx() context.Context {
	return shared.WithTenant(context.Background(), "tenantA")
}

// slaSeedClock hands out the fixed seed instant.
type slaSeedClock struct{}

func (slaSeedClock) Now() time.Time { return slaSeedNow }

// slaSeedIDs hands out distinct ids, so two rows planted through one use case never collide.
type slaSeedIDs struct{ n int }

func (g *slaSeedIDs) NewID() shared.ID {
	g.n++
	return shared.ID(fmt.Sprintf("sla-seed-id-%d", g.n))
}
