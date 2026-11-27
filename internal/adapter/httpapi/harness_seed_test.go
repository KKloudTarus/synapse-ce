package httpapi

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
	siemuc "github.com/KKloudTarus/synapse-ce/internal/usecase/siem"
	usersuc "github.com/KKloudTarus/synapse-ce/internal/usecase/users"
)

// The hostile harness's generated cross-tenant sweep proves a real absence only on a route whose
// handler can run and answers tenantA with its own seeded data. Every route that cannot run, or that
// answers tenantA nothing, proves less. A seed raises that count for one group of routes: it wires
// the subsystem the group needs into the router and plants tenantA data the group's routes serve.
//
// A seed lives in its own file and registers itself from init, so groups never touch each other or
// the harness body:
//
//	func init() {
//		registerHarnessSeed(harnessSeed{
//			Name:   "findings",
//			Routes: []string{"GET /api/v1/engagements/{id}/findings"},
//			Run:    seedFindings,
//		})
//	}
//
// Routes lists the route patterns, exactly as the route table registers them, that the seed makes
// serve tenantA its own data. The sweep fails and names the route when one of them does not, so a
// seed that stopped reaching its routes cannot pass quietly. That is the check that matters when two
// seeds touch the same Router field and the later one replaces the earlier.
//
// A route whose parameter has no value cannot be addressed at all. A seed that plants the record
// names its id in PathValues, and a route the sweep still cannot address fails the test unless
// harnessKnownUnaddressable lists it with a reason, so no route drops out of the sweep unseen.
//
// A parameter name does not say what it names: "{id}" is an engagement under /engagements but an
// integration under /integrations and a sink under /siem/sinks. A seed whose record sits behind such
// a shared name declares the id for its own routes in RoutePathValues, which wins over every other
// value for those routes and leaves the parameter's meaning everywhere else alone:
//
//	RoutePathValues: map[string]map[string]string{
//		"GET /api/v1/integrations/{id}": {"{id}": "integration-A"},
//	},
//
// Rules for a seed:
//   - It runs before the route table is built, so a rt.SetX call it makes also registers any route
//     that SetX enables.
//   - It plants data under tenantA only, and returns markers: strings that appear in a response
//     only when tenantA's data was served. A tenantB response must never contain one.
//   - Prefer the real in-memory use case over a stand-in. A stand-in must return tenantA's marker
//     for every caller, so a missing tenant guard shows up as a leak instead of hiding behind a
//     stand-in that filters by tenant itself.
//   - It must not read or change another seed's data. State two seeds must share goes through
//     harnessWorld.state, and a seed that needs it must also work when it is absent.

// harnessWorld is what a seed may read. The engagements engA (tenantA) and engB (tenantB) and the
// project "project-a" (tenantA) already exist.
type harnessWorld struct {
	t           *testing.T
	rt          *Router
	engagements *memory.EngagementRepository
	engSvc      *enguc.Service
	projectRepo *memory.ProjectRepository
	projects    *projectuc.Service
	analyses    *memory.ProjectAnalysisStore
	assets      *memory.AssetStore
	users       *usersuc.Service
	userRepo    *memory.UserRepository
	audit       *harnessAudit
	// siem is the store behind the fixture's SIEM service. The fixture wires that service itself,
	// because its own SIEM checks read a sealed secret back out of this store, so a seed plants a
	// sink in this store rather than replacing the router's service.
	siem *siemuc.Memory
	// assessmentCycleAPI is the fixture's assessment cycle service and assessmentCycles the store behind
	// it. The fixture's own checks read cycle-A through that service, so a seed plants its cycles in
	// this store and wires further dependencies onto this service rather than replacing it.
	assessmentCycleAPI *cycleuc.APIService
	assessmentCycles   *memory.AssessmentCycleRepository

	// state carries what one seed leaves for another. Some services take their stores only through
	// their constructor, so two seeds cannot each build one without the later replacing the earlier
	// and silently emptying its routes. Seeds run in name order; a seed that finds nothing under a
	// key builds the service without it.
	state map[string]any
}

// harnessSeed describes one group of routes and how to make them serve tenantA's data.
type harnessSeed struct {
	// Name orders the seeds and names a seed in a failure.
	Name string
	// Routes are the patterns this seed makes serve tenantA its own data.
	Routes []string
	// TenantBound lists routes whose use case reads the tenant from the request context, as the
	// production auth middleware sets it, rather than from the principal. The sweep binds the tenant
	// into the context for those routes only: binding it everywhere would let a store that scopes by
	// context hide a missing route guard on routes that do not need it.
	TenantBound []string
	// Queries maps a route to the query string it needs before it reads anything, for example
	// "?path=README.md". The sweep appends it to the concrete path.
	Queries map[string]string
	// PathValues maps a route parameter, braces included ("{did}"), to the id of the record the seed
	// planted for it. The sweep cannot address a route whose parameter has no value, and counts that
	// route as unaddressable; a seed that plants the record names the id here instead of every id
	// living in harnessPathValues.
	PathValues map[string]string
	// RoutePathValues maps a route pattern, exactly as the route table registers it, to the value of
	// each parameter on that route, braces included. A value here takes precedence over
	// harnessPathValues and over every seed's PathValues, for that route only. The sweep fails for
	// a value declared on a route the table does not register, or for a parameter the route does not
	// carry, so a renamed route cannot leave its value behind unseen.
	RoutePathValues map[string]map[string]string
	// ForeignDenied lists routes whose response carries nothing that names the tenant, so a marker
	// check cannot tell tenantA's data from tenantB's. For those the sweep requires the route to
	// refuse a foreign caller with 403 or 404, which proves the guard instead of the data.
	ForeignDenied []string
	// Run wires the subsystem, plants the data and returns the markers.
	Run func(w *harnessWorld) []string
}

var harnessSeeds []harnessSeed

// registerHarnessSeed adds one group's seed. Call it from init in the group's own file.
func registerHarnessSeed(seed harnessSeed) {
	harnessSeeds = append(harnessSeeds, seed)
}

// sortedHarnessSeeds returns the registered seeds in name order, so the route table and the markers
// do not depend on file or init order.
func sortedHarnessSeeds() []harnessSeed {
	seeds := append([]harnessSeed(nil), harnessSeeds...)
	sort.Slice(seeds, func(i, j int) bool { return seeds[i].Name < seeds[j].Name })
	return seeds
}

// runHarnessSeeds runs every registered seed in name order and returns the markers they planted.
func runHarnessSeeds(w *harnessWorld) []string {
	var markers []string
	for _, seed := range sortedHarnessSeeds() {
		markers = append(markers, seed.Run(w)...)
	}
	return markers
}

// harnessExpectedRoutes maps each declared route to the seed that declared it.
func harnessExpectedRoutes() map[string]string {
	out := map[string]string{}
	for _, seed := range sortedHarnessSeeds() {
		for _, route := range seed.Routes {
			out[route] = seed.Name
		}
	}
	return out
}

// harnessTenantBoundRoutes is the set of routes the sweep must probe with the tenant in the context.
func harnessTenantBoundRoutes() map[string]bool {
	out := map[string]bool{}
	for _, seed := range harnessSeeds {
		for _, route := range seed.TenantBound {
			out[route] = true
		}
	}
	return out
}

// harnessRouteQueries is the query string each route needs, keyed by route pattern.
func harnessRouteQueries() map[string]string {
	out := map[string]string{}
	for _, seed := range harnessSeeds {
		for route, query := range seed.Queries {
			out[route] = query
		}
	}
	return out
}

// harnessForeignDeniedRoutes is the set of routes that must refuse a foreign caller.
func harnessForeignDeniedRoutes() map[string]bool {
	out := map[string]bool{}
	for _, seed := range harnessSeeds {
		for _, route := range seed.ForeignDenied {
			out[route] = true
		}
	}
	return out
}

// harnessPathValue returns the id the sweep substitutes for a parameter of route: a value a seed
// declared for that route first, then the fixture's own value, then the one a seed declared for the
// parameter on every route.
func harnessPathValue(route, param string) (string, bool) {
	for _, seed := range sortedHarnessSeeds() {
		if value, ok := seed.RoutePathValues[route][param]; ok {
			return value, true
		}
	}
	if value, ok := harnessPathValues[param]; ok {
		return value, true
	}
	for _, seed := range sortedHarnessSeeds() {
		if value, ok := seed.PathValues[param]; ok {
			return value, true
		}
	}
	return "", false
}

// harnessRoutePathValueProblems names every route-specific value a seed declared on a route the
// table does not register, or for a parameter that route does not carry.
func harnessRoutePathValueProblems(registered map[string]bool) []string {
	var problems []string
	for _, seed := range sortedHarnessSeeds() {
		for route, values := range seed.RoutePathValues {
			if !registered[route] {
				problems = append(problems, fmt.Sprintf("seed %q declares a path value for %s, which the route table does not register", seed.Name, route))
				continue
			}
			for param := range values {
				if !strings.Contains(route, param) {
					problems = append(problems, fmt.Sprintf("seed %q declares %s for %s, which carries no such parameter", seed.Name, param, route))
				}
			}
		}
	}
	sort.Strings(problems)
	return problems
}
