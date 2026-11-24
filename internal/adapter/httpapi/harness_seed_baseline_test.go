package httpapi

// The "baseline" seed plants nothing. It declares the five routes the fixture itself serves tenantA's
// data on (the engagement, its detections, judgments and purple coverage, and the project), so they
// are held by name like every other declared route instead of by a count.
func init() {
	registerHarnessSeed(harnessSeed{
		Name: "baseline",
		Routes: []string{
			"GET /api/v1/engagements/{id}",
			"GET /api/v1/engagements/{id}/detections",
			"GET /api/v1/engagements/{id}/judgments",
			"GET /api/v1/engagements/{id}/purple-coverage",
			"GET /api/v1/projects/{key}",
		},
		// The readiness body is a pure function of the engagement's flags and target kinds, so it
		// names no tenant and a marker cannot tell tenantA's answer from tenantB's. The guard is
		// proven by the refusal instead.
		ForeignDenied: []string{"GET /api/v1/engagements/{id}/agent/readiness"},
		Run:           func(*harnessWorld) []string { return nil },
	})
}
