package httpapi

import (
	"net/http"
)

// Request-body ceilings for the human API plane. The agent plane sets its own caps in
// fleet_handler.go. These are transport ceilings, not validation: a handler that needs a
// tighter bound still applies its own http.MaxBytesReader, and an inner reader nested in
// the outer one behaves correctly.
const (
	// defaultBodyLimit covers every JSON mutation route. 1 MiB is far above any request
	// body the API defines and small enough that an authenticated client cannot exhaust
	// server memory by streaming into a handler that reads the body eagerly.
	defaultBodyLimit = int64(1 << 20)
	// importBodyLimit covers routes that ingest a whole document produced elsewhere:
	// SARIF from a third-party scanner, a CycloneDX SBOM, an engagement bundle, a
	// captured evidence artifact.
	importBodyLimit = int64(64 << 20)
	// sourceUploadBodyLimit matches the ceiling the source publish handler already
	// enforces for a retained source archive (600 MiB, above the 500 MiB retention
	// budget so tar headers and padding fit).
	sourceUploadBodyLimit = int64(600 << 20)
)

// routeBodyLimits overrides defaultBodyLimit for the routes that legitimately carry a
// large body. Keys are ServeMux patterns exactly as registered in routes(), which
// annotateRoutePattern has already resolved onto the request by the time this middleware
// runs. An unknown pattern falls back to the default, so a new route is bounded from the
// moment it is registered.
var routeBodyLimits = map[string]int64{
	"POST /api/v1/projects/{key}/analyses/{id}/source": sourceUploadBodyLimit,
	"POST /api/v1/engagements/import":                  importBodyLimit,
	"POST /api/v1/engagements/{id}/sarif":              importBodyLimit,
	"POST /api/v1/engagements/{id}/sbom":               importBodyLimit,
	"POST /api/v1/engagements/{id}/evidence":           importBodyLimit,
	"POST /api/v1/engagements/{id}/threat-model":       importBodyLimit,
	"PUT /api/v1/engagements/{id}/threat-model":        importBodyLimit,
}

// bodyLimitFor returns the transport ceiling for a resolved route pattern.
func bodyLimitFor(pattern string) int64 {
	if limit, ok := routeBodyLimits[pattern]; ok {
		return limit
	}
	return defaultBodyLimit
}

// limitRequestBody bounds every request body on the human plane. Without it a handler
// that decodes eagerly reads whatever an authenticated client sends, so a single request
// can exhaust server memory. Methods that carry no body are passed through untouched.
func limitRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodDelete, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, bodyLimitFor(r.Pattern))
		}
		next.ServeHTTP(w, r)
	})
}
