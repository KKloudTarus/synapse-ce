package httpapi

import (
	"net/http"
)

// Request-body ceilings for the human API plane. The agent plane sets its own caps in
// fleet_handler.go.
//
// These are transport ceilings, not validation. A handler may nest its own
// http.MaxBytesReader inside this one, but nesting can only ever TIGHTEN the bound: the
// outer reader counts every byte the inner one pulls, so a handler that wraps the body in a
// larger reader still stops at the ceiling chosen here. Any route whose handler legitimately
// accepts more than defaultBodyLimit must therefore be listed in routeBodyLimits, and
// TestMultipartRoutesCarryAnUploadCeiling fails if one is not.
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
	// Engagement and project creation both accept a multipart source archive on the same
	// route that otherwise takes a small JSON body. The JSON branch of each handler bounds
	// itself, so the large ceiling applies only to the upload it exists for.
	"POST /api/v1/engagements":               sourceUploadBodyLimit,
	"POST /api/v1/projects":                  sourceUploadBodyLimit,
	"POST /api/v1/projects/{key}/analyses":   importBodyLimit,
	"POST /api/v1/engagements/import":        importBodyLimit,
	"POST /api/v1/engagements/{id}/sarif":    importBodyLimit,
	"POST /api/v1/engagements/{id}/sbom":     importBodyLimit,
	"POST /api/v1/engagements/{id}/evidence": importBodyLimit,
	// An OpenVEX document is a whole file produced elsewhere; the handler bounds it at 8 MiB.
	"POST /api/v1/engagements/{id}/vex": importBodyLimit,
	// The threat-model routes are deliberately absent. Their handler bounds the body at 1 MiB,
	// which is the default, so an entry here would advertise a ceiling that never takes effect.
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
