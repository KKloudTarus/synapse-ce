package httpapi

import (
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/writeup"
)

// listWriteups returns the built-in finding-writeup library. It is static
// reference data the UI uses to pre-fill the manual-finding form, so it needs no
// engagement context and no service – the domain owns the catalog.
func (rt *Router) listWriteups(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, writeup.Catalog())
}
