package jsreach

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// The analyzer takes narrow consumer-side interfaces rather than importing ports into production code.
// These assertions keep them from drifting away from the ports they are meant to narrow, which would
// otherwise only surface when the composition root wires them.
func TestLocalInterfacesMatchThePorts(t *testing.T) {
	var (
		_ importScanner  = ports.JSImportScanner(nil)
		_ importResolver = ports.JSImportResolver(nil)
	)
}
