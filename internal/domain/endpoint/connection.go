package endpoint

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ConnectionState is the lifecycle state of a projected network connection.
type ConnectionState string

const (
	// ConnectionObserved is a flow seen at least once. A1's NetworkObservation carries no close event or
	// byte counters yet, so "closed" and traffic volume are reserved for the sensor-side tail.
	ConnectionObserved ConnectionState = "observed"
)

// NetworkConnection is a process-attributed network flow reconstructed from network telemetry (B2). It is
// keyed by a stable ConnectionID so re-observing the same flow widens its last-seen time instead of
// creating a duplicate, and it links to the process that opened it by the A1 ProcessEntityID rather than a
// bare PID.
type NetworkConnection struct {
	ConnectionID    shared.ID
	TenantID        shared.ID
	AssetID         shared.ID
	ProcessEntityID shared.ID
	Proto           string
	Direction       string
	LocalAddr       string
	LocalPort       int
	RemoteAddr      string
	RemotePort      int
	Comm            string
	FirstSeenAt     time.Time
	LastSeenAt      time.Time
	State           ConnectionState
}

// Validate enforces a well-formed network connection.
func (c NetworkConnection) Validate() error {
	if c.ConnectionID.IsZero() {
		return fmt.Errorf("%w: network connection has no connection id", shared.ErrValidation)
	}
	if c.AssetID.IsZero() {
		return fmt.Errorf("%w: network connection has no asset id", shared.ErrValidation)
	}
	if c.State != ConnectionObserved {
		return fmt.Errorf("%w: network connection has unknown state %q", shared.ErrValidation, c.State)
	}
	return nil
}

func (c NetworkConnection) clone() NetworkConnection { return c }

// ConnectionID derives the stable identity of a flow from the tuple that distinguishes it on one asset:
// the originating process entity, protocol, direction, and the local/remote 5-tuple. Like the A1 entity
// ids it is a domain-separated sha256 over a LENGTH-PREFIXED encoding of the parts, so no field's content
// (an address, an empty local endpoint) can collide with another via a delimiter. Empty local endpoints
// (the sensor often sees only the connect target) simply hash as empty, which is stable.
func ConnectionID(assetID, processEntityID shared.ID, proto, direction, localAddr string, localPort int, remoteAddr string, remotePort int) shared.ID {
	sum := hashFields("endpoint:network-connection:v1",
		assetID.String(), processEntityID.String(), proto, direction,
		localAddr, strconv.Itoa(localPort), remoteAddr, strconv.Itoa(remotePort))
	return shared.ID("nc_" + sum[:32])
}

// hashFields returns the hex sha256 of a domain-separated, length-prefixed encoding of parts. It mirrors
// the telemetry entity-id construction so endpoint ids share the same collision-resistance discipline.
func hashFields(domain string, parts ...string) string {
	h := sha256.New()
	writeField(h, domain)
	for _, p := range parts {
		writeField(h, p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeField(h io.Writer, s string) {
	var lp [8]byte
	binary.BigEndian.PutUint64(lp[:], uint64(len(s)))
	_, _ = h.Write(lp[:])
	_, _ = io.WriteString(h, s)
}
