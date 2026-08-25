package fleetagent

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// CanonicalSessionID derives the stable A0.1 AgentSessionID from the server-minted enrolled AgentID.
// AgentID changes on re-enrol/reinstall, so the derived session changes with the enrollment session while
// remaining stable across ordinary process restarts. The value is not an authenticator: the control plane
// always recomputes it from the authenticated AgentID and rejects a wire value that disagrees.
func CanonicalSessionID(agentID shared.ID) SessionID {
	if agentID.IsZero() {
		return ""
	}
	sum := sha256.Sum256([]byte("synapse-agent-session:v1\x00" + agentID.String()))
	return SessionID("as_" + hex.EncodeToString(sum[:16]))
}
