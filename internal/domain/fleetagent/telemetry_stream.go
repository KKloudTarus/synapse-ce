package fleetagent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TelemetryDeliveryStreamID derives the server-verifiable identity of one A2 telemetry
// delivery lane. A2 sequence/Epoch coordinates are per priority lane, while an individual
// TelemetryEnvelope.StreamID identifies its sensor/class provenance; the two are deliberately
// distinct. Binding the lane to agent + enrollment session + priority prevents a producer from
// choosing an arbitrary stream namespace to evade ACK/replay state.
func TelemetryDeliveryStreamID(agentID shared.ID, session SessionID, priority DeliveryPriority) (shared.ID, error) {
	if agentID.IsZero() || session == "" {
		return "", fmt.Errorf("%w: telemetry delivery stream needs agent and session identity", shared.ErrValidation)
	}
	if !priority.Valid() {
		return "", fmt.Errorf("%w: unknown telemetry delivery priority %d", shared.ErrValidation, int(priority))
	}
	h := sha256.New()
	writeTelemetryCommitField(h, "synapse-telemetry-delivery-stream:v1")
	writeTelemetryCommitField(h, agentID.String())
	writeTelemetryCommitField(h, string(session))
	writeTelemetryCommitField(h, strconv.Itoa(int(priority)))
	sum := h.Sum(nil)
	return shared.ID("tds_" + hex.EncodeToString(sum[:16])), nil
}

// TelemetryDeliveryKey is the A3 idempotency key for one event position. Unlike the
// older generic DeliveryKey it explicitly commits the authenticated enrollment session
// and server-derived delivery stream, so a sequence reset in a new incarnation cannot
// alias another lane or session. eventIndex remains explicit for future batches that may
// carry more than one event at a delivery sequence; current A2 telemetry uses index zero.
func TelemetryDeliveryKey(agentID shared.ID, session SessionID, streamID shared.ID, priority DeliveryPriority, epoch, sequence uint64, eventIndex int) (string, error) {
	if agentID.IsZero() || session == "" || streamID.IsZero() || !priority.Valid() || epoch == 0 || sequence == 0 || eventIndex < 0 {
		return "", fmt.Errorf("%w: telemetry delivery key coordinates are incomplete", shared.ErrValidation)
	}
	h := sha256.New()
	writeTelemetryCommitField(h, "synapse-telemetry-delivery-key:v1")
	writeTelemetryCommitField(h, agentID.String())
	writeTelemetryCommitField(h, string(session))
	writeTelemetryCommitField(h, streamID.String())
	writeTelemetryCommitField(h, strconv.Itoa(int(priority)))
	writeTelemetryCommitField(h, strconv.FormatUint(epoch, 10))
	writeTelemetryCommitField(h, strconv.FormatUint(sequence, 10))
	writeTelemetryCommitField(h, strconv.Itoa(eventIndex))
	return hex.EncodeToString(h.Sum(nil)), nil
}

type telemetryHashWriter interface {
	Write([]byte) (int, error)
}

func writeTelemetryCommitField(h telemetryHashWriter, value string) {
	_, _ = h.Write([]byte(strconv.Itoa(len(value))))
	_, _ = h.Write([]byte{':'})
	_, _ = h.Write([]byte(value))
}
