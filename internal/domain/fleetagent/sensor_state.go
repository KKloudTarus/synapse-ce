package fleetagent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const sensorStateContext = "synapse-fleet-sensor-state:v1"

var ErrBadSensorStateSignature = fmt.Errorf("bad sensor-state signature")

// SensorStateReport is a signed, self-contained P0 sensor-state/coverage record.
// It deliberately uses the existing telemetry signing key, but a separate message
// context prevents replay as a raw telemetry batch or spool gap.
type SensorStateReport struct {
	ProtocolVersion int
	ReportID        shared.ID
	AgentID         shared.ID
	HostID          shared.ID
	AgentSessionID  SessionID
	AssetID         shared.ID
	Kind            string
	ObservedAt      time.Time
	SchemaVersion   int
	PayloadDigest   string
	States          []detection.ClassCoverage
	KeyID           string
	Signature       string
}

func (r SensorStateReport) Validate() error {
	if r.ProtocolVersion != TelemetryProtocolVersion || r.ReportID.IsZero() || r.AgentID.IsZero() || r.HostID.IsZero() || r.AgentSessionID == "" || r.AssetID.IsZero() {
		return fmt.Errorf("%w: sensor-state report has invalid identity or protocol", shared.ErrValidation)
	}
	if r.Kind != "coverage" && r.Kind != "sensor_state" {
		return fmt.Errorf("%w: sensor-state report has invalid kind %q", shared.ErrValidation, r.Kind)
	}
	if r.ObservedAt.IsZero() || r.SchemaVersion <= 0 || len(r.PayloadDigest) != sha256.Size*2 || r.KeyID == "" || r.Signature == "" {
		return fmt.Errorf("%w: sensor-state report has invalid required fields", shared.ErrValidation)
	}
	if _, err := base64.StdEncoding.DecodeString(r.Signature); err != nil {
		return fmt.Errorf("%w: sensor-state report has malformed signature", shared.ErrValidation)
	}
	if len(r.States) == 0 {
		return fmt.Errorf("%w: sensor-state report has no states", shared.ErrValidation)
	}
	seen := map[detection.Class]struct{}{}
	for _, state := range r.States {
		if err := state.Validate(); err != nil {
			return err
		}
		if state.HostID != r.HostID || (state.AgentID != "" && state.AgentID != r.AgentID) {
			return fmt.Errorf("%w: sensor-state class identity disagrees with report", shared.ErrValidation)
		}
		if _, exists := seen[state.Class]; exists {
			return fmt.Errorf("%w: sensor-state report repeats class %q", shared.ErrValidation, state.Class)
		}
		seen[state.Class] = struct{}{}
	}
	return nil
}

func SensorStateMessage(r SensorStateReport) []byte {
	h := sha256.New()
	write := func(value string) { writeTelemetryCommitField(h, value) }
	write(sensorStateContext)
	write(strconv.Itoa(r.ProtocolVersion))
	write(r.ReportID.String())
	write(r.AgentID.String())
	write(r.HostID.String())
	write(string(r.AgentSessionID))
	write(r.AssetID.String())
	write(r.Kind)
	write(strconv.FormatInt(r.ObservedAt.UTC().UnixNano(), 10))
	write(strconv.Itoa(r.SchemaVersion))
	write(r.PayloadDigest)
	for _, state := range r.States {
		write(string(state.Class))
		write(state.HostID.String())
		write(state.AgentID.String())
		write(string(state.State))
		write(state.Reason)
		write(strconv.FormatInt(state.Since.UTC().UnixNano(), 10))
	}
	write(r.KeyID)
	return h.Sum(nil)
}

func SignSensorState(private ed25519.PrivateKey, r SensorStateReport) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(private, SensorStateMessage(r)))
}

func VerifySensorState(pub ed25519.PublicKey, r SensorStateReport) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bad public key size", ErrBadSensorStateSignature)
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed signature", ErrBadSensorStateSignature)
	}
	if !ed25519.Verify(pub, SensorStateMessage(r), sig) {
		return ErrBadSensorStateSignature
	}
	return nil
}

func VerifySensorStateWithKey(k AgentSigningKey, now time.Time, r SensorStateReport) error {
	if k.Purpose != PurposeTelemetryBatch {
		return fmt.Errorf("%w: signing key %s is for %q, not %q", shared.ErrForbidden, k.KeyID, k.Purpose, PurposeTelemetryBatch)
	}
	if k.AgentID != r.AgentID {
		return fmt.Errorf("%w: signing key %s is bound to agent %s, not %s", shared.ErrForbidden, k.KeyID, k.AgentID, r.AgentID)
	}
	if r.KeyID != k.KeyID {
		return fmt.Errorf("%w: sensor-state report names key %s but was verified against %s", ErrBadSensorStateSignature, r.KeyID, k.KeyID)
	}
	if err := k.UsableAt(now); err != nil {
		return err
	}
	return VerifySensorState(k.PublicKey, r)
}
