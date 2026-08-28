package fleetagent

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func testSensorStateReport(t *testing.T) (SensorStateReport, ed25519.PrivateKey, AgentSigningKey) {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	at := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	report := SensorStateReport{
		ProtocolVersion: TelemetryProtocolVersion,
		ReportID:        "report-1",
		AgentID:         "agent-1",
		HostID:          "agent-1",
		AgentSessionID:  CanonicalSessionID("agent-1"),
		AssetID:         "asset-1",
		Kind:            "sensor_state",
		ObservedAt:      at,
		SchemaVersion:   1,
		PayloadDigest:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		KeyID:           "key-1",
		States: []detection.ClassCoverage{{
			Class: detection.ClassProcess, HostID: "agent-1", AgentID: "agent-1", State: detection.StateActive, Since: at,
		}},
	}
	key, err := NewSigningKey("agent-1", PurposeTelemetryBatch, pub, at.Add(-time.Hour), at.Add(time.Hour))
	if err != nil {
		t.Fatalf("create signing key: %v", err)
	}
	report.KeyID = key.KeyID
	report.Signature = SignSensorState(private, report)
	return report, private, key
}

func TestSensorStateReportSignatureUsesBoundFields(t *testing.T) {
	report, _, key := testSensorStateReport(t)
	if err := report.Validate(); err != nil {
		t.Fatalf("validate signed report: %v", err)
	}
	if err := VerifySensorStateWithKey(key, report.ObservedAt, report); err != nil {
		t.Fatalf("verify signed report: %v", err)
	}

	report.AssetID = shared.ID("other-asset")
	if err := VerifySensorStateWithKey(key, report.ObservedAt, report); !errors.Is(err, ErrBadSensorStateSignature) {
		t.Fatalf("verify altered report error = %v, want bad signature", err)
	}
}

func TestSensorStateReportRejectsWrongSigningPurpose(t *testing.T) {
	report, _, key := testSensorStateReport(t)
	key.Purpose = PurposeDetectionBatch
	if err := VerifySensorStateWithKey(key, report.ObservedAt, report); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("verify wrong-purpose key error = %v, want forbidden", err)
	}
}

func TestSensorStateSignatureUsesDistinctContext(t *testing.T) {
	report, private, _ := testSensorStateReport(t)
	gap := TelemetryGapReport{
		ProtocolVersion: TelemetryProtocolVersion,
		GapID:           "report-1", AgentID: "agent-1", HostID: "agent-1", AgentSessionID: CanonicalSessionID("agent-1"), AssetID: "asset-1",
		StreamID: "stream-1", Priority: PriorityP0, Epoch: 1, KnownSequence: true, FromSequence: 1, ToSequence: 1, Count: 1,
		Reason: TelemetryGapQuotaEviction, FromAt: report.ObservedAt, ToAt: report.ObservedAt, KeyID: report.KeyID,
	}
	gap.Signature = SignSensorState(private, report)
	if err := VerifyTelemetryGap(private.Public().(ed25519.PublicKey), gap); !errors.Is(err, ErrBadTelemetryGapSignature) {
		t.Fatalf("sensor-state signature verified as a gap signature: %v", err)
	}
}
