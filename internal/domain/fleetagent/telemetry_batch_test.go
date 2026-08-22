package fleetagent

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func validManifest() TelemetryBatchManifest {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	return TelemetryBatchManifest{
		ProtocolVersion:      TelemetryProtocolVersion,
		SchemaVersion:        1,
		BatchID:              "batch-1",
		AgentID:              "agent-1",
		AssetID:              "asset-1",
		StreamID:             "stream-1",
		Position:             StreamPosition{Priority: PriorityP1, Epoch: 1, Sequence: 5, Session: "sess-1", Boot: "boot-1"},
		PreviousSequence:     4,
		EventTimeMin:         t0,
		EventTimeMax:         t0.Add(time.Second),
		ObservedCount:        3,
		KeptCount:            2,
		SampledOutCount:      1,
		SamplingPolicyDigest: "spd",
		Events: []EventRef{
			{ID: "e2", Digest: "d2"},
			{ID: "e1", Digest: "d1"},
		},
		PayloadDigest: "payload-digest",
		KeyID:         "key-1",
	}
}

func TestTelemetryManifestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*TelemetryBatchManifest)
		wantErr bool
	}{
		{"valid", func(*TelemetryBatchManifest) {}, false},
		{"no protocol", func(m *TelemetryBatchManifest) { m.ProtocolVersion = 0 }, true},
		{"no schema", func(m *TelemetryBatchManifest) { m.SchemaVersion = 0 }, true},
		{"no batch id", func(m *TelemetryBatchManifest) { m.BatchID = "" }, true},
		{"no agent id", func(m *TelemetryBatchManifest) { m.AgentID = "" }, true},
		{"no asset id", func(m *TelemetryBatchManifest) { m.AssetID = "" }, true},
		{"no stream id", func(m *TelemetryBatchManifest) { m.StreamID = "" }, true},
		{"bad position (epoch 0)", func(m *TelemetryBatchManifest) { m.Position.Epoch = 0 }, true},
		{"prev >= current seq", func(m *TelemetryBatchManifest) { m.PreviousSequence = 5 }, true},
		{"no key id", func(m *TelemetryBatchManifest) { m.KeyID = "" }, true},
		{"no payload digest", func(m *TelemetryBatchManifest) { m.PayloadDigest = "" }, true},
		{"time max before min", func(m *TelemetryBatchManifest) { m.EventTimeMax = m.EventTimeMin.Add(-time.Hour) }, true},
		{"negative count", func(m *TelemetryBatchManifest) { m.DroppedCount = -1 }, true},
		{"kept+lost exceeds observed", func(m *TelemetryBatchManifest) { m.DroppedCount = 5 }, true},
		{"events count != kept", func(m *TelemetryBatchManifest) { m.KeptCount = 3 }, true},
		{"event missing id", func(m *TelemetryBatchManifest) { m.Events[0].ID = "" }, true},
		{"event missing digest", func(m *TelemetryBatchManifest) { m.Events[0].Digest = "" }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := validManifest()
			tt.mutate(&m)
			err := m.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err=%v wantErr=%t", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("error must wrap shared.ErrValidation, got %v", err)
			}
		})
	}
}

func TestTelemetryManifestMessageOrderIndependent(t *testing.T) {
	a := validManifest()
	b := validManifest()
	b.Events = []EventRef{{ID: "e1", Digest: "d1"}, {ID: "e2", Digest: "d2"}} // reversed input order
	if string(TelemetryManifestMessage(a)) != string(TelemetryManifestMessage(b)) {
		t.Fatal("manifest message must be independent of event input order (sorted)")
	}
	// AgentSessionID is the position session.
	if a.AgentSessionID() != "sess-1" {
		t.Fatalf("AgentSessionID() = %q", a.AgentSessionID())
	}
}

func TestTelemetryManifestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	m := validManifest()
	m.Signature = SignTelemetryManifest(priv, m)
	if err := VerifyTelemetryManifest(pub, m); err != nil {
		t.Fatalf("valid signature must verify: %v", err)
	}
	// Tamper: any bound field change breaks the signature.
	for _, mut := range []func(*TelemetryBatchManifest){
		func(m *TelemetryBatchManifest) { m.Position.Sequence = 6 },
		func(m *TelemetryBatchManifest) { m.PayloadDigest = "other" },
		func(m *TelemetryBatchManifest) { m.Events[0].Digest = "tampered" },
		func(m *TelemetryBatchManifest) { m.DroppedCount = 1; m.SampledOutCount = 0 },
		func(m *TelemetryBatchManifest) { m.KeyID = "swapped" },
	} {
		tampered := validManifest()
		tampered.Signature = m.Signature
		mut(&tampered)
		if err := VerifyTelemetryManifest(pub, tampered); !errors.Is(err, ErrBadManifestSignature) {
			t.Fatalf("tampered manifest must fail verification, got %v", err)
		}
	}
}

func TestVerifyTelemetryManifestWithKeyFailClosed(t *testing.T) {
	now := time.Unix(1_700_000_100, 0).UTC()
	pub, priv, _ := ed25519.GenerateKey(nil)
	key, err := NewSigningKey("agent-1", PurposeTelemetryBatch, pub, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	m := validManifest()
	m.KeyID = key.KeyID
	m.Signature = SignTelemetryManifest(priv, m)

	if err := VerifyTelemetryManifestWithKey(key, now, m); err != nil {
		t.Fatalf("well-formed manifest+key must verify: %v", err)
	}

	// Wrong purpose → forbidden.
	wrongPurpose, _ := NewSigningKey("agent-1", PurposeDetectionBatch, pub, now.Add(-time.Hour), now.Add(time.Hour))
	if err := VerifyTelemetryManifestWithKey(wrongPurpose, now, withKeyID(m, wrongPurpose.KeyID, priv)); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("wrong-purpose key must be forbidden, got %v", err)
	}
	// Key bound to a different agent → forbidden.
	otherAgent, _ := NewSigningKey("agent-2", PurposeTelemetryBatch, pub, now.Add(-time.Hour), now.Add(time.Hour))
	if err := VerifyTelemetryManifestWithKey(otherAgent, now, m); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("agent-mismatched key must be forbidden, got %v", err)
	}
	// Manifest names a different key id than the one verifying → bad signature.
	mismatch := m
	mismatch.KeyID = "some-other-key"
	if err := VerifyTelemetryManifestWithKey(key, now, mismatch); !errors.Is(err, ErrBadManifestSignature) {
		t.Fatalf("keyid mismatch must fail closed, got %v", err)
	}
	// Expired key → not usable.
	if err := VerifyTelemetryManifestWithKey(key, now.Add(2*time.Hour), m); err == nil {
		t.Fatal("expired key must fail closed")
	}
}

func withKeyID(m TelemetryBatchManifest, keyID string, priv ed25519.PrivateKey) TelemetryBatchManifest {
	m.KeyID = keyID
	m.Signature = SignTelemetryManifest(priv, m)
	return m
}
