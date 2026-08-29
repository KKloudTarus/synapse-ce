package fleetagent

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func sampleBatchV2() AgentBatchV2 {
	return AgentBatchV2{
		Context:      detectionBatchV2Context,
		Version:      2,
		AgentID:      "agent:1",
		EngagementID: "eng-1",
		Sequence:     3,
		KeyID:        "kid-1",
		Detections:   []DetectionRefV2{sampleDetectionRefV2("d1", "asset-1", "stream-1", 1, 7, "event-7")},
	}
}

func sampleDetectionRefV2(id, asset, stream string, epoch, sequence uint64, event string) DetectionRefV2 {
	return DetectionRefV2{
		ID:            shared.ID(id),
		ContentSHA256: strings.Repeat("a", 64),
		AssetID:       shared.ID(asset),
		TelemetryRefs: []TelemetryReference{{
			StreamID: shared.ID(stream),
			Epoch:    epoch,
			Sequence: sequence,
			EventID:  shared.ID(event),
			Digest:   strings.Repeat("b", 64),
		}},
		Rulepack: RulepackReference{
			ID:      "builtin",
			Version: 1,
			Digest:  strings.Repeat("c", 64),
		},
		RedactionPolicyDigest: strings.Repeat("d", 64),
	}
}

func TestSignVerifyBatchV2RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	batch := sampleBatchV2()
	batch.Signature = SignBatchV2(priv, batch)

	if err := VerifyBatchV2(pub, batch); err != nil {
		t.Fatalf("a validly signed v2 batch must verify: %v", err)
	}
}

func TestVerifyBatchV2RejectsBoundFieldTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	batch := unsortedBatchV2()
	batch.Signature = SignBatchV2(priv, batch)

	tampers := map[string]func(*AgentBatchV2){
		"agent":      func(b *AgentBatchV2) { b.AgentID = "agent:2" },
		"engagement": func(b *AgentBatchV2) { b.EngagementID = "eng-2" },
		"sequence":   func(b *AgentBatchV2) { b.Sequence++ },
		"key":        func(b *AgentBatchV2) { b.KeyID = "kid-2" },
		"add detection": func(b *AgentBatchV2) {
			b.Detections = append(b.Detections, sampleDetectionRefV2("d3", "asset-3", "stream-4", 4, 10, "event-10"))
		},
		"drop detection": func(b *AgentBatchV2) {
			b.Detections = b.Detections[:1]
		},
		"detection id": func(b *AgentBatchV2) { b.Detections[0].ID = "d3" },
		"content digest": func(b *AgentBatchV2) {
			b.Detections[0].ContentSHA256 = strings.Repeat("e", 64)
		},
		"asset": func(b *AgentBatchV2) { b.Detections[0].AssetID = "asset-3" },
		"telemetry stream": func(b *AgentBatchV2) {
			b.Detections[0].TelemetryRefs[0].StreamID = "stream-4"
		},
		"telemetry epoch":    func(b *AgentBatchV2) { b.Detections[0].TelemetryRefs[0].Epoch++ },
		"telemetry sequence": func(b *AgentBatchV2) { b.Detections[0].TelemetryRefs[0].Sequence++ },
		"telemetry event": func(b *AgentBatchV2) {
			b.Detections[0].TelemetryRefs[0].EventID = "event-10"
		},
		"telemetry digest": func(b *AgentBatchV2) {
			b.Detections[0].TelemetryRefs[0].Digest = strings.Repeat("e", 64)
		},
		"rulepack id":      func(b *AgentBatchV2) { b.Detections[0].Rulepack.ID = "custom" },
		"rulepack version": func(b *AgentBatchV2) { b.Detections[0].Rulepack.Version++ },
		"rulepack digest": func(b *AgentBatchV2) {
			b.Detections[0].Rulepack.Digest = strings.Repeat("e", 64)
		},
		"redaction policy": func(b *AgentBatchV2) {
			b.Detections[0].RedactionPolicyDigest = strings.Repeat("e", 64)
		},
	}
	for name, tamper := range tampers {
		t.Run(name, func(t *testing.T) {
			bad := cloneBatchV2(batch)
			tamper(&bad)

			if err := VerifyBatchV2(pub, bad); !errors.Is(err, ErrBadBatchSignature) {
				t.Fatalf("tampered v2 batch must fail verification, got %v", err)
			}
		})
	}
}

func TestVerifyBatchV2IsOrderIndependent(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	batch := unsortedBatchV2()
	batch.Signature = SignBatchV2(priv, batch)

	batch.Detections[0].TelemetryRefs[0], batch.Detections[0].TelemetryRefs[1] = batch.Detections[0].TelemetryRefs[1], batch.Detections[0].TelemetryRefs[0]
	batch.Detections[0], batch.Detections[1] = batch.Detections[1], batch.Detections[0]
	if err := VerifyBatchV2(pub, batch); err != nil {
		t.Fatalf("reordering v2 detections and telemetry references must verify: %v", err)
	}
}

func TestVerifyBatchV2RejectsMalformed(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	batch := sampleBatchV2()
	batch.Signature = SignBatchV2(priv, batch)

	cases := map[string]struct {
		publicKey ed25519.PublicKey
		signature string
	}{
		"bad-size public key": {
			publicKey: ed25519.PublicKey{1, 2, 3},
			signature: batch.Signature,
		},
		"invalid base64 signature": {
			publicKey: pub,
			signature: "not-base64!!",
		},
		"wrong-length decoded signature": {
			publicKey: pub,
			signature: "AQI=",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			bad := batch
			bad.Signature = tc.signature
			if err := VerifyBatchV2(tc.publicKey, bad); !errors.Is(err, ErrBadBatchSignature) {
				t.Fatalf("malformed v2 batch must fail closed, got %v", err)
			}
		})
	}
}

func TestBatchMessageV2RejectsUnsupportedVersion(t *testing.T) {
	batch := sampleBatchV2()
	batch.Version = 99
	if message := BatchMessageV2(batch); message != nil {
		t.Fatalf("unsupported batch version produced signing bytes: %x", message)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	batch.Signature = SignBatchV2(priv, batch)
	if err := VerifyBatchV2(pub, batch); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unsupported batch version verification error=%v, want validation", err)
	}
}

func TestBatchMessageV3RejectsLegacySeparatorAmbiguity(t *testing.T) {
	left := sampleBatchV2()
	left.Context = detectionBatchV3Context
	left.Version = 3
	left.AgentID = "agent:1\x1eeng"
	left.EngagementID = "engagement"

	right := sampleBatchV2()
	right.Context = detectionBatchV3Context
	right.Version = 3
	right.AgentID = "agent:1"
	right.EngagementID = "eng\x1eengagement"

	legacyLeft := left
	legacyLeft.Context = detectionBatchV2Context
	legacyLeft.Version = 2
	legacyRight := right
	legacyRight.Context = detectionBatchV2Context
	legacyRight.Version = 2
	if !bytes.Equal(batchMessageV2Legacy(legacyLeft), batchMessageV2Legacy(legacyRight)) {
		t.Fatal("fixture does not reproduce the legacy adjacent-field framing ambiguity")
	}
	if bytes.Equal(BatchMessageV2(left), BatchMessageV2(right)) {
		t.Fatal("v3 length-prefixed framing did not distinguish ambiguous legacy layouts")
	}
}

func TestBatchMessageV2RegressionFixture(t *testing.T) {
	// BatchMessageV2 returns the SHA-256 input passed to ed25519.Sign. Unsorted fixed inputs exercise both
	// canonical sorts without generated signatures, so signer/verifier lockstep cannot conceal a contract change.
	const want = "ef215b69223ebb948181d612dc9bf1b3f2a3666920b007685dd415490b2760fe"
	if got := hex.EncodeToString(BatchMessageV2(unsortedBatchV2())); got != want {
		t.Fatalf("v2 batch message changed:\n got %s\nwant %s", got, want)
	}
}

func TestBatchMessageV3RegressionFixture(t *testing.T) {
	batch := unsortedBatchV2()
	batch.Context = detectionBatchV3Context
	batch.Version = 3
	const want = "8c226be71f765f44e77989f48044bb8eec93fdd3958e153ff1881332afa25bea"
	if got := hex.EncodeToString(BatchMessageV2(batch)); got != want {
		t.Fatalf("v3 batch message changed:\n got %s\nwant %s", got, want)
	}
}

func unsortedBatchV2() AgentBatchV2 {
	batch := sampleBatchV2()
	second := sampleDetectionRefV2("d2", "asset-2", "stream-2", 2, 8, "event-8")
	second.TelemetryRefs = append(second.TelemetryRefs, TelemetryReference{
		StreamID: "stream-3", Epoch: 3, Sequence: 9, EventID: "event-9", Digest: strings.Repeat("f", 64),
	})
	batch.Detections = []DetectionRefV2{second, batch.Detections[0]}
	return batch
}

func cloneBatchV2(batch AgentBatchV2) AgentBatchV2 {
	clone := batch
	clone.Detections = append([]DetectionRefV2(nil), batch.Detections...)
	for i := range clone.Detections {
		clone.Detections[i].TelemetryRefs = append([]TelemetryReference(nil), batch.Detections[i].TelemetryRefs...)
	}
	return clone
}

func TestBatchMessageV1RegressionFixture(t *testing.T) {
	// BatchMessage returns the exact SHA-256 input passed to ed25519.Sign for the legacy v1 contract. The fixture
	// uses only fixed fields and v1's documented sorting, so it protects compatibility without relying on
	// generated signatures or Go JSON representation details.
	const want = "990ff8758c4d98882d094cc909237648a8fb76beee436e3fb25606c4ec8cf45d"
	if got := hex.EncodeToString(BatchMessage(sampleBatch())); got != want {
		t.Fatalf("v1 batch message changed:\n got %s\nwant %s", got, want)
	}
}
