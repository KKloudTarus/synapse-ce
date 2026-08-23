package fleetagent

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func sampleBatch() AgentBatch {
	return AgentBatch{AgentID: "agent:1", EngagementID: "eng-1", Sequence: 3, KeyID: "kid-1",
		Detections: []DetectionRef{
			{ID: "d3", ContentSHA256: "h3"}, {ID: "d1", ContentSHA256: "h1"}, {ID: "d2", ContentSHA256: "h2"},
		}}
}

func TestSignVerifyBatchRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	b := sampleBatch()
	b.Signature = SignBatch(priv, b)
	if err := VerifyBatch(pub, b); err != nil {
		t.Fatalf("a validly signed batch must verify: %v", err)
	}
}

func TestVerifyBatchRejectsTamper(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	b := sampleBatch()
	b.Signature = SignBatch(priv, b)

	// Altering membership, a content digest, the sequence, or the engagement must break the signature.
	tampers := map[string]func(*AgentBatch){
		"add detection":   func(x *AgentBatch) { x.Detections = append(x.Detections, DetectionRef{ID: "d4", ContentSHA256: "h4"}) },
		"drop detection":  func(x *AgentBatch) { x.Detections = x.Detections[:2] },
		"swap content":    func(x *AgentBatch) { x.Detections[0].ContentSHA256 = "tampered" },
		"bump sequence":   func(x *AgentBatch) { x.Sequence = 4 },
		"swap engagement": func(x *AgentBatch) { x.EngagementID = "eng-2" },
		"swap agent":      func(x *AgentBatch) { x.AgentID = "agent:2" },
		"swap key id":     func(x *AgentBatch) { x.KeyID = "kid-2" },
	}
	for name, tamper := range tampers {
		t.Run(name, func(t *testing.T) {
			bad := b
			bad.Detections = append([]DetectionRef(nil), b.Detections...)
			tamper(&bad)
			if err := VerifyBatch(pub, bad); !errors.Is(err, ErrBadBatchSignature) {
				t.Fatalf("tampered batch must fail verification, got %v", err)
			}
		})
	}
}

func TestVerifyBatchIsOrderIndependent(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	b := sampleBatch()
	b.Signature = SignBatch(priv, b)
	// Reorder the refs: the signature is over the SORTED set, so membership order must not matter.
	b.Detections = []DetectionRef{{ID: "d1", ContentSHA256: "h1"}, {ID: "d2", ContentSHA256: "h2"}, {ID: "d3", ContentSHA256: "h3"}}
	if err := VerifyBatch(pub, b); err != nil {
		t.Fatalf("reordering the same membership must still verify: %v", err)
	}
}

func TestVerifyBatchRejectsMalformed(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	b := sampleBatch()
	b.Signature = "not-base64!!"
	if err := VerifyBatch(pub, b); !errors.Is(err, ErrBadBatchSignature) {
		t.Fatalf("a malformed signature must be rejected, got %v", err)
	}
	if err := VerifyBatch(ed25519.PublicKey{1, 2, 3}, b); !errors.Is(err, ErrBadBatchSignature) {
		t.Fatalf("a bad-size public key must be rejected, got %v", err)
	}
}

func TestBatchValidate(t *testing.T) {
	ref := []DetectionRef{{ID: "d", ContentSHA256: "h"}}
	cases := map[string]AgentBatch{
		"no agent":      {EngagementID: "e", Sequence: 1, Detections: ref},
		"no engagement": {AgentID: "a", Sequence: 1, Detections: ref},
		"zero sequence": {AgentID: "a", EngagementID: "e", Sequence: 0, KeyID: "k", Detections: ref},
		"no key id":     {AgentID: "a", EngagementID: "e", Sequence: 1, Detections: ref},
		"no detections": {AgentID: "a", EngagementID: "e", Sequence: 1, KeyID: "k"},
		"empty id":      {AgentID: "a", EngagementID: "e", Sequence: 1, KeyID: "k", Detections: []DetectionRef{{ContentSHA256: "h"}}},
		"empty content": {AgentID: "a", EngagementID: "e", Sequence: 1, KeyID: "k", Detections: []DetectionRef{{ID: "d"}}},
		"duplicate id":  {AgentID: "a", EngagementID: "e", Sequence: 1, KeyID: "k", Detections: []DetectionRef{{ID: "d", ContentSHA256: "h"}, {ID: "d", ContentSHA256: "h"}}},
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if err := b.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
	if err := sampleBatch().Validate(); err != nil {
		t.Fatalf("a well-formed batch must validate: %v", err)
	}
}

func TestDetectSequenceGap(t *testing.T) {
	// Expected next in line: no gap, no replay.
	if g := DetectSequenceGap(2, 3); g.HasGap() {
		t.Errorf("3 after 2 is the expected next, got %+v", g)
	}
	// First ever batch (last = 0, incoming = 1): no gap.
	if g := DetectSequenceGap(0, 1); g.HasGap() {
		t.Errorf("first batch must not be a gap, got %+v", g)
	}
	// Forward gap: 5 after 2 leaves 3 and 4 missing.
	if g := DetectSequenceGap(2, 5); g.Missing != 2 || g.Replay {
		t.Errorf("want 2 missing, got %+v", g)
	}
	// Replay / out-of-order: incoming not ahead.
	if g := DetectSequenceGap(5, 5); !g.Replay {
		t.Errorf("equal sequence is a replay, got %+v", g)
	}
	if g := DetectSequenceGap(5, 3); !g.Replay {
		t.Errorf("lower sequence is out-of-order, got %+v", g)
	}
}
