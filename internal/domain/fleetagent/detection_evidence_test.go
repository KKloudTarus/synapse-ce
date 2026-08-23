package fleetagent

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func mkEnvDetection(t *testing.T) detection.Detection {
	t.Helper()
	r, ok := detection.Lookup("det.process_enumeration")
	if !ok {
		t.Fatal("expected det.process_enumeration rule")
	}
	ev := detection.Event{Class: detection.ClassProcess, At: time.Unix(1, 0), Host: "h",
		Process: &detection.ProcessEvent{PID: 1, Comm: "ps", Path: "/usr/bin/ps"}}
	d, err := detection.NewDetection(r, "host-1", "agent-1", []detection.Event{ev}, time.Unix(500, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func mkEnvelope(t *testing.T, prov ProvenanceState) DetectionEvidenceEnvelope {
	t.Helper()
	det := mkEnvDetection(t)
	payload, err := json.Marshal(det)
	if err != nil {
		t.Fatal(err)
	}
	asset := shared.ID("asset-1")
	env, err := NewDetectionEvidenceEnvelope("tenant-1", "eng-1", "agent-1", asset, "d1", 7, "key-1",
		DetectionContentHash(payload, asset), prov, det)
	if err != nil {
		t.Fatalf("build envelope: %v", err)
	}
	return env
}

func TestDetectionEvidenceEnvelopeCanonicalIsDeterministic(t *testing.T) {
	a := mkEnvelope(t, ProvenanceComplete)
	b := mkEnvelope(t, ProvenanceComplete)
	ab, err := a.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	bb, err := b.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	// Deterministic: two builds of the same admission produce byte-identical sealed content, so an
	// idempotent re-seal (SealOnce content comparison) converges instead of conflicting.
	if string(ab) != string(bb) {
		t.Fatalf("canonical bytes must be deterministic:\n a=%s\n b=%s", ab, bb)
	}
}

func TestDetectionEvidenceEnvelopeRoundTripAndSelfContained(t *testing.T) {
	env := mkEnvelope(t, ProvenanceComplete)
	content, err := env.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	// Decode the sealed content ALONE (as if the projection has expired) — it must reconstruct the full
	// attribution and stay self-verifying against its content commitment.
	got, err := DecodeDetectionEvidenceEnvelope(content)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.TenantID != "tenant-1" || got.EngagementID != "eng-1" || got.AgentID != "agent-1" || got.AssetID != "asset-1" ||
		got.DetectionID != "d1" || got.BatchSequence != 7 || got.KeyID != "key-1" || got.Provenance != ProvenanceComplete {
		t.Fatalf("round-trip lost attribution: %+v", got)
	}
	if got.RuleID != env.Detection.RuleID {
		t.Fatalf("round-trip lost rule provenance: %q vs %q", got.RuleID, env.Detection.RuleID)
	}
	if err := got.VerifyContent(); err != nil {
		t.Fatalf("decoded envelope must self-verify: %v", err)
	}
}

func TestDetectionEvidenceEnvelopeDetectsContentTamper(t *testing.T) {
	env := mkEnvelope(t, ProvenanceComplete)
	// Tamper the sealed detection body after commitment: VerifyContent must catch the mismatch from the
	// envelope alone (no projection), because the embedded commitment no longer matches the detection.
	env.Detection.Severity = shared.SeverityCritical
	if err := env.VerifyContent(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a tampered detection body must fail VerifyContent, got %v", err)
	}
}

func TestDecodeRejectsForeignContent(t *testing.T) {
	// A plain detection JSON (no domain-separation context) must not decode as an evidence envelope.
	raw, err := json.Marshal(mkEnvDetection(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDetectionEvidenceEnvelope(raw); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("foreign content must be rejected, got %v", err)
	}
}

func TestProvenanceStateValid(t *testing.T) {
	for _, p := range []ProvenanceState{ProvenancePending, ProvenanceComplete, ProvenanceExpired, ProvenanceBroken} {
		if !p.Valid() {
			t.Fatalf("%q must be valid", p)
		}
	}
	if ProvenanceState("nonsense").Valid() {
		t.Fatal("unknown provenance must be invalid")
	}
}

func TestDetectionEvidenceEnvelopeValidate(t *testing.T) {
	det := mkEnvDetection(t)
	payload, _ := json.Marshal(det)
	asset := shared.ID("asset-1")
	digest := DetectionContentHash(payload, asset)
	base := func() DetectionEvidenceEnvelope {
		e, err := NewDetectionEvidenceEnvelope("tenant-1", "eng-1", "agent-1", asset, "d1", 1, "key-1", digest, ProvenanceComplete, det)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	// unknown provenance
	if _, err := NewDetectionEvidenceEnvelope("tenant-1", "eng-1", "agent-1", asset, "d1", 1, "key-1", digest, ProvenanceState("x"), det); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown provenance must be rejected, got %v", err)
	}
	// missing ids / key / commitment
	e := base()
	e.AgentID = ""
	if err := e.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing agent id must fail, got %v", err)
	}
	e = base()
	e.KeyID = ""
	if err := e.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing key id must fail, got %v", err)
	}
	e = base()
	e.ContentSHA256 = ""
	if err := e.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing commitment must fail, got %v", err)
	}
	e = base()
	e.Context = "wrong"
	if err := e.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("wrong context must fail, got %v", err)
	}
}
