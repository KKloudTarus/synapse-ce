package e2e

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/detectledger"
)

// plantedSecret is a fake credential assembled from parts (no verbatim secret in source) used to prove the
// A6 redaction holds across the whole loop.
var plantedSecret = "hunter2" + "E2ESecretValue"

// --- Full loop: telemetry + detection through the real components -------------------------------------

func TestFullLoop_TelemetryAndDetection(t *testing.T) {
	h := newHarness(t, 0)

	// Telemetry leg: normalize→redact→sign→ingest. Two events in one batch at seq 1.
	res, err := h.shipTelemetry(1, 1, 0,
		h.telemetryEnvelope(1, []string{"app", "--password=" + plantedSecret, "run"}),
		h.telemetryEnvelope(2, []string{"app", "status"}),
	)
	if err != nil {
		t.Fatalf("telemetry ship: %v", err)
	}
	if !res.Accepted || res.ACK != 1 {
		t.Fatalf("telemetry not accepted/acked: %+v", res)
	}
	if n, _ := h.transport.CountBatchEvents(h.ctx, e2eAgent, e2eStream, 1, 1); n != 2 {
		t.Fatalf("both events must be stored, got %d", n)
	}

	// Detection leg: redact evidence→sign→ingest→seal. Read the PERMANENT evidence back and prove the
	// secret is absent from the sealed, self-contained envelope (coverage-honesty + A6 across the seal).
	det := h.mkDetection([]string{"app", "--password=" + plantedSecret, "dump"})
	dres, err := h.shipDetection("d1", 1, h.detPriv, h.detKey.KeyID, det)
	if err != nil {
		t.Fatalf("detection ship: %v", err)
	}
	if len(dres.SealedRecords) != 1 {
		t.Fatalf("detection must seal exactly one record: %+v", dres)
	}
	links, err := h.evidence.List(h.ctx, e2eEng)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 {
		t.Fatalf("exactly one permanent chain link expected, got %d", len(links))
	}
	env, err := fleetagent.DecodeDetectionEvidenceEnvelope(links[0].Content)
	if err != nil {
		t.Fatalf("sealed link must be a self-contained envelope: %v", err)
	}
	if err := env.VerifyContent(); err != nil {
		t.Fatalf("sealed envelope must self-verify: %v", err)
	}
	if strings.Contains(string(links[0].Content), plantedSecret) {
		t.Fatalf("secret leaked into the permanent sealed detection evidence")
	}
	// Positive: the secret is redacted IN PLACE (not the whole argv dropped) — the flag+placeholder remain,
	// so forensic context is kept while the value is gone.
	gotArgs := env.Detection.Evidence[0].Process.Args
	if len(gotArgs) != 3 || gotArgs[0] != "app" || gotArgs[1] != "--password=[redacted]" || gotArgs[2] != "dump" {
		t.Fatalf("secret must be redacted in place, argv context preserved: %#v", gotArgs)
	}
}

// --- Failure matrix: duplicate, out-of-order gap, gap-fill (no silent loss, idempotent ACK) -----------

func TestFailure_DuplicateOutOfOrderAndGapFill(t *testing.T) {
	h := newHarness(t, 0)
	if _, err := h.shipTelemetry(1, 1, 0, h.telemetryEnvelope(1, []string{"a"})); err != nil {
		t.Fatal(err)
	}
	// Duplicate: idempotent, ACK stable, events not double-stored.
	dup, err := h.shipTelemetry(1, 1, 0, h.telemetryEnvelope(1, []string{"a"}))
	if err != nil || !dup.Duplicate || dup.ACK != 1 {
		t.Fatalf("duplicate must be idempotent with ACK=1: %+v err=%v", dup, err)
	}
	if n, _ := h.transport.CountBatchEvents(h.ctx, e2eAgent, e2eStream, 1, 1); n != 1 {
		t.Fatalf("duplicate must not double-store, got %d", n)
	}
	// Out-of-order: seq 3 while 2 is missing → accepted, ACK stays at 1, gap [2,2] durable (no silent loss).
	fwd, err := h.shipTelemetry(1, 3, 2, h.telemetryEnvelope(3, []string{"c"}))
	if err != nil || !fwd.Accepted || fwd.ACK != 1 || !fwd.GapOpen {
		t.Fatalf("forward gap must keep ACK=1 and report an open gap: %+v err=%v", fwd, err)
	}
	gaps, _ := h.transport.ListGaps(h.ctx, e2eAgent, e2eStream)
	if len(gaps) != 1 || gaps[0].FromSequence != 2 || gaps[0].ToSequence != 2 {
		t.Fatalf("missing sequence must be a durable queryable gap [2,2], got %+v", gaps)
	}
	// Gap fill: seq 2 arrives → ACK advances to 3, gap cleared (derived, no phantom).
	fill, err := h.shipTelemetry(1, 2, 1, h.telemetryEnvelope(2, []string{"b"}))
	if err != nil || fill.ACK != 3 {
		t.Fatalf("gap fill must advance ACK to 3: %+v err=%v", fill, err)
	}
	if g, _ := h.transport.ListGaps(h.ctx, e2eAgent, e2eStream); len(g) != 0 {
		t.Fatalf("filled gap must not linger, got %+v", g)
	}
}

func TestFailure_BadSignatureRefusedAndAudited(t *testing.T) {
	h := newHarness(t, 0)
	// Sign the manifest with the WRONG private key (its public half is not the registered one).
	_, badPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	saved := h.telPriv
	h.telPriv = badPriv
	_, err = h.shipTelemetry(1, 1, 0, h.telemetryEnvelope(1, []string{"a"}))
	h.telPriv = saved
	if !errors.Is(err, fleetagent.ErrBadManifestSignature) {
		t.Fatalf("a bad signature must be refused, got %v", err)
	}
	if !h.audit.has("fleet.telemetry.reject") {
		t.Fatal("a refused batch must be audited")
	}
}

func TestFailure_StaleIncarnationRejected(t *testing.T) {
	h := newHarness(t, 0)
	if _, err := h.shipTelemetry(2, 1, 0, h.telemetryEnvelope(1, []string{"a"})); err != nil {
		t.Fatal(err)
	}
	// A batch for the older epoch 1 after the stream advanced to epoch 2 is a stale incarnation.
	if _, err := h.shipTelemetry(1, 5, 4, h.telemetryEnvelope(5, []string{"b"})); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("stale incarnation must be rejected, got %v", err)
	}
}

func TestFailure_KeyRotationOverlapAndRevoke(t *testing.T) {
	h := newHarness(t, 0)
	// Rotation with overlap: a freshly registered second telemetry key also verifies.
	oldPriv, oldKey := h.telPriv, h.telKey
	newPriv, newKey := h.registerKey(fleetagent.PurposeTelemetryBatch)
	h.telPriv, h.telKey = newPriv, newKey
	if res, err := h.shipTelemetry(1, 1, 0, h.telemetryEnvelope(1, []string{"a"})); err != nil || !res.Accepted {
		t.Fatalf("rotated (overlapping) key must verify: %+v err=%v", res, err)
	}
	// Revoke the OLD key → a batch signed with it fails closed.
	if err := h.keys.Revoke(h.ctx, e2eAgent, oldKey.KeyID, h.now); err != nil {
		t.Fatal(err)
	}
	h.telPriv, h.telKey = oldPriv, oldKey
	if _, err := h.shipTelemetry(1, 2, 1, h.telemetryEnvelope(2, []string{"b"})); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("a revoked key must be refused fail-closed, got %v", err)
	}
}

func TestFailure_DetectionSealedOnceAndIdempotent(t *testing.T) {
	h := newHarness(t, 0)
	det := h.mkDetection([]string{"app", "run"})
	if _, err := h.shipDetection("dX", 1, h.detPriv, h.detKey.KeyID, det); err != nil {
		t.Fatal(err)
	}
	// Re-ship the SAME detection id (agent retry): idempotent — still exactly one permanent link.
	res, err := h.shipDetection("dX", 1, h.detPriv, h.detKey.KeyID, det)
	if err != nil {
		t.Fatalf("idempotent re-ship must not error: %v", err)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("re-ship must skip the already-sealed detection: %+v", res)
	}
	if links, _ := h.evidence.List(h.ctx, e2eEng); len(links) != 1 {
		t.Fatalf("a detection must be sealed at most once, got %d links", len(links))
	}
}

func TestFailure_IdentityMismatchForbidden(t *testing.T) {
	h := newHarness(t, 0)
	// A detection batch whose agent is not the authenticated agent is refused before sealing.
	det := h.mkDetection([]string{"app", "run"})
	scrubbed := det
	payload, _ := json.Marshal(scrubbed)
	batch := fleetagent.AgentBatch{
		AgentID: "someone-else", EngagementID: e2eEng, Sequence: 1, KeyID: h.detKey.KeyID,
		Detections: []fleetagent.DetectionRef{{ID: "d1", ContentSHA256: fleetagent.DetectionContentHash(payload, e2eAsset)}},
	}
	batch.Signature = fleetagent.SignBatch(h.detPriv, batch)
	items := []detectledger.IngestItem{{ID: "d1", Detection: scrubbed, AssetID: e2eAsset}}
	if _, err := h.ledger.Ingest(h.ctx, e2eAgent, batch, items); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("identity mismatch must be forbidden, got %v", err)
	}
	if links, _ := h.evidence.List(h.ctx, e2eEng); len(links) != 0 {
		t.Fatalf("an identity-mismatched batch must seal nothing, got %d", len(links))
	}
	if !h.audit.has("detection.batch_rejected") {
		t.Fatal("an identity-mismatched batch must be audited as rejected (attributable fail-closed)")
	}
}

func TestRetention_EvidenceSurvivesProjectionExpiry(t *testing.T) {
	h := newHarness(t, time.Hour) // projections expire; the chain is permanent
	det := h.mkDetection([]string{"app", "run"})
	if _, err := h.shipDetection("dR", 1, h.detPriv, h.detKey.KeyID, det); err != nil {
		t.Fatal(err)
	}
	// The projection row exists now.
	if recs, _ := h.records.ListDetections(h.ctx, e2eEng); len(recs) != 1 {
		t.Fatalf("projection row must exist before expiry, got %d", len(recs))
	}
	// Advance the SHARED clock past retention (the ledger sees it via the pointer) and expire the projection.
	h.clock.t = h.now.Add(2 * time.Hour)
	expired, err := h.ledger.Expire(h.ctx, e2eEng, "operator", "retention-sweep-test")
	if err != nil {
		t.Fatalf("expire: %v", err)
	}
	if expired != 1 {
		t.Fatalf("retention sweep must actually remove the aged projection row, expired=%d", expired)
	}
	if recs, _ := h.records.ListDetections(h.ctx, e2eEng); len(recs) != 0 {
		t.Fatalf("projection must be gone after the sweep, got %d", len(recs))
	}
	// The PERMANENT evidence link must survive the projection sweep and stay verifiable + self-contained.
	links, err := h.evidence.List(h.ctx, e2eEng)
	if err != nil || len(links) != 1 {
		t.Fatalf("the permanent evidence link must survive projection expiry, got %d err=%v", len(links), err)
	}
	if err := h.evidence.VerifyChainError(h.ctx, e2eEng); err != nil {
		t.Fatalf("the chain must remain intact after expiry: %v", err)
	}
	if env, derr := fleetagent.DecodeDetectionEvidenceEnvelope(links[0].Content); derr != nil || env.VerifyContent() != nil {
		t.Fatalf("the surviving link must remain a self-verifying envelope: decode=%v", derr)
	}
}

// --- Soak: sustained ingest stays bounded and leaks no goroutines ------------------------------------

func TestSoak_BoundedNoGoroutineLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping soak in -short")
	}
	h := newHarness(t, 0)
	before := runtime.NumGoroutine()
	const n = 500
	for seq := uint64(1); seq <= n; seq++ {
		res, err := h.shipTelemetry(1, seq, seq-1, h.telemetryEnvelope(seq, []string{"app", "run"}))
		if err != nil {
			t.Fatalf("soak ship seq %d: %v", seq, err)
		}
		if res.ACK != seq {
			t.Fatalf("contiguous ACK must track seq: got %d want %d", res.ACK, seq)
		}
	}
	// No open gaps after a fully-contiguous run.
	if g, _ := h.transport.ListGaps(h.ctx, e2eAgent, e2eStream); len(g) != 0 {
		t.Fatalf("a contiguous soak must leave no gaps, got %d", len(g))
	}
	runtime.GC()
	after := runtime.NumGoroutine()
	if after > before+5 {
		t.Fatalf("goroutine leak: before=%d after=%d", before, after)
	}
}
