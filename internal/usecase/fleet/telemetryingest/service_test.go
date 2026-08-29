package telemetryingest

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const tenant = shared.ID("tenant-1")

type fakeClock struct{ now time.Time }

func (c *fakeClock) Set(now time.Time) { c.now = now }

func (c *fakeClock) Now() time.Time { return c.now }

type fakeAudit struct {
	mu         sync.Mutex
	n          int
	failAction string
	keys       map[string]int
	entries    map[string]ports.AuditEntry
	failed     map[string]ports.AuditEntry
}

func (a *fakeAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.n++
	if a.failAction != "" && entry.Action == a.failAction {
		return errors.New("audit store unavailable")
	}
	return nil
}

func (a *fakeAudit) RecordOnce(ctx context.Context, e ports.AuditEntry) error {
	a.mu.Lock()
	if a.failAction != "" && e.Action == a.failAction {
		if a.failed == nil {
			a.failed = map[string]ports.AuditEntry{}
		}
		a.failed[e.Metadata["idempotency_key"]] = e
		a.mu.Unlock()
		return errors.New("audit store unavailable")
	}
	if a.keys == nil {
		a.keys = map[string]int{}
	}
	if a.entries == nil {
		a.entries = map[string]ports.AuditEntry{}
	}
	key := e.Metadata["idempotency_key"]
	if key == "" {
		a.mu.Unlock()
		return a.Record(ctx, e)
	}
	if existing, ok := a.entries[key]; ok {
		if !reflect.DeepEqual(existing, e) {
			a.mu.Unlock()
			return errors.New("idempotent audit metadata changed")
		}
		a.mu.Unlock()
		return nil
	}
	a.entries[key] = e
	a.keys[key]++
	a.n++
	a.mu.Unlock()
	return nil
}

// recordedOnce reports how many audit lines carried the given deterministic key.
func (a *fakeAudit) recordedOnce(key string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.keys[key]
}

func (a *fakeAudit) sameFailedAndRecorded(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return reflect.DeepEqual(a.failed[key], a.entries[key])
}

func (a *fakeAudit) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.n
}

type fakeKeys struct{ key fleetagent.AgentSigningKey }

func (k fakeKeys) ResolveSigningKey(_ context.Context, agentID shared.ID, keyID string) (fleetagent.AgentSigningKey, error) {
	if agentID == k.key.AgentID && keyID == k.key.KeyID {
		return k.key, nil
	}
	return fleetagent.AgentSigningKey{}, shared.ErrNotFound
}

type harness struct {
	t            *testing.T
	svc          *Service
	transport    *memory.TelemetryTransportStore
	priv         ed25519.PrivateKey
	key          fleetagent.AgentSigningKey
	audit        *fakeAudit
	clock        *fakeClock
	now          time.Time
	ctx          context.Context
	stream       shared.ID
	session      fleetagent.SessionID
	policyDigest string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	now := time.Unix(1_700_000_000, 0).UTC()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := fleetagent.NewSigningKey("agent-1", fleetagent.PurposeTelemetryBatch, pub, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	transport := memory.NewTelemetryTransportStore()
	policies := memory.NewPrivacyPolicyStore()
	audit := &fakeAudit{}
	clock := &fakeClock{now: now}
	ctx := shared.WithTenant(context.Background(), tenant)
	assignment, err := privacy.NewAssignment(tenant, privacy.DefaultPolicy(), "test-operator", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policies.PutPrivacyPolicy(ctx, assignment); err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(transport, fakeKeys{key: key}, policies, audit, clock)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetSensorStateStore(memory.NewSensorStateStore())
	if err := transport.BindTelemetryAsset(ctx, ports.TelemetryAssetBinding{TenantID: tenant, AgentID: "agent-1", AssetID: "asset-1", UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	session := fleetagent.CanonicalSessionID("agent-1")
	stream, err := fleetagent.TelemetryDeliveryStreamID("agent-1", session, fleetagent.PriorityP3)
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, svc: svc, transport: transport, priv: priv, key: key, audit: audit, clock: clock, now: now, ctx: ctx, stream: stream, session: session, policyDigest: assignment.Digest}
}

func (h *harness) canonicalEvent(version int, id shared.ID, sequence uint64) (EventPayload, fleetagent.EventRef) {
	h.t.Helper()
	observed := h.now.Add(time.Duration(sequence) * time.Millisecond)
	ev := telemetry.TelemetryEvent{
		Class:   detection.ClassProcess,
		Process: &telemetry.ProcessObservation{Kind: "exec", PID: 100 + int(sequence), EntityID: shared.ID("proc-" + id.String()), Comm: "test-proc"},
	}
	env := telemetry.TelemetryEnvelope{
		SchemaVersion: version,
		EventID:       id, EventType: ev.EventType(), EventClass: detection.ClassProcess,
		AgentID: "agent-1", AgentSessionID: shared.ID(h.session), AssetID: "asset-1",
		BootID: "boot-1", StreamID: "sensor-stream-1", SensorID: "sensor-1", SensorVersion: "1",
		OccurredAt: observed.Add(-time.Millisecond), ObservedAt: observed, Sequence: sequence,
		RedactionPolicyDigest: h.policyDigest,
		Event:                 ev,
	}
	payload, err := json.Marshal(env)
	if err != nil {
		h.t.Fatal(err)
	}
	wrapped := EventPayload{EventID: id, Class: detection.ClassProcess, Payload: payload, ObservedAt: observed}
	ref := fleetagent.EventRef{ID: id, Digest: fleetagent.TelemetryEventDigest(payload, "asset-1")}
	return wrapped, ref
}

func (h *harness) signedBatch(epoch, seq, prev uint64, eventIDs ...shared.ID) IngestRequest {
	return h.signedBatchVersion(telemetry.SchemaVersion, epoch, seq, prev, eventIDs...)
}

func (h *harness) signedBatchVersion(version int, epoch, seq, prev uint64, eventIDs ...shared.ID) IngestRequest {
	h.t.Helper()
	assetID := shared.ID("asset-1")
	events := make([]EventPayload, len(eventIDs))
	refs := make([]fleetagent.EventRef, len(eventIDs))
	var minAt, maxAt time.Time
	for i, id := range eventIDs {
		events[i], refs[i] = h.canonicalEvent(version, id, uint64(i+1))
		at := events[i].ObservedAt.UTC()
		if minAt.IsZero() || at.Before(minAt) {
			minAt = at
		}
		if maxAt.IsZero() || at.After(maxAt) {
			maxAt = at
		}
	}
	m := fleetagent.TelemetryBatchManifest{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion,
		SchemaVersion:   version,
		BatchID:         shared.ID("batch-" + seqStr(epoch) + "-" + seqStr(seq)),
		AgentID:         "agent-1", HostID: "agent-1", AssetID: assetID, StreamID: h.stream,
		Position:             fleetagent.StreamPosition{Priority: fleetagent.PriorityP3, Epoch: epoch, Sequence: seq, Session: h.session, Boot: "boot-1"},
		PreviousSequence:     prev,
		EventTimeMin:         minAt,
		EventTimeMax:         maxAt,
		ObservedCount:        len(eventIDs),
		KeptCount:            len(eventIDs),
		SamplingPolicyDigest: "spd",
		Events:               refs,
		PayloadDigest:        fleetagent.TelemetryPayloadDigest(refs),
		KeyID:                h.key.KeyID,
	}
	m.Signature = fleetagent.SignTelemetryManifest(h.priv, m)
	return IngestRequest{Manifest: m, Events: events}
}

func (h *harness) resignPayload(req *IngestRequest, index int, mutate func(*telemetry.TelemetryEnvelope)) {
	h.t.Helper()
	var env telemetry.TelemetryEnvelope
	if err := json.Unmarshal(req.Events[index].Payload, &env); err != nil {
		h.t.Fatal(err)
	}
	mutate(&env)
	payload, err := json.Marshal(env)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Events[index].Payload = payload
	for i := range req.Manifest.Events {
		if req.Manifest.Events[i].ID == req.Events[index].EventID {
			req.Manifest.Events[i].Digest = fleetagent.TelemetryEventDigest(payload, req.Manifest.AssetID)
		}
	}
	req.Manifest.PayloadDigest = fleetagent.TelemetryPayloadDigest(req.Manifest.Events)
	req.Manifest.Signature = fleetagent.SignTelemetryManifest(h.priv, req.Manifest)
}

func (h *harness) retimeBatch(req *IngestRequest, minAt, maxAt time.Time) {
	h.t.Helper()
	minAt = minAt.UTC()
	maxAt = maxAt.UTC()
	if maxAt.Before(minAt) {
		h.t.Fatalf("invalid test batch bounds [%s,%s]", minAt, maxAt)
	}
	var eventTimeMin, eventTimeMax time.Time
	for i := range req.Events {
		observed := minAt
		if len(req.Events) > 1 {
			observed = minAt.Add(time.Duration(i) * maxAt.Sub(minAt) / time.Duration(len(req.Events)-1))
		}
		var env telemetry.TelemetryEnvelope
		if err := json.Unmarshal(req.Events[i].Payload, &env); err != nil {
			h.t.Fatal(err)
		}
		env.ObservedAt = observed
		env.OccurredAt = observed.Add(-time.Millisecond)
		payload, err := json.Marshal(env)
		if err != nil {
			h.t.Fatal(err)
		}
		req.Events[i].Payload = payload
		req.Events[i].ObservedAt = observed
		if eventTimeMin.IsZero() || observed.Before(eventTimeMin) {
			eventTimeMin = observed
		}
		if eventTimeMax.IsZero() || observed.After(eventTimeMax) {
			eventTimeMax = observed
		}
		for j := range req.Manifest.Events {
			if req.Manifest.Events[j].ID == req.Events[i].EventID {
				req.Manifest.Events[j].Digest = fleetagent.TelemetryEventDigest(payload, req.Manifest.AssetID)
			}
		}
	}
	req.Manifest.EventTimeMin = eventTimeMin
	req.Manifest.EventTimeMax = eventTimeMax
	req.Manifest.PayloadDigest = fleetagent.TelemetryPayloadDigest(req.Manifest.Events)
	req.Manifest.Signature = fleetagent.SignTelemetryManifest(h.priv, req.Manifest)
}

func seqStr(u uint64) string { return string(rune('0' + int(u%10))) }

func (h *harness) signedSensorState() fleetagent.SensorStateReport {
	h.t.Helper()
	report := fleetagent.SensorStateReport{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion,
		ReportID:        "state-1", AgentID: "agent-1", HostID: "agent-1", AgentSessionID: h.session, AssetID: "asset-1",
		Kind: "sensor_state", ObservedAt: h.now, SchemaVersion: 1,
		PayloadDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", KeyID: h.key.KeyID,
		States: []detection.ClassCoverage{{Class: detection.ClassProcess, HostID: "agent-1", AgentID: "agent-1", State: detection.StateActive, Since: h.now}},
	}
	report.Signature = fleetagent.SignSensorState(h.priv, report)
	return report
}

func TestIngestSensorStateBindsAssetAndIsIdempotent(t *testing.T) {
	h := newHarness(t)
	report := h.signedSensorState()
	res, err := h.svc.IngestSensorState(h.ctx, "agent-1", report)
	if err != nil || res.ReportID != report.ReportID {
		t.Fatalf("ingest sensor state = %+v, %v", res, err)
	}
	if _, err := h.svc.IngestSensorState(h.ctx, "agent-1", report); err != nil {
		t.Fatalf("exact retry: %v", err)
	}
}

func TestIngestSensorStateRetryPreservesFirstRecordedAt(t *testing.T) {
	h := newHarness(t)
	report := h.signedSensorState()
	first, err := h.svc.IngestSensorState(h.ctx, "agent-1", report)
	if err != nil || first.ReportID != report.ReportID {
		t.Fatalf("first ingest = %+v, %v", first, err)
	}
	h.clock.Set(h.now.Add(time.Second + 123*time.Nanosecond))
	if _, err := h.svc.IngestSensorState(h.ctx, "agent-1", report); err != nil {
		t.Fatalf("later retry: %v", err)
	}
	states, err := h.svc.sensorStates.ListSensorStates(h.ctx, ports.SensorStateQuery{})
	if err != nil || len(states) != 1 {
		t.Fatalf("stored sensor states = %+v, %v; want one", states, err)
	}
	if got, want := states[0].RecordedAt, h.now.UTC().Truncate(time.Microsecond); !got.Equal(want) {
		t.Fatalf("recorded at = %s, want first acceptance %s", got, want)
	}
}

func TestIngestSensorStateRejectsForgedAsset(t *testing.T) {
	h := newHarness(t)
	report := h.signedSensorState()
	report.AssetID = "other-asset"
	report.Signature = fleetagent.SignSensorState(h.priv, report)
	if _, err := h.svc.IngestSensorState(h.ctx, "agent-1", report); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("forged asset error = %v, want forbidden", err)
	}
}

type recordingPolicyResolver struct {
	assignments map[string]privacy.Assignment
	calls       map[string]int
	err         error
	mutate      func(privacy.Assignment) privacy.Assignment
}

func (r *recordingPolicyResolver) PrivacyPolicyByDigest(
	_ context.Context,
	_ shared.ID,
	digest string,
) (privacy.Assignment, error) {
	if r.calls == nil {
		r.calls = make(map[string]int)
	}
	r.calls[digest]++
	if r.err != nil {
		return privacy.Assignment{}, r.err
	}
	assignment, ok := r.assignments[digest]
	if !ok {
		return privacy.Assignment{}, shared.ErrNotFound
	}
	if r.mutate != nil {
		assignment = r.mutate(assignment)
	}
	return assignment, nil
}

type recordingCoverageReconciler struct {
	mu       sync.Mutex
	requests []ports.CoverageReconcileRequest
	fail     error
}

type recordingDetectionReconciler struct {
	calls int
	fail  error
}

func (r *recordingDetectionReconciler) ReconcilePendingDetections(ctx context.Context) (int, error) {
	if _, ok := shared.TenantFrom(ctx); !ok {
		return 0, errors.New("missing tenant context")
	}
	r.calls++
	if r.fail != nil {
		return 0, r.fail
	}
	return 1, nil
}

func (r *recordingCoverageReconciler) ReconcileCoverage(_ context.Context, request ports.CoverageReconcileRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, request)
	return r.fail
}

func (r *recordingCoverageReconciler) snapshot() []ports.CoverageReconcileRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ports.CoverageReconcileRequest(nil), r.requests...)
}

func (r *recordingCoverageReconciler) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = nil
}

func TestNewServiceRejectsNilPrivacyPolicyResolver(t *testing.T) {
	h := newHarness(t)
	if _, err := NewService(h.transport, fakeKeys{key: h.key}, nil, h.audit, h.clock); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil privacy-policy resolver error = %v, want validation", err)
	}
}

func TestIngestRejectsMissingRedactionPolicyDigestBeforeMutation(t *testing.T) {
	h := newHarness(t)
	req := h.signedBatch(1, 1, 0, "e1")
	h.resignPayload(&req, 0, func(env *telemetry.TelemetryEnvelope) {
		env.RedactionPolicyDigest = ""
	})

	if _, err := h.svc.Ingest(h.ctx, "agent-1", req); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing redaction-policy digest error = %v, want validation", err)
	}
	assertNoTelemetryMutation(t, h)
}

func TestIngestRejectsUnknownRedactionPolicyBeforeMutation(t *testing.T) {
	h := newHarness(t)
	req := h.signedBatch(1, 1, 0, "e1")
	h.resignPayload(&req, 0, func(env *telemetry.TelemetryEnvelope) {
		env.RedactionPolicyDigest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	})

	if _, err := h.svc.Ingest(h.ctx, "agent-1", req); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("unknown redaction policy error = %v, want forbidden", err)
	}
	assertNoTelemetryMutation(t, h)
}

func TestIngestAcceptsInactiveHistoricalRedactionPolicy(t *testing.T) {
	h := newHarness(t)
	policies := memory.NewPrivacyPolicyStore()
	firstPolicy := privacy.DefaultPolicy()
	firstPolicy.Version = "tenant:v1"
	first, err := privacy.NewAssignment(tenant, firstPolicy, "test-operator", h.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policies.PutPrivacyPolicy(h.ctx, first); err != nil {
		t.Fatal(err)
	}
	secondPolicy := privacy.DefaultPolicy()
	secondPolicy.Version = "tenant:v2"
	secondPolicy.MaxArgLen = 1024
	second, err := privacy.NewAssignment(tenant, secondPolicy, "test-operator", h.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policies.PutPrivacyPolicy(h.ctx, second); err != nil {
		t.Fatal(err)
	}
	h.svc.policies = policies
	req := h.signedBatch(1, 1, 0, "e1")
	h.resignPayload(&req, 0, func(env *telemetry.TelemetryEnvelope) {
		env.RedactionPolicyDigest = first.Digest
	})

	if _, err := h.svc.Ingest(h.ctx, "agent-1", req); err != nil {
		t.Fatalf("ingest with inactive historical policy: %v", err)
	}
}

func TestIngestAcceptsMixedKnownPoliciesAndResolvesEachDigestOnce(t *testing.T) {
	h := newHarness(t)
	firstPolicy := privacy.DefaultPolicy()
	firstPolicy.Version = "tenant:v1"
	first, err := privacy.NewAssignment(tenant, firstPolicy, "test-operator", h.now)
	if err != nil {
		t.Fatal(err)
	}
	secondPolicy := privacy.DefaultPolicy()
	secondPolicy.Version = "tenant:v2"
	secondPolicy.MaxArgLen = 1024
	second, err := privacy.NewAssignment(tenant, secondPolicy, "test-operator", h.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	resolver := &recordingPolicyResolver{assignments: map[string]privacy.Assignment{
		first.Digest:  first,
		second.Digest: second,
	}}
	h.svc.policies = resolver
	req := h.signedBatch(1, 1, 0, "e1", "e2", "e3")
	for i, digest := range []string{first.Digest, second.Digest, first.Digest} {
		i, digest := i, digest
		h.resignPayload(&req, i, func(env *telemetry.TelemetryEnvelope) {
			env.RedactionPolicyDigest = digest
		})
	}

	if _, err := h.svc.Ingest(h.ctx, "agent-1", req); err != nil {
		t.Fatalf("ingest mixed known policies: %v", err)
	}
	if resolver.calls[first.Digest] != 1 || resolver.calls[second.Digest] != 1 {
		t.Fatalf("policy lookups = %#v, want one per distinct digest", resolver.calls)
	}
}

func TestIngestPolicyResolverFailureDoesNotMutateTransport(t *testing.T) {
	h := newHarness(t)
	resolverErr := errors.New("policy store unavailable")
	h.svc.policies = &recordingPolicyResolver{err: resolverErr}

	if _, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 1, 0, "e1")); !errors.Is(err, resolverErr) {
		t.Fatalf("policy resolver failure error = %v, want resolver cause", err)
	}
	assertNoTelemetryMutation(t, h)
}

func TestIngestRejectsContradictoryPolicyResolverIdentityBeforeMutation(t *testing.T) {
	h := newHarness(t)
	policy := privacy.DefaultPolicy()
	assignment, err := privacy.NewAssignment(tenant, policy, "test-operator", h.now)
	if err != nil {
		t.Fatal(err)
	}
	h.svc.policies = &recordingPolicyResolver{
		assignments: map[string]privacy.Assignment{assignment.Digest: assignment},
		mutate: func(got privacy.Assignment) privacy.Assignment {
			got.TenantID = "other-tenant"
			return got
		},
	}

	if _, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 1, 0, "e1")); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("contradictory policy identity error = %v, want conflict", err)
	}
	assertNoTelemetryMutation(t, h)
}

func assertNoTelemetryMutation(t *testing.T, h *harness) {
	t.Helper()
	if n, err := h.transport.CountBatchEvents(h.ctx, "agent-1", h.stream, 1, 1); err != nil || n != 0 {
		t.Fatalf("stored events = %d, %v; want none", n, err)
	}
	state, err := h.transport.StreamState(h.ctx, "agent-1", h.stream, 1)
	if err != nil {
		t.Fatalf("read stream state: %v", err)
	}
	if state.Contiguous != 0 || len(state.Pending) != 0 || state.Version != 0 {
		t.Fatalf("stream state mutated before policy authorization: %+v", state)
	}
}

func TestIngestAcceptsAndAcks(t *testing.T) {
	h := newHarness(t)
	res, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 1, 0, "e1", "e2"))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if !res.Accepted || res.Duplicate || res.ACK != 1 || res.Provenance != ProvenanceAcknowledged {
		t.Fatalf("unexpected result: %+v", res)
	}
	if n, _ := h.transport.CountBatchEvents(h.ctx, "agent-1", h.stream, 1, 1); n != 2 {
		t.Fatalf("want 2 stored events, got %d", n)
	}
}

func TestIngestAcceptsHonestZeroKeptManifest(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sampledOut int
		dropped    int
	}{
		{name: "all sampled", sampledOut: 4},
		{name: "all dropped", dropped: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			coverage := &recordingCoverageReconciler{}
			h.svc.SetCoverageReconciler(coverage)
			req := h.signedBatch(1, 1, 0, "e1")
			req.Events = nil
			req.Manifest.Events = nil
			req.Manifest.ObservedCount = 4
			req.Manifest.KeptCount = 0
			req.Manifest.SampledOutCount = tc.sampledOut
			req.Manifest.DroppedCount = tc.dropped
			req.Manifest.PayloadDigest = fleetagent.TelemetryPayloadDigest(nil)
			req.Manifest.Signature = fleetagent.SignTelemetryManifest(h.priv, req.Manifest)

			res, err := h.svc.Ingest(h.ctx, "agent-1", req)
			if err != nil {
				t.Fatalf("ingest honest zero-kept manifest: %v", err)
			}
			if !res.Accepted || res.Duplicate || res.ACK != 1 || res.Provenance != ProvenanceAcknowledged {
				t.Fatalf("zero-kept result = %+v, want accepted ACK=1", res)
			}
			if n, err := h.transport.CountBatchEvents(h.ctx, "agent-1", h.stream, 1, 1); err != nil || n != 0 {
				t.Fatalf("stored events = %d, %v; want none without a fabricated event", n, err)
			}
			state, err := h.transport.StreamState(h.ctx, "agent-1", h.stream, 1)
			if err != nil {
				t.Fatalf("read stream state: %v", err)
			}
			if state.Contiguous != 1 || len(state.Pending) != 0 || state.Version != 1 {
				t.Fatalf("zero-kept stream state = %+v, want contiguous ACK persisted", state)
			}
			accounting, err := h.transport.QueryTelemetryBatchAccounting(h.ctx, ports.TelemetryBatchAccountingQuery{
				AgentID: "agent-1", AssetID: "asset-1",
				Since: req.Manifest.EventTimeMin.Add(-time.Microsecond),
				Until: req.Manifest.EventTimeMax.Add(time.Microsecond),
			})
			if err != nil {
				t.Fatalf("query signed accounting: %v", err)
			}
			if len(accounting) != 1 || accounting[0].ObservedCount != 4 || accounting[0].KeptCount != 0 ||
				accounting[0].SampledOutCount != tc.sampledOut || accounting[0].DroppedCount != tc.dropped {
				t.Fatalf("durable zero-kept accounting = %+v", accounting)
			}
			requests := coverage.snapshot()
			if len(requests) != 1 || !requests[0].Since.Equal(req.Manifest.EventTimeMin) ||
				!requests[0].Until.Equal(req.Manifest.EventTimeMax) {
				t.Fatalf("coverage requests = %+v, want signed source-time span", requests)
			}

			replay, err := h.svc.Ingest(h.ctx, "agent-1", req)
			if err != nil {
				t.Fatalf("replay honest zero-kept manifest: %v", err)
			}
			if replay.Accepted || !replay.Duplicate || replay.ACK != 1 {
				t.Fatalf("zero-kept replay = %+v, want duplicate ACK=1", replay)
			}
			if n, err := h.transport.CountBatchEvents(h.ctx, "agent-1", h.stream, 1, 1); err != nil || n != 0 {
				t.Fatalf("replay stored events = %d, %v; want none", n, err)
			}
			if got := len(coverage.snapshot()); got != 2 {
				t.Fatalf("coverage reconciliation calls after exact retry = %d, want 2", got)
			}
		})
	}
}

func TestIngestRejectsDishonestLossAccountingBeforeMutation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*fleetagent.TelemetryBatchManifest)
	}{
		{name: "accounting equation", mutate: func(manifest *fleetagent.TelemetryBatchManifest) {
			manifest.ObservedCount++
		}},
		{name: "truncated exceeds kept", mutate: func(manifest *fleetagent.TelemetryBatchManifest) {
			manifest.TruncatedCount = manifest.KeptCount + 1
		}},
		{name: "negative sampled count", mutate: func(manifest *fleetagent.TelemetryBatchManifest) {
			manifest.SampledOutCount = -1
			manifest.ObservedCount--
		}},
		{name: "zero observed count", mutate: func(manifest *fleetagent.TelemetryBatchManifest) {
			manifest.ObservedCount = 0
			manifest.KeptCount = 0
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			req := h.signedBatch(1, 1, 0, "e1")
			tc.mutate(&req.Manifest)
			req.Manifest.Signature = fleetagent.SignTelemetryManifest(h.priv, req.Manifest)

			if _, err := h.svc.Ingest(h.ctx, "agent-1", req); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("dishonest manifest error = %v, want validation", err)
			}
			if h.audit.count() != 0 {
				t.Fatalf("dishonest manifest emitted %d audit records before admission, want 0", h.audit.count())
			}
			assertNoTelemetryMutation(t, h)
		})
	}
}

func TestIngestCommitsSignedLossAccounting(t *testing.T) {
	h := newHarness(t)
	req := h.signedBatch(1, 1, 0, "e1", "e2")
	req.Manifest.ObservedCount = 5
	req.Manifest.SampledOutCount = 1
	req.Manifest.TruncatedCount = 1
	req.Manifest.DroppedCount = 2
	req.Manifest.SamplingPolicyDigest = "policy-digest-1"
	req.Manifest.Signature = fleetagent.SignTelemetryManifest(h.priv, req.Manifest)
	if _, err := h.svc.Ingest(h.ctx, "agent-1", req); err != nil {
		t.Fatalf("ingest accounting batch: %v", err)
	}

	replay := req
	replay.Manifest.SampledOutCount++
	replay.Manifest.DroppedCount--
	replay.Manifest.Signature = fleetagent.SignTelemetryManifest(h.priv, replay.Manifest)
	if _, err := h.svc.Ingest(h.ctx, "agent-1", replay); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("same signed batch coordinate with different accounting error = %v, want conflict", err)
	}
}

func TestIngestIdempotentReplay(t *testing.T) {
	h := newHarness(t)
	batch := h.signedBatch(1, 1, 0, "e1")
	if _, err := h.svc.Ingest(h.ctx, "agent-1", batch); err != nil {
		t.Fatal(err)
	}
	res, err := h.svc.Ingest(h.ctx, "agent-1", batch)
	if err != nil {
		t.Fatalf("replay must not error: %v", err)
	}
	if res.Accepted || !res.Duplicate || res.ACK != 1 {
		t.Fatalf("replay must be an idempotent duplicate with ACK=1: %+v", res)
	}
	if n, _ := h.transport.CountBatchEvents(h.ctx, "agent-1", h.stream, 1, 1); n != 1 {
		t.Fatalf("replay must not duplicate stored events, got %d", n)
	}
}

// TestIngestAuditFailureIsRepairedByExactRetry proves telemetry admission never silently loses its
// audit line: a failing audit surfaces as an error, and because admission is idempotent the exact
// retry both reports the duplicate honestly and writes exactly ONE audit line for that position.
func TestIngestAuditFailureIsRepairedByExactRetry(t *testing.T) {
	h := newHarness(t)
	batch := h.signedBatch(1, 1, 0, "e1")
	h.audit.failAction = "fleet.telemetry.ingest"
	if _, err := h.svc.Ingest(h.ctx, "agent-1", batch); err == nil {
		t.Fatal("a failed admission audit must surface, never be discarded")
	}
	if n, _ := h.transport.CountBatchEvents(h.ctx, "agent-1", h.stream, 1, 1); n != 1 {
		t.Fatalf("the telemetry itself is durable before the audit; stored events = %d, want 1", n)
	}

	h.audit.failAction = ""
	res, err := h.svc.Ingest(h.ctx, "agent-1", batch)
	if err != nil {
		t.Fatalf("exact retry must repair the missing audit: %v", err)
	}
	if !res.Duplicate {
		t.Fatalf("retry of durable telemetry must report the duplicate honestly: %+v", res)
	}
	key := telemetryAuditKey("fleet.telemetry.ingest", batch.Manifest)
	if got := h.audit.recordedOnce(key); got != 1 {
		t.Fatalf("repaired audit lines for %q = %d, want exactly 1", key, got)
	}
	if !h.audit.sameFailedAndRecorded(key) {
		t.Fatal("exact retry changed immutable telemetry admission audit metadata")
	}
	if n, _ := h.transport.CountBatchEvents(h.ctx, "agent-1", h.stream, 1, 1); n != 1 {
		t.Fatalf("audit repair must not duplicate stored events, got %d", n)
	}
}

// TestIngestSensorStateAuditFailureIsRepairedByExactRetry proves the same for durable sensor state:
// the report id keys the audit line, so a retry after an audit outage repairs it exactly once.
func TestIngestSensorStateAuditFailureIsRepairedByExactRetry(t *testing.T) {
	h := newHarness(t)
	report := h.signedSensorState()
	h.audit.failAction = "fleet.sensor_state.ingest"
	if _, err := h.svc.IngestSensorState(h.ctx, "agent-1", report); err == nil {
		t.Fatal("a failed sensor-state audit must surface, never be discarded")
	}

	h.audit.failAction = ""
	if _, err := h.svc.IngestSensorState(h.ctx, "agent-1", report); err != nil {
		t.Fatalf("exact retry must repair the missing sensor-state audit: %v", err)
	}
	key := "fleet.sensor_state.ingest:" + report.ReportID.String()
	if got := h.audit.recordedOnce(key); got != 1 {
		t.Fatalf("repaired sensor-state audit lines = %d, want exactly 1", got)
	}
}

func TestIngestRepairsPendingDetectionsAfterDurableTelemetryOnExactRetry(t *testing.T) {
	h := newHarness(t)
	reconciler := &recordingDetectionReconciler{fail: errors.New("detection reconciliation unavailable")}
	h.svc.SetDetectionReconciler(reconciler)
	batch := h.signedBatch(1, 1, 0, "e1")

	if _, err := h.svc.Ingest(h.ctx, "agent-1", batch); err == nil {
		t.Fatal("post-persistence detection reconciliation failure must be surfaced")
	}
	if reconciler.calls != 1 {
		t.Fatalf("reconciliation calls after first ingest = %d, want 1", reconciler.calls)
	}
	if state, err := h.transport.StreamState(h.ctx, "agent-1", h.stream, 1); err != nil || state.Contiguous != 1 {
		t.Fatalf("durable stream state after reconciliation failure = %+v, %v; want ACK 1", state, err)
	}
	if n, err := h.transport.CountBatchEvents(h.ctx, "agent-1", h.stream, 1, 1); err != nil || n != 1 {
		t.Fatalf("durable event count after reconciliation failure = %d, %v; want 1", n, err)
	}

	reconciler.fail = nil
	result, err := h.svc.Ingest(h.ctx, "agent-1", batch)
	if err != nil {
		t.Fatalf("exact retry must repair pending detections: %v", err)
	}
	if !result.Duplicate || result.Accepted || result.ACK != 1 {
		t.Fatalf("repair retry result = %+v, want duplicate ACK 1", result)
	}
	if reconciler.calls != 2 {
		t.Fatalf("reconciliation calls after repair = %d, want 2", reconciler.calls)
	}
	if n, err := h.transport.CountBatchEvents(h.ctx, "agent-1", h.stream, 1, 1); err != nil || n != 1 {
		t.Fatalf("event count after repair retry = %d, %v; want exactly one", n, err)
	}
}

func TestIngestRebootResetIsNotReplay(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 1, 0, "e1")); err != nil {
		t.Fatal(err)
	}
	res, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(2, 1, 0, "e2"))
	if err != nil {
		t.Fatalf("reboot reset must ingest: %v", err)
	}
	if !res.Accepted || res.Duplicate {
		t.Fatalf("epoch-bumped reset-to-1 must be a fresh accept, not a replay: %+v", res)
	}
}

func TestIngestStaleIncarnationRejected(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(2, 1, 0, "e1")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 5, 4, "e2")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("stale incarnation must be rejected, got %v", err)
	}
}

func TestIngestForwardGapPersisted(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 1, 0, "e1")); err != nil {
		t.Fatal(err)
	}
	res, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 4, 3, "e4"))
	if err != nil {
		t.Fatalf("forward-gap batch must ingest: %v", err)
	}
	if !res.Accepted || !res.GapOpen || res.ACK != 1 {
		t.Fatalf("forward gap result: %+v", res)
	}
	gaps, _ := h.transport.ListGaps(h.ctx, "agent-1", h.stream)
	if len(gaps) != 1 || gaps[0].FromSequence != 2 || gaps[0].ToSequence != 3 {
		t.Fatalf("want materialized gap [2,3], got %+v", gaps)
	}
	if _, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 2, 1, "e2")); err != nil {
		t.Fatal(err)
	}
	res3, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 3, 2, "e3"))
	if err != nil {
		t.Fatal(err)
	}
	if res3.ACK != 4 {
		t.Fatalf("filling 2,3 must advance ACK to 4, got %d", res3.ACK)
	}
	if gaps, _ := h.transport.ListGaps(h.ctx, "agent-1", h.stream); len(gaps) != 0 {
		t.Fatalf("filled gap must not linger, got %+v", gaps)
	}
}

func TestIngestReconcilesInferredGapHistoryAndRepairsAfterCoverageFailure(t *testing.T) {
	h := newHarness(t)
	coverage := &recordingCoverageReconciler{}
	h.svc.SetCoverageReconciler(coverage)

	first := h.signedBatch(1, 1, 0, "e1")
	h.retimeBatch(&first, h.now, h.now.Add(time.Minute))
	if _, err := h.svc.Ingest(h.ctx, "agent-1", first); err != nil {
		t.Fatalf("ingest predecessor: %v", err)
	}
	coverage.reset()

	successor := h.signedBatch(1, 4, 3, "e4")
	h.retimeBatch(&successor, h.now.Add(16*time.Minute), h.now.Add(17*time.Minute))
	if _, err := h.svc.Ingest(h.ctx, "agent-1", successor); err != nil {
		t.Fatalf("ingest gap successor: %v", err)
	}
	requests := coverage.snapshot()
	if len(requests) != 2 {
		t.Fatalf("coverage requests after gap creation = %d, want batch and inferred gap: %#v", len(requests), requests)
	}
	if requests[1].Since != first.Manifest.EventTimeMax || requests[1].Until != successor.Manifest.EventTimeMin {
		t.Fatalf("inferred gap span = [%s,%s], want trusted predecessor/successor [%s,%s]",
			requests[1].Since, requests[1].Until, first.Manifest.EventTimeMax, successor.Manifest.EventTimeMin)
	}

	coverage.reset()
	middle := h.signedBatch(1, 2, 1, "e2")
	h.retimeBatch(&middle, h.now.Add(6*time.Minute), h.now.Add(7*time.Minute))
	if _, err := h.svc.Ingest(h.ctx, "agent-1", middle); err != nil {
		t.Fatalf("shrink inferred gap: %v", err)
	}
	requests = coverage.snapshot()
	if len(requests) != 3 {
		t.Fatalf("coverage after gap shrink = %#v, want batch plus old and new gap spans", requests)
	}
	if requests[1].Since != first.Manifest.EventTimeMax || requests[1].Until != successor.Manifest.EventTimeMin {
		t.Fatalf("historical gap span after shrink = [%s,%s], want [%s,%s]",
			requests[1].Since, requests[1].Until, first.Manifest.EventTimeMax, successor.Manifest.EventTimeMin)
	}
	if requests[2].Since != middle.Manifest.EventTimeMax || requests[2].Until != successor.Manifest.EventTimeMin {
		t.Fatalf("new gap span after shrink = [%s,%s], want [%s,%s]",
			requests[2].Since, requests[2].Until, middle.Manifest.EventTimeMax, successor.Manifest.EventTimeMin)
	}

	coverage.reset()
	coverage.fail = errors.New("coverage append unavailable")
	last := h.signedBatch(1, 3, 2, "e3")
	h.retimeBatch(&last, h.now.Add(11*time.Minute), h.now.Add(12*time.Minute))
	if _, err := h.svc.Ingest(h.ctx, "agent-1", last); err == nil {
		t.Fatal("coverage failure after durable gap resolution must be surfaced")
	}
	if state, err := h.transport.StreamState(h.ctx, "agent-1", h.stream, 1); err != nil || state.Contiguous != 4 {
		t.Fatalf("source state after coverage failure = %+v, %v; want durable ACK 4", state, err)
	}
	if gaps, err := h.transport.ListGaps(h.ctx, "agent-1", h.stream); err != nil || len(gaps) != 0 {
		t.Fatalf("resolved source gap after coverage failure = %#v, %v; want none open", gaps, err)
	}

	coverage.reset()
	coverage.fail = nil
	result, err := h.svc.Ingest(h.ctx, "agent-1", last)
	if err != nil {
		t.Fatalf("exact retry must repair coverage: %v", err)
	}
	if !result.Duplicate || result.ACK != 4 {
		t.Fatalf("repair retry result = %+v, want duplicate ACK 4", result)
	}
	requests = coverage.snapshot()
	if len(requests) != 3 {
		t.Fatalf("repair retry coverage requests = %d, want batch and both resolved gap facts: %#v", len(requests), requests)
	}
	if requests[1].Since != first.Manifest.EventTimeMax || requests[1].Until != successor.Manifest.EventTimeMin {
		t.Fatalf("original resolved gap repair span = [%s,%s], want historical [%s,%s]",
			requests[1].Since, requests[1].Until, first.Manifest.EventTimeMax, successor.Manifest.EventTimeMin)
	}
	if requests[2].Since != middle.Manifest.EventTimeMax || requests[2].Until != successor.Manifest.EventTimeMin {
		t.Fatalf("shrunk resolved gap repair span = [%s,%s], want historical [%s,%s]",
			requests[2].Since, requests[2].Until, middle.Manifest.EventTimeMax, successor.Manifest.EventTimeMin)
	}
}

func TestIngestInferredGapWithoutPredecessorUsesSuccessorPoint(t *testing.T) {
	h := newHarness(t)
	coverage := &recordingCoverageReconciler{}
	h.svc.SetCoverageReconciler(coverage)

	successor := h.signedBatch(1, 4, 3, "e4")
	h.retimeBatch(&successor, h.now.Add(16*time.Minute), h.now.Add(17*time.Minute))
	if _, err := h.svc.Ingest(h.ctx, "agent-1", successor); err != nil {
		t.Fatalf("ingest successor without predecessor: %v", err)
	}
	requests := coverage.snapshot()
	if len(requests) != 2 {
		t.Fatalf("coverage requests = %d, want batch and inferred-gap point: %#v", len(requests), requests)
	}
	if requests[1].Since != successor.Manifest.EventTimeMin || requests[1].Until != successor.Manifest.EventTimeMin {
		t.Fatalf("unknown predecessor gap span = [%s,%s], want honest successor point %s",
			requests[1].Since, requests[1].Until, successor.Manifest.EventTimeMin)
	}
}

func TestIngestForwardJumpTooLargeRejected(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 1, 0, "e1")); err != nil {
		t.Fatal(err)
	}
	far := uint64(1) + maxForwardGap + 1
	if _, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, far, far-1, "eFar")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("oversized jump must be validation error, got %v", err)
	}
}

func TestIngestIdentityMismatchForbidden(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Ingest(h.ctx, "agent-2", h.signedBatch(1, 1, 0, "e1")); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("identity mismatch must be forbidden, got %v", err)
	}
}

func TestIngestRejectionAuditFailureSurfaces(t *testing.T) {
	h := newHarness(t)
	h.audit.failAction = "fleet.telemetry.reject"

	if _, err := h.svc.Ingest(h.ctx, "agent-2", h.signedBatch(1, 1, 0, "e1")); !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("telemetry rejection audit failure = %v, want saturated", err)
	}
	assertNoTelemetryMutation(t, h)
}

func TestIngestGapRejectionAuditFailureSurfaces(t *testing.T) {
	h := newHarness(t)
	h.audit.failAction = "fleet.telemetry.gap_reject"
	report := signedGapForHarness(t, h, "gap-reject-audit")

	if _, err := h.svc.IngestGap(h.ctx, "agent-2", report); !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("telemetry-gap rejection audit failure = %v, want saturated", err)
	}
	gaps, queryErr := h.transport.QueryDeliveryGaps(h.ctx, ports.TelemetryGapQuery{})
	if queryErr != nil || len(gaps) != 0 {
		t.Fatalf("rejected telemetry gap persisted=%d err=%v", len(gaps), queryErr)
	}
}

func TestIngestSensorStateRejectionAuditFailureSurfaces(t *testing.T) {
	h := newHarness(t)
	h.audit.failAction = "fleet.sensor_state.reject"
	report := h.signedSensorState()

	if _, err := h.svc.IngestSensorState(h.ctx, "agent-2", report); !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("sensor-state rejection audit failure = %v, want saturated", err)
	}
}

func TestIngestRejectsForgedHostSessionStreamAndAsset(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*IngestRequest)
	}{
		{"host", func(r *IngestRequest) { r.Manifest.HostID = "forged-host" }},
		{"session", func(r *IngestRequest) { r.Manifest.Position.Session = "forged-session" }},
		{"stream", func(r *IngestRequest) { r.Manifest.StreamID = "forged-stream" }},
		{"asset", func(r *IngestRequest) { r.Manifest.AssetID = "forged-asset" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			req := h.signedBatch(1, 1, 0, "e1")
			tt.mutate(&req)
			req.Manifest.Signature = fleetagent.SignTelemetryManifest(h.priv, req.Manifest)
			if _, err := h.svc.Ingest(h.ctx, "agent-1", req); !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("forged %s must be forbidden, got %v", tt.name, err)
			}
		})
	}
}

func TestIngestRejectsForgedCanonicalPayloadIdentity(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*telemetry.TelemetryEnvelope)
		want   error
	}{
		{"agent", func(e *telemetry.TelemetryEnvelope) { e.AgentID = "forged-agent" }, shared.ErrForbidden},
		{"asset", func(e *telemetry.TelemetryEnvelope) { e.AssetID = "forged-asset" }, shared.ErrForbidden},
		{"session", func(e *telemetry.TelemetryEnvelope) { e.AgentSessionID = "forged-session" }, shared.ErrForbidden},
		{"boot", func(e *telemetry.TelemetryEnvelope) { e.BootID = "forged-boot" }, shared.ErrForbidden},
		{"received-at", func(e *telemetry.TelemetryEnvelope) { e.ReceivedAt = e.ObservedAt.Add(time.Second) }, shared.ErrForbidden},
		{"schema", func(e *telemetry.TelemetryEnvelope) { e.SchemaVersion = 1 }, shared.ErrValidation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			req := h.signedBatchVersion(2, 1, 1, 0, "e1")
			h.resignPayload(&req, 0, tt.mutate)
			if _, err := h.svc.Ingest(h.ctx, "agent-1", req); !errors.Is(err, tt.want) {
				t.Fatalf("forged canonical payload %s: want %v, got %v", tt.name, tt.want, err)
			}
		})
	}
}

func TestIngestRejectsWrapperMetadataThatDisagreesWithSignedPayload(t *testing.T) {
	h := newHarness(t)
	req := h.signedBatch(1, 1, 0, "e1")
	req.Events[0].Class = detection.ClassNetwork
	if _, err := h.svc.Ingest(h.ctx, "agent-1", req); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("wrapper class mismatch must fail, got %v", err)
	}

	h = newHarness(t)
	req = h.signedBatch(1, 1, 0, "e1")
	req.Events[0].ObservedAt = req.Events[0].ObservedAt.Add(time.Second)
	if _, err := h.svc.Ingest(h.ctx, "agent-1", req); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("wrapper observed-at mismatch must fail, got %v", err)
	}
}

func TestIngestAcceptsSchemaV1AndV2(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(seqStr(uint64(version)), func(t *testing.T) {
			h := newHarness(t)
			req := h.signedBatchVersion(version, 1, 1, 0, "e1")
			if _, err := h.svc.Ingest(h.ctx, "agent-1", req); err != nil {
				t.Fatalf("schema v%d must ingest: %v", version, err)
			}
		})
	}
}

func TestIngestFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*IngestRequest)
		is     error
	}{
		{"bad signature", func(r *IngestRequest) { r.Manifest.Signature = "AAAA" }, fleetagent.ErrBadManifestSignature},
		{"unknown key", func(r *IngestRequest) { r.Manifest.KeyID = "unknown" }, shared.ErrForbidden},
		{"unsupported schema", func(r *IngestRequest) { r.Manifest.SchemaVersion = 999 }, shared.ErrValidation},
		{"tampered event body", func(r *IngestRequest) { r.Events[0].Payload = []byte("tampered") }, shared.ErrValidation},
		{"event not in manifest", func(r *IngestRequest) { r.Events[0].EventID = "ghost" }, shared.ErrValidation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			req := h.signedBatch(1, 1, 0, "e1")
			if tt.name == "unsupported schema" {
				req.Manifest.SchemaVersion = 999
				req.Manifest.Signature = fleetagent.SignTelemetryManifest(h.priv, req.Manifest)
			}
			tt.mutate(&req)
			if _, err := h.svc.Ingest(h.ctx, "agent-1", req); !errors.Is(err, tt.is) {
				t.Fatalf("%s: want %v, got %v", tt.name, tt.is, err)
			}
		})
	}
}
