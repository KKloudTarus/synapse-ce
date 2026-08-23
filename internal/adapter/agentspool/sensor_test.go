package agentspool

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var adapterNow = time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

// TestDurableSensorRedactsSecretsAtSource proves A6 (#627): a secret in argv is scrubbed on the agent
// BEFORE it enters the spool, so the persisted payload never contains it. The secret is assembled from
// parts so it does not appear verbatim in source.
func TestDurableSensorRedactsSecretsAtSource(t *testing.T) {
	secret := "topSecret" + "Value123"
	source := newFakeSensor()
	durable := &captureSpool{}
	wrapper := mustSensor(t, source, durable)
	wrapper.now = func() time.Time { return adapterNow }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := wrapper.Start(ctx); err != nil {
		t.Fatal(err)
	}
	source.events <- detection.Event{
		Class: detection.ClassProcess, At: adapterNow.Add(-time.Millisecond), Host: "asset-1",
		Process: &detection.ProcessEvent{PID: 10, PPID: 1, Comm: "mysql", Path: "/usr/bin/mysql",
			Args: []string{"mysql", "--password=" + secret, "app_db"}, UID: 1000},
	}
	select {
	case <-wrapper.Events():
	case <-time.After(time.Second):
		t.Fatal("event not forwarded")
	}
	item := durable.snapshot()[0]
	if strings.Contains(string(item.Payload), secret) {
		t.Fatalf("secret entered the spool unredacted: %s", item.Payload)
	}
	var env telemetry.TelemetryEnvelope
	if err := json.Unmarshal(item.Payload, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if !env.DataQuality.Has(telemetry.QualityRedacted) || env.RedactionPolicyDigest == "" {
		t.Fatalf("redaction was not recorded on the spooled envelope: quality=%s digest=%q", env.DataQuality, env.RedactionPolicyDigest)
	}
	// Non-secret argv context is preserved.
	if env.Event.Process.Args[0] != "mysql" || env.Event.Process.Args[2] != "app_db" {
		t.Fatalf("forensic argv context lost: %#v", env.Event.Process.Args)
	}
	cancel()
	if err := wrapper.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDurableSensorNormalizesAndPersistsBeforeForwarding(t *testing.T) {
	source := newFakeSensor()
	durable := &captureSpool{}
	wrapper := mustSensor(t, source, durable)
	wrapper.now = func() time.Time { return adapterNow }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := wrapper.Start(ctx); err != nil {
		t.Fatal(err)
	}
	event := processEvent()
	source.events <- event
	select {
	case got := <-wrapper.Events():
		if got.Process.Path != event.Process.Path {
			t.Fatalf("forwarded event = %#v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("event was not forwarded")
	}
	items := durable.snapshot()
	if len(items) != 1 {
		t.Fatalf("spooled items = %d", len(items))
	}
	item := items[0]
	if item.Kind != ports.SpoolRecordTelemetry || item.Priority != fleetagent.PriorityP3 || item.MustNotShed {
		t.Fatalf("spool classification = %#v", item)
	}
	var envelope telemetry.TelemetryEnvelope
	if err := json.Unmarshal(item.Payload, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if err := envelope.Validate(); err != nil {
		t.Fatalf("canonical envelope invalid: %v", err)
	}
	if envelope.EventClass != detection.ClassProcess || envelope.Sequence != 1 || envelope.AgentID != "agent-1" || envelope.BootID != "boot-1" {
		t.Fatalf("envelope attribution = %#v", envelope)
	}
	if envelope.Event.Process.StartTimeNanos != 0 || !envelope.DataQuality.Has(telemetry.QualityMissingStartTime) {
		t.Fatalf("legacy sensor limitations were not represented honestly: %#v", envelope.Event.Process)
	}
	if !envelope.DataQuality.Has(telemetry.QualityKernelTimestampUnavailable) || !envelope.OccurredAt.Equal(envelope.ObservedAt) {
		t.Fatalf("userspace-only timestamp was presented as kernel truth: quality=%s occurred=%s observed=%s",
			envelope.DataQuality, envelope.OccurredAt, envelope.ObservedAt)
	}
	cancel()
	if err := wrapper.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDurableSensorClassifiesCriticalTelemetryP2NeverShed(t *testing.T) {
	for _, event := range []detection.Event{fileEvent(), privilegeEvent()} {
		t.Run(string(event.Class), func(t *testing.T) {
			source := newFakeSensor()
			durable := &captureSpool{}
			wrapper := mustSensor(t, source, durable)
			wrapper.now = func() time.Time { return adapterNow }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := wrapper.Start(ctx); err != nil {
				t.Fatal(err)
			}
			source.events <- event
			select {
			case <-wrapper.Events():
			case <-time.After(time.Second):
				t.Fatal("event not forwarded")
			}
			item := durable.snapshot()[0]
			if item.Priority != fleetagent.PriorityP2 || !item.MustNotShed {
				t.Fatalf("critical item = %#v", item)
			}
			cancel()
			_ = wrapper.Close()
		})
	}
}

func TestDurableSensorUsesIndependentPerClassSequences(t *testing.T) {
	source := newFakeSensor()
	durable := &captureSpool{}
	wrapper := mustSensor(t, source, durable)
	wrapper.now = func() time.Time { return adapterNow }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := wrapper.Start(ctx); err != nil {
		t.Fatal(err)
	}
	for _, event := range []detection.Event{processEvent(), fileEvent(), processEvent(), fileEvent()} {
		source.events <- event
		<-wrapper.Events()
	}
	items := durable.snapshot()
	want := []uint64{1, 1, 2, 2}
	for index, item := range items {
		var envelope telemetry.TelemetryEnvelope
		if err := json.Unmarshal(item.Payload, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Sequence != want[index] {
			t.Errorf("item %d sequence = %d, want %d", index, envelope.Sequence, want[index])
		}
	}
	cancel()
	_ = wrapper.Close()
}

func TestDurableSensorRetriesSaturationInsteadOfDropping(t *testing.T) {
	source := newFakeSensor()
	durable := &captureSpool{errors: []error{ports.ErrTelemetrySpoolSaturated, nil}}
	wrapper := mustSensor(t, source, durable)
	wrapper.now = func() time.Time { return adapterNow }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := wrapper.Start(ctx); err != nil {
		t.Fatal(err)
	}
	source.events <- fileEvent()
	select {
	case <-wrapper.Events():
	case <-time.After(time.Second):
		t.Fatal("saturated event was not retried")
	}
	if durable.calls != 2 {
		t.Fatalf("enqueue calls = %d, want 2", durable.calls)
	}
	if wrapper.Dropped()[detection.ClassFile] != 0 {
		t.Fatal("successfully retried event counted as dropped")
	}
	cancel()
	_ = wrapper.Close()
}

func TestDurableSensorShedsP3SaturationWithoutHeadOfLineBlocking(t *testing.T) {
	source := newFakeSensor()
	durable := &captureSpool{errors: []error{ports.ErrTelemetrySpoolSaturated}}
	wrapper := mustSensor(t, source, durable)
	wrapper.now = func() time.Time { return adapterNow }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := wrapper.Start(ctx); err != nil {
		t.Fatal(err)
	}
	source.events <- processEvent()
	select {
	case <-wrapper.Events():
	case <-time.After(100 * time.Millisecond):
		t.Fatal("sheddable P3 saturation blocked the sensor")
	}
	if durable.calls != 1 || wrapper.Dropped()[detection.ClassProcess] != 1 {
		t.Fatalf("calls=%d dropped=%v", durable.calls, wrapper.Dropped())
	}
	cancel()
	_ = wrapper.Close()
}

func TestDurableSensorFailureDegradesCoverage(t *testing.T) {
	source := newFakeSensor()
	durable := &captureSpool{errors: []error{errors.New("disk I/O failed")}}
	wrapper := mustSensor(t, source, durable)
	wrapper.now = func() time.Time { return adapterNow }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := wrapper.Start(ctx); err != nil {
		t.Fatal(err)
	}
	source.events <- processEvent()
	select {
	case <-wrapper.Events():
	case <-time.After(time.Second):
		t.Fatal("detection path should continue after recorded telemetry failure")
	}
	coverage := wrapper.Coverage()
	if len(coverage) != 1 || coverage[0].State != detection.StateDegraded || coverage[0].Reason == "" {
		t.Fatalf("coverage = %#v", coverage)
	}
	if wrapper.Dropped()[detection.ClassProcess] != 1 {
		t.Fatalf("dropped = %#v", wrapper.Dropped())
	}
	cancel()
	_ = wrapper.Close()
}

func TestDurableSensorFailureDoesNotMaskFailedCoverage(t *testing.T) {
	source := newFakeSensor()
	source.coverage = []detection.ClassCoverage{{
		Class: detection.ClassProcess, HostID: "asset-1", AgentID: "agent-1",
		State: detection.StateFailed, Reason: "probe attach failed", Since: adapterNow,
	}}
	durable := &captureSpool{errors: []error{errors.New("disk I/O failed")}}
	wrapper := mustSensor(t, source, durable)
	wrapper.now = func() time.Time { return adapterNow }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := wrapper.Start(ctx); err != nil {
		t.Fatal(err)
	}
	source.events <- processEvent()
	select {
	case <-wrapper.Events():
	case <-time.After(time.Second):
		t.Fatal("detection path should continue after recorded telemetry failure")
	}
	coverage := wrapper.Coverage()
	if len(coverage) != 1 || coverage[0].State != detection.StateFailed || coverage[0].Reason != "probe attach failed" {
		t.Fatalf("failed source coverage was masked: %#v", coverage)
	}
	cancel()
	_ = wrapper.Close()
}

func TestSaturationRetryDelayIsJitteredWithinBounds(t *testing.T) {
	seen := make(map[time.Duration]struct{})
	for range 100 {
		delay := saturationRetryDelay()
		if delay < minSaturationRetryDelay || delay > maxSaturationRetryDelay {
			t.Fatalf("retry delay %s outside [%s, %s]", delay, minSaturationRetryDelay, maxSaturationRetryDelay)
		}
		seen[delay] = struct{}{}
	}
	if len(seen) == 1 {
		t.Fatal("retry delay remained fixed")
	}
}

func TestDurableSensorRejectsBadDependenciesAndDoubleStart(t *testing.T) {
	identity := testIdentity()
	if _, err := NewDurableSensor(nil, &captureSpool{}, identity); err == nil {
		t.Fatal("nil source accepted")
	}
	if _, err := NewDurableSensor(newFakeSensor(), nil, identity); err == nil {
		t.Fatal("nil spool accepted")
	}
	identity.BootID = ""
	if _, err := NewDurableSensor(newFakeSensor(), &captureSpool{}, identity); err == nil {
		t.Fatal("incomplete identity accepted")
	}
	wrapper := mustSensor(t, newFakeSensor(), &captureSpool{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := wrapper.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := wrapper.Start(ctx); err == nil {
		t.Fatal("double Start accepted")
	}
	cancel()
	_ = wrapper.Close()
}

func mustSensor(t *testing.T, source ports.DetectionSensor, durable ports.TelemetrySpool) *DurableSensor {
	t.Helper()
	sensor, err := NewDurableSensor(source, durable, testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	return sensor
}

func testIdentity() SensorIdentity {
	return SensorIdentity{
		AgentID: "agent-1", AssetID: "asset-1", AgentSession: "session-1", BootID: "boot-1",
		SensorID: "ebpf", SensorVersion: "1",
	}
}

func processEvent() detection.Event {
	return detection.Event{
		Class: detection.ClassProcess, At: adapterNow.Add(-time.Millisecond), Host: "asset-1",
		Process: &detection.ProcessEvent{PID: 10, PPID: 1, Comm: "curl", Path: "/usr/bin/curl", Args: []string{"curl", "https://example.test"}, UID: 1000},
	}
}

func fileEvent() detection.Event {
	return detection.Event{
		Class: detection.ClassFile, At: adapterNow.Add(-time.Millisecond), Host: "asset-1",
		File: &detection.FileEvent{Op: "write", Path: "/etc/shadow", PID: 10, Comm: "vi"},
	}
}

func privilegeEvent() detection.Event {
	return detection.Event{
		Class: detection.ClassPrivilege, At: adapterNow.Add(-time.Millisecond), Host: "asset-1",
		Privilege: &detection.PrivilegeEvent{Kind: "setuid", PID: 10, Comm: "sudo", FromUID: 1000, ToUID: 0},
	}
}

type fakeSensor struct {
	events   chan detection.Event
	coverage []detection.ClassCoverage
	once     sync.Once
}

func newFakeSensor() *fakeSensor                     { return &fakeSensor{events: make(chan detection.Event)} }
func (f *fakeSensor) Start(context.Context) error    { return nil }
func (f *fakeSensor) Events() <-chan detection.Event { return f.events }
func (f *fakeSensor) Coverage() []detection.ClassCoverage {
	if f.coverage != nil {
		return append([]detection.ClassCoverage(nil), f.coverage...)
	}
	return []detection.ClassCoverage{{Class: detection.ClassProcess, HostID: "asset-1", AgentID: "agent-1", State: detection.StateActive, Since: adapterNow}}
}
func (f *fakeSensor) Dropped() map[detection.Class]uint64 { return nil }
func (f *fakeSensor) Close() error {
	f.once.Do(func() { close(f.events) })
	return nil
}

type captureSpool struct {
	mu     sync.Mutex
	items  []ports.SpoolItem
	errors []error
	calls  int
}

func (c *captureSpool) Enqueue(_ context.Context, item ports.SpoolItem) (fleetagent.StreamPosition, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if len(c.errors) > 0 {
		err := c.errors[0]
		c.errors = c.errors[1:]
		if err != nil {
			return fleetagent.StreamPosition{}, err
		}
	}
	item.Payload = append([]byte(nil), item.Payload...)
	c.items = append(c.items, item)
	return fleetagent.StreamPosition{Priority: item.Priority, Epoch: 1, Sequence: uint64(len(c.items)), Session: "s", Boot: "b"}, nil
}
func (c *captureSpool) snapshot() []ports.SpoolItem {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]ports.SpoolItem(nil), c.items...)
}
func (c *captureSpool) Peek(context.Context, ports.PeekSpoolRequest) ([]ports.SpoolRecord, error) {
	return nil, nil
}
func (c *captureSpool) Ack(context.Context, ports.SpoolACK) (ports.SpoolACKResult, error) {
	return ports.SpoolACKResult{}, nil
}
func (c *captureSpool) Flush(context.Context) error                    { return nil }
func (c *captureSpool) Gaps(context.Context) ([]ports.SpoolGap, error) { return nil, nil }
func (c *captureSpool) Stats(context.Context) (ports.SpoolStats, error) {
	return ports.SpoolStats{}, nil
}
func (c *captureSpool) Close() error { return nil }
