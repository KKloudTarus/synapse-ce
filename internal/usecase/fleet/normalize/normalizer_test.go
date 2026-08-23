package normalize

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

var (
	occurred = time.Unix(1_700_000_000, 0).UTC()
	observed = occurred.Add(3 * time.Millisecond)
)

func baseProcess() DecodedEvent {
	return DecodedEvent{
		Class:          detection.ClassProcess,
		AgentID:        "agent-1",
		AgentSessionID: "session-1",
		AssetID:        "asset-1",
		BootID:         "boot-1",
		StreamID:       "stream-1",
		Sequence:       42,
		OccurredAt:     occurred,
		ObservedAt:     observed,
		Resource:       telemetry.ResourceContext{Host: "h1"},
		Process: &DecodedProcess{
			Kind: "exec", PID: 1234, PPID: 1000,
			StartTimeNanos: 5555, ParentStartTimeNanos: 1111,
			Comm: "curl", Path: "/usr/bin/curl", Args: []string{"curl", "http://x"}, UID: 0,
		},
	}
}

func TestNormalizeProcessGolden(t *testing.T) {
	env, err := Normalizer{}.Normalize(baseProcess())
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if env.SchemaVersion != telemetry.SchemaVersion {
		t.Errorf("schema version = %d", env.SchemaVersion)
	}
	if env.EventClass != detection.ClassProcess || env.EventType != "process.exec" {
		t.Errorf("class/type = %s / %s", env.EventClass, env.EventType)
	}
	if !env.OccurredAt.Equal(occurred) || !env.ObservedAt.Equal(observed) {
		t.Errorf("timestamps not carried through: occurred=%s observed=%s", env.OccurredAt, env.ObservedAt)
	}
	if !env.ReceivedAt.IsZero() {
		t.Errorf("received-at must be zero on the agent side, got %s", env.ReceivedAt)
	}
	wantEntity := telemetry.ProcessEntityID("asset-1", "boot-1", 1234, 5555)
	if env.Event.Process.EntityID != wantEntity {
		t.Errorf("entity id = %q, want %q", env.Event.Process.EntityID, wantEntity)
	}
	wantParent := telemetry.ProcessEntityID("asset-1", "boot-1", 1000, 1111)
	if env.Event.Process.ParentEntityID != wantParent {
		t.Errorf("parent entity id = %q, want %q", env.Event.Process.ParentEntityID, wantParent)
	}
	wantEventID := telemetry.DeriveEventID("asset-1", "boot-1", "stream-1", 42, detection.ClassProcess, occurred.UnixNano())
	if env.EventID != wantEventID {
		t.Errorf("event id = %q, want %q", env.EventID, wantEventID)
	}
	if !env.DataQuality.IsClean() {
		t.Errorf("clean process must have no quality flags, got %s", env.DataQuality)
	}
	if err := env.Validate(); err != nil {
		t.Errorf("normalized envelope must validate: %v", err)
	}
}

func TestNormalizeNetworkGolden(t *testing.T) {
	d := DecodedEvent{
		Class: detection.ClassNetwork, AgentID: "a", AgentSessionID: "session-1", AssetID: "asset-1", BootID: "boot-1", StreamID: "s", Sequence: 1,
		OccurredAt: occurred, ObservedAt: observed,
		Network: &DecodedNetwork{Kind: "connect", Proto: "tcp", Direction: "egress", RemoteAddr: "9.9.9.9", RemotePort: 53, PID: 1234, ProcStartTimeNanos: 5555, Comm: "curl"},
	}
	env, err := Normalizer{}.Normalize(d)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if env.EventType != "network.connect" {
		t.Errorf("event type = %q", env.EventType)
	}
	want := telemetry.ProcessEntityID("asset-1", "boot-1", 1234, 5555)
	if env.Event.Network.ProcessEntityID != want {
		t.Errorf("flow must link to the process entity id: got %q want %q", env.Event.Network.ProcessEntityID, want)
	}
	if err := env.Validate(); err != nil {
		t.Errorf("validate: %v", err)
	}
}

func TestNormalizeFileGolden(t *testing.T) {
	d := DecodedEvent{
		Class: detection.ClassFile, AgentID: "a", AgentSessionID: "session-1", AssetID: "asset-1", BootID: "boot-1", StreamID: "s", Sequence: 1,
		OccurredAt: occurred, ObservedAt: observed,
		File: &DecodedFile{Op: "write", Path: "/etc/shadow", Device: 66, Inode: 128, PID: 1234, ProcStartTimeNanos: 5555, Comm: "vi"},
	}
	env, err := Normalizer{}.Normalize(d)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if env.EventType != "file.write" {
		t.Errorf("event type = %q (must be a real op, never a hardcoded 'open')", env.EventType)
	}
	if got := env.Event.File.TargetID(); got != telemetry.FileTargetID("/etc/shadow", 66, 128, "") {
		t.Errorf("file target id mismatch: %q", got)
	}
	if err := env.Validate(); err != nil {
		t.Errorf("validate: %v", err)
	}
}

func TestNormalizePrivilegeGolden(t *testing.T) {
	d := DecodedEvent{
		Class: detection.ClassPrivilege, AgentID: "a", AgentSessionID: "session-1", AssetID: "asset-1", BootID: "boot-1", StreamID: "s", Sequence: 1,
		OccurredAt: occurred, ObservedAt: observed,
		Privilege: &DecodedPrivilege{Kind: "setuid", PID: 1234, ProcStartTimeNanos: 5555, FromUID: 1000, ToUID: 0, Comm: "sudo"},
	}
	env, err := Normalizer{}.Normalize(d)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if env.EventType != "privilege.setuid" {
		t.Errorf("event type = %q", env.EventType)
	}
	if env.Event.Privilege.ToUID != 0 || env.Event.Privilege.FromUID != 1000 {
		t.Errorf("uid transition not carried")
	}
	if err := env.Validate(); err != nil {
		t.Errorf("validate: %v", err)
	}
}

func TestNormalizeKernelTimestampFallback(t *testing.T) {
	d := baseProcess()
	d.OccurredAt = time.Time{} // sensor could not read a kernel timestamp
	env, err := Normalizer{}.Normalize(d)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !env.OccurredAt.Equal(env.ObservedAt) {
		t.Errorf("fallback must set occurred = observed, got %s vs %s", env.OccurredAt, env.ObservedAt)
	}
	if !env.DataQuality.Has(telemetry.QualityKernelTimestampUnavailable) {
		t.Errorf("fallback must set the kernel-ts-unavailable flag, got %s", env.DataQuality)
	}
	if err := env.Validate(); err != nil {
		t.Errorf("validate: %v", err)
	}
}

func TestNormalizeClockSkewClamp(t *testing.T) {
	d := baseProcess()
	d.OccurredAt = observed.Add(time.Second) // kernel ts implausibly after decode: clock-domain skew
	env, err := Normalizer{}.Normalize(d)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if env.OccurredAt.After(env.ObservedAt) {
		t.Errorf("occurred must never be after observed after clamp")
	}
	if !env.DataQuality.Has(telemetry.QualityKernelTimestampUnavailable) {
		t.Errorf("a clamped skewed ts must be flagged")
	}
}

func TestNormalizeQualityFlags(t *testing.T) {
	d := baseProcess()
	d.Process.ArgsTruncated = true
	d.Process.PathTruncated = true
	d.Process.StartTimeNanos = 0 // unknown start time
	d.Process.PPID = 0           // unknown parent
	env, err := Normalizer{}.Normalize(d)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	for _, f := range []telemetry.DataQuality{
		telemetry.QualityTruncatedArgv, telemetry.QualityTruncatedPath,
		telemetry.QualityMissingStartTime, telemetry.QualityMissingPPID,
	} {
		if !env.DataQuality.Has(f) {
			t.Errorf("expected quality flag %s to be set; got %s", f, env.DataQuality)
		}
	}
	if !env.Event.Process.ParentEntityID.IsZero() {
		t.Errorf("missing PPID must leave parent entity id empty")
	}
}

func TestNormalizeParentStartTimeMissing(t *testing.T) {
	// A KNOWN parent pid but an UNKNOWN parent start time must NOT synthesize a start=0 parent id (it
	// would mis-match the parent's real entity and could alias under PID reuse — the D4 failure mode).
	// The link is left empty and the gap is flagged.
	d := baseProcess()
	d.Process.PPID = 1000
	d.Process.ParentStartTimeNanos = 0
	env, err := Normalizer{}.Normalize(d)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !env.Event.Process.ParentEntityID.IsZero() {
		t.Errorf("unknown parent start time must leave ParentEntityID empty, got %q", env.Event.Process.ParentEntityID)
	}
	if !env.DataQuality.Has(telemetry.QualityMissingParentStartTime) {
		t.Errorf("must flag QualityMissingParentStartTime; got %s", env.DataQuality)
	}
	if env.DataQuality.Has(telemetry.QualityMissingPPID) {
		t.Errorf("PPID is known, so QualityMissingPPID must NOT be set; got %s", env.DataQuality)
	}
	// A known parent pid WITH a start time still derives the parent id (the normal, trustworthy path).
	d.Process.ParentStartTimeNanos = 4242
	env2, _ := Normalizer{}.Normalize(d)
	if env2.Event.Process.ParentEntityID != telemetry.ProcessEntityID("asset-1", "boot-1", 1000, 4242) {
		t.Errorf("a known parent start time must derive the parent entity id")
	}
	if env2.DataQuality.Has(telemetry.QualityMissingParentStartTime) {
		t.Errorf("a resolved parent must not carry the missing-parent-start flag")
	}
}

func TestNormalizeDeterministic(t *testing.T) {
	a, err := Normalizer{}.Normalize(baseProcess())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Normalizer{}.Normalize(baseProcess())
	if err != nil {
		t.Fatal(err)
	}
	if a.EventID != b.EventID || a.Event.Process.EntityID != b.Event.Process.EntityID {
		t.Fatalf("normalization must be deterministic: %q/%q vs %q/%q", a.EventID, a.Event.Process.EntityID, b.EventID, b.Event.Process.EntityID)
	}
}

func TestNormalizePIDReuseDistinct(t *testing.T) {
	first := baseProcess()
	first.Process.StartTimeNanos = 1000
	second := baseProcess()
	second.Process.StartTimeNanos = 2000 // same PID, later start = a reused PID, distinct process
	ea, _ := Normalizer{}.Normalize(first)
	eb, _ := Normalizer{}.Normalize(second)
	if ea.Event.Process.EntityID == eb.Event.Process.EntityID {
		t.Fatalf("PID reuse with a new start time must produce distinct entity ids")
	}
}

func TestNormalizeLinkProcessOptional(t *testing.T) {
	d := DecodedEvent{
		Class: detection.ClassNetwork, AgentID: "a", AgentSessionID: "session-1", AssetID: "asset-1", BootID: "boot-1", StreamID: "s", Sequence: 1,
		OccurredAt: occurred, ObservedAt: observed,
		Network: &DecodedNetwork{Kind: "connect", Proto: "udp", Direction: "egress", RemoteAddr: "1.1.1.1", RemotePort: 53, PID: 1234, ProcStartTimeNanos: 0},
	}
	env, err := Normalizer{}.Normalize(d)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !env.Event.Network.ProcessEntityID.IsZero() {
		t.Errorf("an unresolvable process start time must leave the link empty, not a wrong-but-present id")
	}
}

func TestNormalizeErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DecodedEvent)
	}{
		{"no observed-at", func(d *DecodedEvent) { d.ObservedAt = time.Time{} }},
		{"no payload", func(d *DecodedEvent) { d.Process = nil }},
		{"two payloads", func(d *DecodedEvent) {
			d.Network = &DecodedNetwork{Kind: "connect", Proto: "tcp", Direction: "egress", RemoteAddr: "1.1.1.1", RemotePort: 1}
		}},
		{"class-payload mismatch", func(d *DecodedEvent) { d.Class = detection.ClassNetwork }},
		{"unknown class", func(d *DecodedEvent) { d.Class = "bogus" }},
		{"invalid payload (bad kind)", func(d *DecodedEvent) { d.Process.Kind = "weird" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := baseProcess()
			tt.mutate(&d)
			_, err := Normalizer{}.Normalize(d)
			if err == nil {
				t.Fatalf("expected an error")
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("error must wrap shared.ErrValidation, got %v", err)
			}
		})
	}
}
