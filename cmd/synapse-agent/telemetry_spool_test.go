package main

import (
	"context"
	"runtime"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
)

func TestParsePositiveBytes(t *testing.T) {
	for _, tt := range []struct {
		input string
		def   int64
		want  int64
	}{
		{"", 99, 99},
		{"1048576", 99, 1048576},
		{"0", 99, 99},
		{"-1", 99, 99},
		{"not-a-number", 99, 99},
	} {
		if got := parsePositiveBytes(tt.input, tt.def); got != tt.want {
			t.Errorf("parsePositiveBytes(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestCurrentBootIDIsHonestAboutPlatform(t *testing.T) {
	id, err := currentBootID()
	if runtime.GOOS == "linux" {
		if err != nil || id.IsZero() {
			t.Fatalf("Linux boot id = %q, %v", id, err)
		}
		return
	}
	if err == nil || !id.IsZero() {
		t.Fatalf("unsupported platform fabricated boot id %q, %v", id, err)
	}
}

func TestOpenTelemetrySpoolUsesCanonicalIdentity(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("live telemetry spool is paired with the Linux-only eBPF sensor")
	}
	r := &runner{cfg: config{stateDir: t.TempDir(), spoolBytes: 1 << 20}}
	durable, identity, err := r.openTelemetrySpool(context.Background(), fleetclient.Credential{AgentID: " agent-1 "})
	if err != nil {
		t.Fatal(err)
	}
	defer durable.Close()
	if identity.AgentID != "agent-1" || identity.AssetID != identity.AgentID || identity.AgentSession != identity.AgentID || identity.BootID.IsZero() {
		t.Fatalf("identity = %#v", identity)
	}
}

func TestOpenTelemetrySpoolRejectsMissingAgentIdentity(t *testing.T) {
	r := &runner{cfg: config{stateDir: t.TempDir(), spoolBytes: 1 << 20}}
	if durable, _, err := r.openTelemetrySpool(context.Background(), fleetclient.Credential{}); err == nil {
		_ = durable.Close()
		t.Fatal("missing canonical agent id accepted")
	}
}
