package telemetry

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func validProcess() *ProcessObservation {
	return &ProcessObservation{Kind: "exec", PID: 10, EntityID: "pe_x", Comm: "sh", Path: "/bin/sh"}
}
func validNetwork() *NetworkObservation {
	return &NetworkObservation{Kind: "connect", Proto: "tcp", Direction: "egress", RemoteAddr: "1.2.3.4", RemotePort: 443}
}
func validFile() *FileObservation {
	return &FileObservation{Op: "open", Path: "/etc/shadow"}
}
func validPriv() *PrivilegeObservation {
	return &PrivilegeObservation{Kind: "setuid", PID: 10, ToUID: 0}
}

func TestTelemetryEventValidate(t *testing.T) {
	tests := []struct {
		name    string
		event   TelemetryEvent
		wantErr bool
	}{
		{"valid process", TelemetryEvent{Class: detection.ClassProcess, Process: validProcess()}, false},
		{"valid network", TelemetryEvent{Class: detection.ClassNetwork, Network: validNetwork()}, false},
		{"valid file", TelemetryEvent{Class: detection.ClassFile, File: validFile()}, false},
		{"valid privilege", TelemetryEvent{Class: detection.ClassPrivilege, Privilege: validPriv()}, false},
		{"unknown class", TelemetryEvent{Class: "bogus", Process: validProcess()}, true},
		{"no payload", TelemetryEvent{Class: detection.ClassProcess}, true},
		{"two payloads", TelemetryEvent{Class: detection.ClassProcess, Process: validProcess(), Network: validNetwork()}, true},
		{"payload mismatches class", TelemetryEvent{Class: detection.ClassProcess, Network: validNetwork()}, true},
		{"process bad kind", TelemetryEvent{Class: detection.ClassProcess, Process: &ProcessObservation{Kind: "weird", PID: 1, EntityID: "pe_x", Comm: "x"}}, true},
		{"process no pid", TelemetryEvent{Class: detection.ClassProcess, Process: &ProcessObservation{Kind: "exec", PID: 0, EntityID: "pe_x", Comm: "x"}}, true},
		{"process no entity id", TelemetryEvent{Class: detection.ClassProcess, Process: &ProcessObservation{Kind: "exec", PID: 1, Comm: "x"}}, true},
		{"process no comm/path", TelemetryEvent{Class: detection.ClassProcess, Process: &ProcessObservation{Kind: "exec", PID: 1, EntityID: "pe_x"}}, true},
		{"network bad proto", TelemetryEvent{Class: detection.ClassNetwork, Network: &NetworkObservation{Kind: "connect", Proto: "sctp", Direction: "egress", RemoteAddr: "1.1.1.1", RemotePort: 1}}, true},
		{"network bad direction", TelemetryEvent{Class: detection.ClassNetwork, Network: &NetworkObservation{Kind: "connect", Proto: "tcp", Direction: "sideways", RemoteAddr: "1.1.1.1", RemotePort: 1}}, true},
		{"network no remote", TelemetryEvent{Class: detection.ClassNetwork, Network: &NetworkObservation{Kind: "connect", Proto: "tcp", Direction: "egress", RemotePort: 1}}, true},
		{"network port out of range", TelemetryEvent{Class: detection.ClassNetwork, Network: &NetworkObservation{Kind: "connect", Proto: "tcp", Direction: "egress", RemoteAddr: "1.1.1.1", RemotePort: 70000}}, true},
		{"file bad op", TelemetryEvent{Class: detection.ClassFile, File: &FileObservation{Op: "chmod", Path: "/x"}}, true},
		{"file no path", TelemetryEvent{Class: detection.ClassFile, File: &FileObservation{Op: "open"}}, true},
		{"priv bad kind", TelemetryEvent{Class: detection.ClassPrivilege, Privilege: &PrivilegeObservation{Kind: "sudo", PID: 1}}, true},
		{"priv capset no cap", TelemetryEvent{Class: detection.ClassPrivilege, Privilege: &PrivilegeObservation{Kind: "capset", PID: 1}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.event.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err=%v, wantErr=%t", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("error must wrap shared.ErrValidation, got %v", err)
			}
		})
	}
}

func TestTelemetryEventEventType(t *testing.T) {
	tests := []struct {
		event TelemetryEvent
		want  string
	}{
		{TelemetryEvent{Class: detection.ClassProcess, Process: &ProcessObservation{Kind: "exec"}}, "process.exec"},
		{TelemetryEvent{Class: detection.ClassProcess, Process: &ProcessObservation{Kind: "fork"}}, "process.fork"},
		{TelemetryEvent{Class: detection.ClassNetwork, Network: &NetworkObservation{Kind: "connect"}}, "network.connect"},
		{TelemetryEvent{Class: detection.ClassFile, File: &FileObservation{Op: "write"}}, "file.write"},
		{TelemetryEvent{Class: detection.ClassPrivilege, Privilege: &PrivilegeObservation{Kind: "capset"}}, "privilege.capset"},
	}
	for _, tt := range tests {
		if got := tt.event.EventType(); got != tt.want {
			t.Errorf("EventType() = %q, want %q", got, tt.want)
		}
	}
}

func TestTelemetryEventCloneIsDeep(t *testing.T) {
	orig := TelemetryEvent{Class: detection.ClassProcess, Process: &ProcessObservation{Kind: "exec", PID: 1, EntityID: "pe_x", Comm: "x", Args: []string{"a", "b"}}}
	c := orig.clone()
	c.Process.Args[0] = "MUTATED"
	c.Process.Comm = "changed"
	if orig.Process.Args[0] != "a" {
		t.Fatalf("clone must not alias argv slice")
	}
	if orig.Process.Comm != "x" {
		t.Fatalf("clone must not alias payload")
	}
}
