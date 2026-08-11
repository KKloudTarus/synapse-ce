//go:build !linux

// Package ebpf degrades the detection sensor to a no-op off Linux: eBPF tracepoints and kprobes are
// Linux-only. NewSensor still exists so the composition root compiles everywhere; Start reports every
// class as a failed observation gap (never as a clean host) and returns ErrSensorUnavailable.
package ebpf

import (
	"context"
	"errors"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ErrSensorUnavailable means the detection sensor cannot run here (Linux only).
var ErrSensorUnavailable = errors.New("ebpf detection sensor unavailable: Linux only")

// Sensor is the off-Linux stub.
type Sensor struct {
	host      shared.ID
	agentID   shared.ID
	events    chan detection.Event
	closeOnce sync.Once
}

// NewSensor returns a stub sensor.
func NewSensor(host, agentID shared.ID, _ []detection.Class) *Sensor {
	return &Sensor{host: host, agentID: agentID, events: make(chan detection.Event)}
}

// Start always fails off Linux, reporting every class as a failed gap first.
func (s *Sensor) Start(_ context.Context) error { return ErrSensorUnavailable }

// Events returns a channel that never yields off Linux.
func (s *Sensor) Events() <-chan detection.Event { return s.events }

// Coverage reports every class as a failed observation gap off Linux — never clean.
func (s *Sensor) Coverage() []detection.ClassCoverage {
	out := make([]detection.ClassCoverage, 0, 4)
	for _, cls := range detection.Classes() {
		out = append(out, detection.ClassCoverage{
			Class: cls, HostID: s.host, AgentID: s.agentID, State: detection.StateFailed,
			Reason: "eBPF sensor unavailable: Linux only",
		})
	}
	return out
}

// Dropped reports no drops off Linux (nothing is observed).
func (s *Sensor) Dropped() map[detection.Class]uint64 { return map[detection.Class]uint64{} }

// Close closes the stub channel. Idempotent, matching the Linux Sensor's contract, so a double Close (or
// a defer plus an explicit Close) does not panic on either build.
func (s *Sensor) Close() error {
	s.closeOnce.Do(func() { close(s.events) })
	return nil
}
