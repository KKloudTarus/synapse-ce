//go:build !linux

package ebpf

import (
	"context"
	"time"
)

// LibraryLoadEvent is the off-Linux stub of the runtime library-load evidence record.
type LibraryLoadEvent struct {
	PID  uint32
	UID  uint32
	Comm string
	Path string
	At   time.Time
}

// LibraryLoadSensor is the off-Linux stub: the openat tracepoint needs Linux eBPF.
type LibraryLoadSensor struct{}

// NewLibraryLoadSensor returns a stub sensor.
func NewLibraryLoadSensor() *LibraryLoadSensor { return &LibraryLoadSensor{} }

// Start always fails off Linux; runtime reachability is raise-only, so its absence changes no verdict.
func (s *LibraryLoadSensor) Start(context.Context) error { return ErrUnavailable }

// Events returns a closed channel off Linux.
func (s *LibraryLoadSensor) Events() <-chan LibraryLoadEvent {
	ch := make(chan LibraryLoadEvent)
	close(ch)
	return ch
}

// Close is a no-op off Linux.
func (s *LibraryLoadSensor) Close() error { return nil }
