package spool

import (
	"errors"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var (
	// ErrSaturated means the quota could not be satisfied without deleting a
	// non-sheddable P0..P2 record. Producers should apply backpressure.
	ErrSaturated = ports.ErrTelemetrySpoolSaturated
	// ErrClosed means the spool no longer accepts or serves operations.
	ErrClosed = errors.New("telemetry spool closed")
	// ErrFailed means a durability operation had an ambiguous outcome. The
	// spool fails stop until it is closed and recovered from disk.
	ErrFailed = errors.New("telemetry spool durability failure")
	// ErrGapJournalFull means loss evidence cannot be retained within its
	// reserved share of the spool quota. The spool fails stop rather than erase
	// evidence or grow beyond its configured disk bound.
	ErrGapJournalFull = errors.New("telemetry spool gap journal full")
	// ErrLocked means another process already owns the spool directory.
	ErrLocked = errors.New("telemetry spool already open")
	// ErrACKAhead means an ACK claims a sequence which this spool has never assigned.
	ErrACKAhead = errors.New("telemetry spool ACK is ahead of assigned sequence")
	// ErrStaleACK means an ACK addresses an incarnation which this spool cannot own.
	ErrStaleACK = errors.New("telemetry spool ACK addresses a stale incarnation")
)

// SaturatedError includes safe capacity information without leaking host paths.
type SaturatedError struct {
	UsedBytes     int64
	MaxBytes      int64
	RequiredBytes int64
}

func (e *SaturatedError) Error() string {
	return fmt.Sprintf("%v: used=%d max=%d required=%d", ErrSaturated, e.UsedBytes, e.MaxBytes, e.RequiredBytes)
}

func (e *SaturatedError) Unwrap() error { return ErrSaturated }
