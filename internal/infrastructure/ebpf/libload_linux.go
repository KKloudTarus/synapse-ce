//go:build linux

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// LibraryLoadEvent is one observed shared-library open by a running process (EPIC #1042 #1060). It is
// runtime-reachability EVIDENCE, not a detection: userspace resolves Path to its owning OS package so the
// raise-only runtime coordinator (#1061) can escalate a finding on that package. It never suppresses.
type LibraryLoadEvent struct {
	PID  uint32
	UID  uint32
	Comm string
	Path string    // absolute path of the opened shared object, e.g. /usr/lib/x86_64-linux-gnu/libssl.so.3
	At   time.Time // wall-clock, mapped from the kernel-monotonic timestamp
}

// rawLibrary mirrors `struct library_event` in library.bpf.c (packed, host == little-endian on the
// supported architectures).
type rawLibrary struct {
	Ktime uint64
	PID   uint32
	UID   uint32
	Comm  [16]byte
	Path  [256]byte
}

// LibraryLoadSensor is a live library-load observer: it loads the embedded library.bpf.o, attaches its
// tracepoint to sys_enter_openat, and drains the ring buffer, emitting one LibraryLoadEvent per opened
// shared object. Standalone (like the connlog monitor), independent of the detection Sensor, because a
// library load is reachability evidence rather than a detection-class event.
type LibraryLoadSensor struct {
	coll   *ebpf.Collection
	lnk    link.Link
	rd     *ringbuf.Reader
	events chan LibraryLoadEvent
	done   chan struct{}
	epoch  time.Time
}

// NewLibraryLoadSensor returns an unstarted sensor.
func NewLibraryLoadSensor() *LibraryLoadSensor {
	return &LibraryLoadSensor{events: make(chan LibraryLoadEvent, 1024), done: make(chan struct{})}
}

// Start loads and attaches the program and begins draining. It fails with ErrUnavailable when eBPF cannot
// run here (no privilege / kernel support / architecture mismatch); callers degrade to no runtime evidence
// rather than blocking, because runtime reachability is raise-only and its absence changes no verdict.
func (s *LibraryLoadSensor) Start(_ context.Context) error {
	if embeddedObjectArch == "" {
		return fmt.Errorf("%w: no architecture-matched object", ErrUnavailable)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("%w: memlock: %v", ErrUnavailable, err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(libraryObj))
	if err != nil {
		return fmt.Errorf("%w: load spec: %v", ErrUnavailable, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("%w: load programs: %v", ErrUnavailable, err)
	}
	l, err := link.Tracepoint("syscalls", "sys_enter_openat", coll.Programs["detect_library"], nil)
	if err != nil {
		coll.Close()
		return fmt.Errorf("%w: attach tracepoint: %v", ErrUnavailable, err)
	}
	rd, err := ringbuf.NewReader(coll.Maps["library_events"])
	if err != nil {
		_ = l.Close()
		coll.Close()
		return fmt.Errorf("%w: ringbuf reader: %v", ErrUnavailable, err)
	}
	s.coll, s.lnk, s.rd, s.epoch = coll, l, rd, captureKtimeEpoch()
	go s.drain()
	return nil
}

func (s *LibraryLoadSensor) drain() {
	defer close(s.events)
	for {
		rec, err := s.rd.Read()
		if err != nil {
			return // reader closed on Close(), or a transient error: stop draining
		}
		ev, ok := decodeLibrary(rec.RawSample, s.epoch)
		if !ok {
			continue
		}
		select {
		case s.events <- ev:
		case <-s.done:
			return
		default:
			// channel full: drop the event rather than block the drain (raise-only; a missed load never hides
			// a finding, it only forgoes an urgency raise).
		}
	}
}

// Events streams decoded library-load events until Close.
func (s *LibraryLoadSensor) Events() <-chan LibraryLoadEvent { return s.events }

// Close detaches the program and stops the drain.
func (s *LibraryLoadSensor) Close() error {
	close(s.done)
	if s.rd != nil {
		_ = s.rd.Close()
	}
	if s.lnk != nil {
		_ = s.lnk.Close()
	}
	if s.coll != nil {
		s.coll.Close()
	}
	return nil
}

// decodeLibrary parses one raw ring-buffer record and confirms the ".so" suffix the in-kernel prefix gate
// leaves to userspace. A path under a library directory that is not a shared object (a config file, a
// directory read) is dropped here, keeping the evidence to actual shared-object opens.
func decodeLibrary(raw []byte, epoch time.Time) (LibraryLoadEvent, bool) {
	var e rawLibrary
	if binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e) != nil {
		return LibraryLoadEvent{}, false
	}
	path := cstr(e.Path[:])
	if !isSharedObjectPath(path) {
		return LibraryLoadEvent{}, false
	}
	return LibraryLoadEvent{
		PID:  e.PID,
		UID:  e.UID,
		Comm: cstr(e.Comm[:]),
		Path: path,
		At:   epoch.Add(time.Duration(e.Ktime) * time.Nanosecond),
	}, true
}

// isSharedObjectPath reports whether path names an ELF shared object: it ends in ".so" or carries a
// versioned ".so." suffix (libssl.so.3). Matching the ".so" token (not merely the substring) avoids
// treating an unrelated path that merely contains "so" as a library.
func isSharedObjectPath(path string) bool {
	if strings.HasSuffix(path, ".so") {
		return true
	}
	if i := strings.Index(path, ".so."); i >= 0 {
		// Everything after ".so." must be a version (digits and dots), e.g. libc.so.6, libssl.so.3.0.2.
		rest := path[i+len(".so."):]
		if rest == "" {
			return false
		}
		for _, r := range rest {
			if (r < '0' || r > '9') && r != '.' {
				return false
			}
		}
		return true
	}
	return false
}
