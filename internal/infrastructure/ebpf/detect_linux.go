//go:build linux

// Package ebpf also hosts the agent-side detection SENSOR (issue #422): host-wide eBPF observers for the
// four detection event classes. Unlike the per-run cgroup connect-logger in this package, the sensor
// attaches system-wide (syscall tracepoints for exec/file/privilege, kprobes for network) and streams
// decoded domain events to the agent-side engine (internal/usecase/fleet/detect).
//
// Each class is a SEPARATE eBPF object with its OWN ring-buffer map, loaded and attached independently.
// A class that fails to load or attach — because a program is unsupported or the kernel lacks a feature
// — is reported as an observation GAP for that class, and the OTHER classes keep running: a missing
// feature disables one class with a coverage report, never the whole engine (issue #422 reqs 1, 5, 6).
package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// The sensor is consumed by the agent-side engine through ports.DetectionSensor, never as a concrete
// type — the dependency points inward (usecase ← infrastructure).
var _ ports.DetectionSensor = (*Sensor)(nil)

// Rebuild the committed amd64 and arm64 artifacts after editing .bpf.c sources with
// make ebpf-generate on Linux. Production binaries embed only their architecture's objects.

// ErrSensorUnavailable means the detection sensor cannot run here at all (no privilege, no eBPF). It is
// distinct from a single class failing to load — that is a coverage gap, not a total failure.
var ErrSensorUnavailable = errors.New("ebpf detection sensor unavailable")

// classProgram describes how to load and attach one event class: its embedded object, the ring-buffer
// map name, and the (program name, attach) pairs. A class may attach more than one program (privilege
// hooks both setuid and setresuid; network hooks udp_sendmsg and tcp_connect).
type classProgram struct {
	class        detection.Class
	obj          []byte
	requiresCORE bool
	mapName      string
	attach       []progAttach
	decode       func(host shared.ID, raw []byte, now time.Time) (detection.Event, bool)
}

type attachKind int

const (
	attachTracepoint attachKind = iota
	attachKprobe
)

type progAttach struct {
	prog  string // program (C function) name in the object
	kind  attachKind
	group string // tracepoint group (e.g. "syscalls"); unused for kprobes
	name  string // tracepoint name or kprobe symbol
}

func classPrograms() []classProgram {
	return []classProgram{
		{
			class: detection.ClassProcess, obj: execObj, mapName: "exec_events",
			attach: []progAttach{{prog: "detect_execve", kind: attachTracepoint, group: "syscalls", name: "sys_enter_execve"}},
			decode: decodeExec,
		},
		{
			class: detection.ClassFile, obj: fileObj, mapName: "file_events",
			attach: []progAttach{{prog: "detect_openat", kind: attachTracepoint, group: "syscalls", name: "sys_enter_openat"}},
			decode: decodeFile,
		},
		{
			class: detection.ClassPrivilege, obj: privObj, mapName: "priv_events",
			attach: []progAttach{
				{prog: "detect_setuid", kind: attachTracepoint, group: "syscalls", name: "sys_enter_setuid"},
				{prog: "detect_setresuid", kind: attachTracepoint, group: "syscalls", name: "sys_enter_setresuid"},
			},
			decode: decodePriv,
		},
		{
			class: detection.ClassNetwork, obj: netObj, requiresCORE: true, mapName: "net_events",
			attach: []progAttach{
				{prog: "detect_udp_sendmsg", kind: attachKprobe, name: "udp_sendmsg"},
				{prog: "detect_tcp_connect", kind: attachKprobe, name: "tcp_connect"},
			},
			decode: decodeNet,
		},
	}
}

// Sensor is a live set of per-class observers. It owns the loaded objects, the attach links, and the
// ring-buffer drains; Events streams decoded domain events and Coverage reports which classes are active
// and which are gaps.
type Sensor struct {
	host      shared.ID
	agentID   shared.ID
	requested map[detection.Class]bool

	mu       sync.Mutex
	loaded   []*loadedClass
	coverage []detection.ClassCoverage

	events  chan detection.Event
	wg      sync.WaitGroup
	started bool
	closed  bool
}

type loadedClass struct {
	class   detection.Class
	coll    *ebpf.Collection
	links   []link.Link
	rd      *ringbuf.Reader
	dropped atomic.Uint64 // events observed but dropped because the consumer was behind
}

// NewSensor builds a sensor for the requested classes. A class not requested is reported as
// StateDisabled — switched off by configuration is still a coverage gap, not a clean host.
func NewSensor(host, agentID shared.ID, classes []detection.Class) *Sensor {
	req := make(map[detection.Class]bool, len(classes))
	for _, c := range classes {
		req[c] = true
	}
	return &Sensor{host: host, agentID: agentID, requested: req, events: make(chan detection.Event, 1024)}
}

// Start loads and attaches every requested class independently. It returns ErrSensorUnavailable only if
// the environment cannot host eBPF at all (memlock); a per-class load/attach failure is recorded as a
// coverage gap and does not fail Start. After Start, Coverage reports the outcome for every class.
func (s *Sensor) Start(ctx context.Context) error {
	// Start exactly once. A second Start (or Start after Close) would re-attach every class, append a
	// duplicate set of coverage records (which the domain roll-up rejects), and — after Close has closed
	// the events channel — panic on send-on-closed in the new drains. Guard against all of that.
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("%w: sensor already closed", ErrSensorUnavailable)
	}
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("%w: sensor already started", ErrSensorUnavailable)
	}
	s.started = true
	s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrSensorUnavailable, err)
	}
	if embeddedObjectArch == "" {
		for _, cp := range classPrograms() {
			if s.requested[cp.class] {
				s.recordGap(cp.class, detection.StateFailed, "no architecture-matched eBPF objects for linux/"+runtime.GOARCH)
			}
		}
		s.markDisabledClasses()
		return fmt.Errorf("%w: unsupported architecture linux/%s", ErrSensorUnavailable, runtime.GOARCH)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		// Nothing can load. Report every requested class as a failed gap and surface the total failure.
		for _, cp := range classPrograms() {
			s.recordGap(cp.class, detection.StateFailed, "remove memlock rlimit: "+err.Error())
		}
		s.markDisabledClasses()
		return fmt.Errorf("%w: %v", ErrSensorUnavailable, err)
	}

	var coreCache *btf.Cache
	var coreCapabilities HostCapabilities
	if s.requested[detection.ClassNetwork] {
		coreCache = btf.NewCache()
		coreCapabilities = probeHostCapabilities(runtime.GOARCH, embeddedObjectArch, func() (kernelTypeLookup, error) {
			spec, err := coreCache.Kernel()
			if err != nil {
				return nil, err
			}
			return spec.AnyTypeByName, nil
		})
	}

	for _, cp := range classPrograms() {
		if !s.requested[cp.class] {
			continue // reported as StateDisabled below
		}
		if cp.requiresCORE && !coreCapabilities.CORE {
			s.recordGap(cp.class, detection.StateDegraded, coreCapabilities.Reason)
			continue
		}
		lc, err := s.loadClass(cp, coreCache)
		if err != nil {
			s.recordGap(cp.class, gapStateFor(err), err.Error())
			continue
		}
		s.mu.Lock()
		s.loaded = append(s.loaded, lc)
		s.coverage = append(s.coverage, detection.ClassCoverage{
			Class: cp.class, HostID: s.host, AgentID: s.agentID, State: detection.StateActive, Since: time.Now().UTC(),
		})
		s.mu.Unlock()
		s.wg.Add(1)
		go s.drain(lc, cp.decode)
	}
	s.markDisabledClasses()

	// Fail closed when classes were requested but NONE came up: a caller that checks only the returned
	// error (not Coverage) must still learn the sensor is not observing. Coverage already carries the
	// per-class reasons; this makes the error contract match them.
	if len(s.requested) > 0 && s.activeCount() == 0 {
		return fmt.Errorf("%w: no requested class could be loaded", ErrSensorUnavailable)
	}
	return nil
}

// activeCount reports how many classes reached StateActive.
func (s *Sensor) activeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.coverage {
		if c.State == detection.StateActive {
			n++
		}
	}
	return n
}

// gapStateFor classifies a class failure: a missing kernel feature/symbol degrades the class (the engine
// keeps running the rest); anything else is a hard failure. Both are observation gaps.
func gapStateFor(err error) detection.ClassState {
	if errors.Is(err, ebpf.ErrNotSupported) || errors.Is(err, link.ErrNotSupported) {
		return detection.StateDegraded
	}
	return detection.StateFailed
}

func (s *Sensor) loadClass(cp classProgram, cache *btf.Cache) (*loadedClass, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(cp.obj))
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Cache: cache})
	if err != nil {
		return nil, fmt.Errorf("load programs: %w", err)
	}
	lc := &loadedClass{class: cp.class, coll: coll}
	for _, pa := range cp.attach {
		prog := coll.Programs[pa.prog]
		if prog == nil {
			lc.closeAll()
			return nil, fmt.Errorf("program %q missing from object", pa.prog)
		}
		var l link.Link
		var lerr error
		switch pa.kind {
		case attachTracepoint:
			l, lerr = link.Tracepoint(pa.group, pa.name, prog, nil)
		case attachKprobe:
			l, lerr = link.Kprobe(pa.name, prog, nil)
		}
		if lerr != nil {
			lc.closeAll()
			return nil, fmt.Errorf("attach %s: %w", pa.name, lerr)
		}
		lc.links = append(lc.links, l)
	}
	rd, err := ringbuf.NewReader(coll.Maps[cp.mapName])
	if err != nil {
		lc.closeAll()
		return nil, fmt.Errorf("ring buffer %q: %w", cp.mapName, err)
	}
	lc.rd = rd
	return lc, nil
}

func (s *Sensor) drain(lc *loadedClass, decode func(shared.ID, []byte, time.Time) (detection.Event, bool)) {
	defer s.wg.Done()
	for {
		rec, err := lc.rd.Read()
		if err != nil {
			return // reader closed on Close()
		}
		ev, ok := decode(s.host, rec.RawSample, time.Now().UTC())
		if !ok {
			continue
		}
		select {
		case s.events <- ev:
		default:
			// The consumer is behind. Drop rather than block the drain — a blocked drain would stall the
			// ring buffer. The drop is COUNTED, not silent: Dropped() surfaces it so pressure is visible
			// (the engine treats a class with drops as degraded rather than fully observed).
			lc.dropped.Add(1)
		}
	}
}

func (s *Sensor) recordGap(class detection.Class, state detection.ClassState, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.coverage = append(s.coverage, detection.ClassCoverage{
		Class: class, HostID: s.host, AgentID: s.agentID, State: state, Reason: reason, Since: time.Now().UTC(),
	})
}

// markDisabledClasses records every requested-but-not and not-requested class that has no coverage entry
// yet as StateDisabled, so Coverage always reports all four classes — a class is never silently absent.
func (s *Sensor) markDisabledClasses() {
	s.mu.Lock()
	defer s.mu.Unlock()
	have := make(map[detection.Class]bool, len(s.coverage))
	for _, c := range s.coverage {
		have[c.Class] = true
	}
	for _, cls := range detection.Classes() {
		if have[cls] {
			continue
		}
		s.coverage = append(s.coverage, detection.ClassCoverage{
			Class: cls, HostID: s.host, AgentID: s.agentID, State: detection.StateDisabled,
			Reason: "class not enabled by configuration", Since: time.Now().UTC(),
		})
	}
}

// Events streams decoded domain events from every active class.
func (s *Sensor) Events() <-chan detection.Event { return s.events }

// Coverage returns a snapshot of the per-class observation status, one entry per class.
func (s *Sensor) Coverage() []detection.ClassCoverage {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]detection.ClassCoverage, len(s.coverage))
	copy(out, s.coverage)
	return out
}

// Dropped returns the number of observed-but-dropped events per class, caused by the consumer falling
// behind the drain. It is surfaced so load pressure is visible rather than silent: the engine treats a
// class with a rising drop count as degraded (its "no detections" can no longer be trusted) rather than
// fully observed.
func (s *Sensor) Dropped() map[detection.Class]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[detection.Class]uint64, len(s.loaded))
	for _, lc := range s.loaded {
		if n := lc.dropped.Load(); n > 0 {
			out[lc.class] = n
		}
	}
	return out
}

// Close detaches every class, stops the drains, and closes the event channel.
func (s *Sensor) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	loaded := s.loaded
	s.loaded = nil
	s.mu.Unlock()

	for _, lc := range loaded {
		if lc.rd != nil {
			_ = lc.rd.Close() // unblocks its drain
		}
	}
	s.wg.Wait()
	for _, lc := range loaded {
		lc.closeAll()
	}
	close(s.events)
	return nil
}

func (lc *loadedClass) closeAll() {
	for _, l := range lc.links {
		_ = l.Close()
	}
	lc.links = nil
	if lc.rd != nil {
		_ = lc.rd.Close()
		lc.rd = nil
	}
	if lc.coll != nil {
		lc.coll.Close()
		lc.coll = nil
	}
}

// ---- decoders: mirror the C event structs (fixed layout, little-endian host) ------------------------

type rawExec struct {
	PID      uint32
	UID      uint32
	Comm     [16]byte
	Filename [256]byte
	Arg1     [48]byte
	Arg2     [48]byte
}

func decodeExec(host shared.ID, raw []byte, now time.Time) (detection.Event, bool) {
	var e rawExec
	if binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e) != nil {
		return detection.Event{}, false
	}
	var args []string
	if a := cstr(e.Arg1[:]); a != "" {
		args = append(args, a)
	}
	if a := cstr(e.Arg2[:]); a != "" {
		args = append(args, a)
	}
	// At sys_enter_execve, bpf_get_current_comm returns the CALLER's comm (the old image is still mapped),
	// not the program being executed — useless for a process rule that matches on the command. The
	// reliable identity is the executable being run, so derive comm from the basename of its path; fall
	// back to the kernel comm only if the path was unreadable.
	path := cstr(e.Filename[:])
	comm := cstr(e.Comm[:])
	if path != "" {
		comm = filepath.Base(path)
	}
	return detection.Event{
		Class: detection.ClassProcess, At: now, Host: host,
		Process: &detection.ProcessEvent{PID: int(e.PID), UID: int(e.UID), Comm: comm, Path: path, Args: args},
	}, true
}

type rawFile struct {
	PID      uint32
	UID      uint32
	Comm     [16]byte
	Filename [256]byte
}

func decodeFile(host shared.ID, raw []byte, now time.Time) (detection.Event, bool) {
	var e rawFile
	if binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e) != nil {
		return detection.Event{}, false
	}
	return detection.Event{
		Class: detection.ClassFile, At: now, Host: host,
		File: &detection.FileEvent{PID: int(e.PID), Comm: cstr(e.Comm[:]), Path: cstr(e.Filename[:]), Op: "open"},
	}, true
}

type rawPriv struct {
	PID   uint32
	UID   uint32
	ToUID uint32
	Comm  [16]byte
	Kind  [12]byte
}

func decodePriv(host shared.ID, raw []byte, now time.Time) (detection.Event, bool) {
	var e rawPriv
	if binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e) != nil {
		return detection.Event{}, false
	}
	return detection.Event{
		Class: detection.ClassPrivilege, At: now, Host: host,
		Privilege: &detection.PrivilegeEvent{PID: int(e.PID), Comm: cstr(e.Comm[:]), ToUID: int(e.ToUID), Kind: cstr(e.Kind[:])},
	}, true
}

type rawNet struct {
	PID   uint32
	DAddr uint32 // network byte order
	DPort uint16 // host order (BPF ntohs'd it)
	Proto uint8
	Pad   uint8
	Comm  [16]byte
}

func decodeNet(host shared.ID, raw []byte, now time.Time) (detection.Event, bool) {
	var e rawNet
	if binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e) != nil {
		return detection.Event{}, false
	}
	proto := "tcp"
	if e.Proto == 17 {
		proto = "udp"
	}
	var ipb [4]byte
	binary.BigEndian.PutUint32(ipb[:], ntohl(e.DAddr))
	return detection.Event{
		Class: detection.ClassNetwork, At: now, Host: host,
		Network: &detection.NetworkEvent{
			PID: int(e.PID), Comm: cstr(e.Comm[:]), Proto: proto,
			RemoteAddr: netip.AddrFrom4(ipb).String(), RemotePort: int(e.DPort), Direction: "egress",
		},
	}, true
}

// ntohl converts a network-order (big-endian) uint32 read into little-endian host memory back to a plain
// host uint32 whose bytes are the address octets in order.
func ntohl(n uint32) uint32 {
	return (n&0xff)<<24 | (n&0xff00)<<8 | (n&0xff0000)>>8 | (n&0xff000000)>>24
}

// cstr trims a fixed C char array at its first NUL and returns the Go string.
func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
