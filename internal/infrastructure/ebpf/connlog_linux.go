//go:build linux

// Package ebpf is the egress connection observer: a cgroup connect4/connect6 eBPF
// program (compiled to bytecode by clang, embedded, loaded by cilium/ebpf – no toolchain
// at runtime) attached to a per-run cgroup. Every outbound connect() the sandboxed tool
// attempts – including ones the kernel egress filter then DROPS – is captured and returned
// for sealing as evidence. It only OBSERVES; enforcement stays with the iptables filter.
package ebpf

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Rebuild the embedded object after editing connlog.bpf.c (run on a Linux host with
// clang + libbpf-devel; the result is committed so no toolchain is needed at build time):
//
//go:generate sh -c "clang -target bpf -D__TARGET_ARCH_x86 -O2 -g -Wall -c c/connlog.bpf.c -o c/connlog.bpf.o"
//go:embed c/connlog.bpf.o
var connlogObj []byte

const cgroupRoot = "/sys/fs/cgroup"

// ErrUnavailable means the eBPF connect-logger cannot run here (no privilege / kernel
// support). Callers degrade to no connect-log – never block or fail the run on it.
var ErrUnavailable = errors.New("ebpf connect-logger unavailable")

// rawEvent mirrors `struct conn_event` in connlog.bpf.c (packed, host == little-endian).
type rawEvent struct {
	PID    uint32
	IP4    [4]byte  // network order
	IP6    [16]byte // network order
	Port   uint16   // host order (the BPF program ntohs'd it)
	Family uint16   // 2 = AF_INET, 10 = AF_INET6
}

// Monitor builds per-run eBPF connect-loggers.
type Monitor struct{}

// NewMonitor returns a connect-log monitor.
func NewMonitor() *Monitor { return &Monitor{} }

// Session is a live attach: an isolated cgroup with the connect4/connect6 hooks, a
// background drain of the ring buffer, and the cgroup dir fd for clone-into-cgroup (the
// tool is created directly in the cgroup, so its connects are captured race-free).
type Session struct {
	cgroupPath string
	cgroupDir  *os.File
	ownsCgroup bool // true when this session created the cgroup (and must remove it on Close)
	coll       *ebpf.Collection
	links      []link.Link
	rd         *ringbuf.Reader
	mu         sync.Mutex
	events     []ports.ConnEvent
	done       chan struct{}
}

// Start creates a fresh cgroup named for the run, attaches the connect hooks, and begins
// draining. Use when the caller has no cgroup of its own. Close removes the cgroup.
func (m *Monitor) Start(name string) (*Session, error) {
	cgPath := filepath.Join(cgroupRoot, "synapse-conn-"+sanitize(name))
	if err := os.Mkdir(cgPath, 0o755); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("%w: create cgroup: %v", ErrUnavailable, err)
	}
	cgDir, err := os.Open(cgPath)
	if err != nil {
		_ = os.Remove(cgPath)
		return nil, fmt.Errorf("%w: open cgroup: %v", ErrUnavailable, err)
	}
	sess, err := m.attach(cgPath, cgDir, true)
	if err != nil {
		_ = cgDir.Close()
		_ = os.Remove(cgPath)
		return nil, err
	}
	return sess, nil
}

// Attach attaches the connect hooks to an EXISTING cgroup (owned by the caller – e.g. the
// sandbox's per-run limit cgroup, F3). Close detaches but does NOT remove the cgroup.
func (m *Monitor) Attach(cgroupPath string) (*Session, error) {
	return m.attach(cgroupPath, nil, false)
}

// attach loads the program and links connect4/connect6 to cgroupPath, then drains.
func (m *Monitor) attach(cgPath string, cgDir *os.File, owns bool) (*Session, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("%w: memlock: %v", ErrUnavailable, err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(connlogObj))
	if err != nil {
		return nil, fmt.Errorf("%w: load spec: %v", ErrUnavailable, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("%w: load programs: %v", ErrUnavailable, err)
	}
	sess := &Session{cgroupPath: cgPath, cgroupDir: cgDir, ownsCgroup: owns, coll: coll, done: make(chan struct{})}
	attachOne := func(prog string, at ebpf.AttachType) error {
		l, lerr := link.AttachCgroup(link.CgroupOptions{Path: cgPath, Attach: at, Program: coll.Programs[prog]})
		if lerr != nil {
			return lerr
		}
		sess.links = append(sess.links, l)
		return nil
	}
	if err := attachOne("connlog_connect4", ebpf.AttachCGroupInet4Connect); err != nil {
		sess.closeProg()
		return nil, fmt.Errorf("%w: attach connect4: %v", ErrUnavailable, err)
	}
	if err := attachOne("connlog_connect6", ebpf.AttachCGroupInet6Connect); err != nil {
		sess.closeProg()
		return nil, fmt.Errorf("%w: attach connect6: %v", ErrUnavailable, err)
	}
	rd, err := ringbuf.NewReader(coll.Maps["conn_events"])
	if err != nil {
		sess.closeProg()
		return nil, fmt.Errorf("%w: ring buffer: %v", ErrUnavailable, err)
	}
	sess.rd = rd
	go sess.drain()
	return sess, nil
}

// closeProg tears down only the eBPF objects (links + collection), not the cgroup – used
// on a failed attach where the caller still owns cgroup cleanup.
func (s *Session) closeProg() {
	for _, l := range s.links {
		_ = l.Close()
	}
	s.links = nil
	if s.coll != nil {
		s.coll.Close()
		s.coll = nil
	}
}

// CgroupFD is the cgroup directory fd to pass as syscall.SysProcAttr.CgroupFD (with
// UseCgroupFD) so the launched process is created inside the monitored cgroup.
func (s *Session) CgroupFD() int { return int(s.cgroupDir.Fd()) }

func (s *Session) drain() {
	defer close(s.done)
	for {
		rec, err := s.rd.Read()
		if err != nil {
			return // reader closed on Close()
		}
		var raw rawEvent
		if binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw) != nil {
			continue
		}
		ev := ports.ConnEvent{PID: raw.PID, Port: int(raw.Port)}
		if raw.Family == 2 {
			ev.Family, ev.IP = 4, netip.AddrFrom4(raw.IP4).String()
		} else {
			ev.Family, ev.IP = 6, netip.AddrFrom16(raw.IP6).Unmap().String()
		}
		s.mu.Lock()
		s.events = append(s.events, ev)
		s.mu.Unlock()
	}
}

// Close detaches the hooks, removes the cgroup, and returns the captured attempts. Safe to
// call on a partially-started session. Idempotent enough for a deferred call.
func (s *Session) Close() []ports.ConnEvent {
	if s.rd != nil {
		_ = s.rd.Close() // unblocks drain
		<-s.done
		s.rd = nil
	}
	for _, l := range s.links {
		_ = l.Close()
	}
	s.links = nil
	if s.coll != nil {
		s.coll.Close()
		s.coll = nil
	}
	if s.ownsCgroup {
		if s.cgroupDir != nil {
			_ = s.cgroupDir.Close()
			s.cgroupDir = nil
		}
		if s.cgroupPath != "" {
			_ = os.Remove(s.cgroupPath) // rmdir: the tool has exited, the cgroup is empty
			s.cgroupPath = ""
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.events
}

// sanitize keeps a cgroup directory name to safe characters.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, s)
}
